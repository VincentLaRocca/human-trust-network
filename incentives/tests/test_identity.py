"""Phase 2: key rotation, revocation and recovery."""
import copy
import json
import random

from conftest import DAY, T0

from htn import events as ev
from htn import scoring
from htn.ledger import Ledger


def build(world):
    return Ledger.build(world.events, world.config)


def op_of(world, led, onboard_event):
    return led.registry.operators[onboard_event["id"]]


# -- the three scenarios required by the brief ------------------------------

def test_thief_rotation_then_recovery_override(world):
    """A thief steals the worker's key and rotates to their own key.
    The recovery key overrides it; the thief's key and post-theft events don't count."""
    ob = world.onboard(world.worker, world.worker_rec)
    honest_job = world.job(at=T0)
    world.complete(world.client, honest_job, at=T0 + 100)

    stolen_at = T0 + 1000
    thief_rot = world.rotate(world.worker, ob, world.thief, at=stolen_at + 10)  # thief uses stolen key
    thief_job = world.job(worker=world.thief, at=stolen_at + 20)
    world.complete(world.client, thief_job, at=stolen_at + 30)
    thief_vouch = world.vouch(world.thief, honest_job, at=stolen_at + 40)

    rec = world.recover(world.worker_rec, ob, world.worker_new, since=stolen_at, at=stolen_at + 500)
    led = build(world)
    op = op_of(world, led, ob)

    assert rec["id"] in led.accepted
    assert op.current == world.worker_new.pubkey
    assert led.rejected[thief_rot["id"]].startswith("disputable")
    assert led.rejected[thief_vouch["id"]].startswith("disputable")
    assert led.rejected[thief_job["id"]].startswith("disputable")
    assert led.registry.is_compromised(world.worker.pubkey, stolen_at)
    assert led.registry.is_compromised(world.thief.pubkey, stolen_at + 20)
    # The honest work from before the theft still counts.
    rec_score = scoring.operator_record(led, ob["id"])
    assert rec_score["completed_jobs"] == 1 and rec_score["score"] == 1

    # The thief keeps trying with the stolen keys after the recovery: still excluded.
    again = world.rotate(world.thief, ob, world.stranger, at=stolen_at + 600)
    late_job = world.job(worker=world.worker, at=stolen_at + 700)
    led = build(world)
    assert again["id"] in led.rejected
    assert led.rejected[late_job["id"]].startswith("disputable")
    assert op_of(world, led, ob).current == world.worker_new.pubkey


def test_lost_key_replaced_via_recovery(world):
    ob = world.onboard(world.worker, world.worker_rec)
    world.complete(world.client, world.job(at=T0), at=T0 + 100)
    lost_at = T0 + 2 * DAY
    world.recover(world.worker_rec, ob, world.worker_new, since=lost_at, at=lost_at)
    # The operator keeps working under the new key; history carries over.
    j2 = world.job(worker=world.worker_new, at=lost_at + 10)
    world.complete(world.client, j2, at=lost_at + 20)
    led = build(world)
    assert not led.rejected, led.rejected
    rec = scoring.operator_record(led, ob["id"])
    assert rec["keys"] == [world.worker.pubkey, world.worker_new.pubkey]
    assert rec["completed_jobs"] == 2


def test_post_compromise_events_excluded_from_scoring(world):
    ob = world.onboard(world.worker, world.worker_rec)
    world.complete(world.client, world.job(at=T0), at=T0 + 100)
    world.vouch(world.worker, world.job(client=world.stranger, worker=world.courier2, at=T0 + 200),
                at=T0 + 300)
    since = T0 + 1000
    # Thief vouches with the stolen key on several jobs and they get forfeited.
    for i in range(3):
        j = world.job(client=world.stranger, worker=world.courier2, at=since + 10 + i)
        world.vouch(world.worker, j, at=since + 20 + i)
        d = world.dispute(world.stranger, j, at=since + 30 + i)
        world.resolve(world.founder, d, "upheld", at=since + 40 + i)
    world.recover(world.worker_rec, ob, world.worker_new, since=since, at=since + DAY)
    led = build(world)
    rec = scoring.operator_record(led, ob["id"])
    assert rec["forfeited_vouches"] == 0     # thief's vouches don't hurt the real operator
    assert rec["active_vouches"] == 1        # the honest pre-theft vouch remains
    assert rec["completed_jobs"] == 1
    assert len(led.disputable()) == 3
    result = scoring.score_all(world.events, world.config)
    assert result["disputable_events"] == 3


# -- ordinary rotation ------------------------------------------------------

def test_ordinary_rotation(world):
    ob = world.onboard(world.worker, world.worker_rec)
    rot = world.rotate(world.worker, ob, world.worker_new, at=T0)
    led = build(world)
    assert rot["id"] in led.accepted
    assert op_of(world, led, ob).current == world.worker_new.pubkey
    assert led.ident(world.worker.pubkey) == led.ident(world.worker_new.pubkey) == ob["id"]


def test_retired_key_cannot_sign_new_events(world):
    ob = world.onboard(world.worker, world.worker_rec)
    world.rotate(world.worker, ob, world.worker_new, at=T0)
    j = world.job(at=T0 + 10)
    v = world.vouch(world.worker, j, at=T0 + 20)  # old key
    led = build(world)
    assert "retired" in led.rejected[v["id"]]
    assert not led.rejected[v["id"]].startswith("disputable")


def test_only_current_key_can_rotate(world):
    ob = world.onboard(world.worker, world.worker_rec)
    world.rotate(world.worker, ob, world.worker_new, at=T0)
    stale = world.rotate(world.worker, ob, world.thief, at=T0 + 10)
    stranger = world.rotate(world.stranger, ob, world.thief, at=T0 + 20)
    led = build(world)
    assert stale["id"] in led.rejected and stranger["id"] in led.rejected


def test_cannot_rotate_into_another_operators_key(world):
    ob = world.onboard(world.worker, world.worker_rec)
    world.onboard(world.voucher, world.stranger)
    rot = world.rotate(world.worker, ob, world.voucher, at=T0)
    assert "already belongs" in build(world).rejected[rot["id"]]


def test_recovery_key_cannot_become_operational(world):
    ob = world.onboard(world.worker, world.worker_rec)
    rot = world.rotate(world.worker, ob, world.worker_rec, at=T0)
    rec = world.recover(world.worker_rec, ob, world.worker_rec, since=T0, at=T0 + 1)
    led = build(world)
    assert rot["id"] in led.rejected and rec["id"] in led.rejected


def test_onboard_rules(world):
    same = world.onboard(world.worker, world.worker)   # recovery == operational key
    ok = world.onboard(world.voucher, world.worker_rec, at=T0)
    dup = world.onboard(world.voucher, world.stranger, at=T0 + 1)  # key already onboarded
    led = build(world)
    assert same["id"] in led.rejected and ok["id"] in led.accepted and dup["id"] in led.rejected


# -- recovery rules ---------------------------------------------------------

def test_wrong_recovery_key_rejected(world):
    ob = world.onboard(world.worker, world.worker_rec)
    fake = world.recover(world.thief, ob, world.thief, since=T0, at=T0)
    assert "recovery key" in build(world).rejected[fake["id"]]


def test_recovery_since_bounds(world):
    ob = world.onboard(world.worker, world.worker_rec, at=T0)
    future = world.recover(world.worker_rec, ob, world.worker_new, since=T0 + 500, at=T0 + 100)
    before = world.recover(world.worker_rec, ob, world.worker_new, since=T0 - 1, at=T0 + 100)
    led = build(world)
    assert future["id"] in led.rejected and before["id"] in led.rejected


def test_second_recovery_cannot_rewrite_before_first(world):
    ob = world.onboard(world.worker, world.worker_rec, at=T0)
    world.recover(world.worker_rec, ob, world.worker_new, since=T0 + 10, at=T0 + 100)
    again = world.recover(world.worker_rec, ob, world.courier2, since=T0 + 50, at=T0 + 200)
    ok = world.recover(world.worker_rec, ob, world.courier2, since=T0 + 150, at=T0 + 201)
    led = build(world)
    assert again["id"] in led.rejected and ok["id"] in led.accepted
    assert led.registry.is_compromised(world.worker_new.pubkey, T0 + 150)


def test_recovery_always_wins_over_rotations(world):
    """However many rotations the thief chains, one recovery takes everything back."""
    ob = world.onboard(world.worker, world.worker_rec)
    keys = [world.thief, world.stranger, world.courier2]
    signer = world.worker
    for i, k in enumerate(keys):
        world.rotate(signer, ob, k, at=T0 + 10 * (i + 1))
        signer = k
    world.recover(world.worker_rec, ob, world.worker_new, since=T0 + 5, at=T0 + 100)
    led = build(world)
    assert op_of(world, led, ob).current == world.worker_new.pubkey
    for k in [world.worker] + keys:
        assert led.registry.is_compromised(k.pubkey, T0 + 50)


# -- identities across rotations -------------------------------------------

def test_vouch_cap_survives_rotation(world):
    ob = world.onboard(world.voucher, world.worker_rec)
    for i in range(5):
        world.vouch(world.voucher, world.job(at=T0 + i), at=T0 + 100 + i)
    world.rotate(world.voucher, ob, world.worker_new, at=T0 + 200)
    sixth = world.vouch(world.worker_new, world.job(at=T0 + 300), at=T0 + 400)
    assert "maximum" in build(world).rejected[sixth["id"]]


def test_worker_cannot_complete_own_job_with_another_of_their_keys(world):
    ob = world.onboard(world.worker, world.worker_rec)
    j = world.job(at=T0)
    world.rotate(world.worker, ob, world.worker_new, at=T0 + 10)
    c = world.complete(world.worker_new, j, at=T0 + 20)
    assert c["id"] in build(world).rejected


def test_founder_recusal_follows_identity(world):
    ob = world.onboard(world.founder, world.worker_rec)
    world.rotate(world.founder, ob, world.worker_new, at=T0 - 10)
    j = world.job(client=world.worker_new, at=T0)  # founder's operator, new key, is the client
    d = world.dispute(world.worker_new, j)
    r = world.resolve(world.backup, d, "upheld")
    assert r["id"] in build(world).accepted


def test_identity_scoring_is_deterministic(world):
    ob = world.onboard(world.worker, world.worker_rec)
    world.complete(world.client, world.job(at=T0), at=T0 + 2)
    world.rotate(world.worker, ob, world.thief, at=T0 + 50)
    world.complete(world.client, world.job(worker=world.thief, at=T0 + 60), at=T0 + 70)
    world.recover(world.worker_rec, ob, world.worker_new, since=T0 + 40, at=T0 + 100)
    world.complete(world.client, world.job(worker=world.worker_new, at=T0 + 200), at=T0 + 210)
    evs = world.events
    baseline = json.dumps(scoring.score_all(evs, world.config), sort_keys=True)
    rng = random.Random(3)
    for _ in range(20):
        shuffled = copy.deepcopy(evs) + copy.deepcopy(rng.sample(evs, 3))
        rng.shuffle(shuffled)
        assert json.dumps(scoring.score_all(shuffled, world.config), sort_keys=True) == baseline
    rec = json.loads(baseline)["operators"][ob["id"]]
    assert rec["completed_jobs"] == 2


def test_identity_events_pass_schema_and_carry_no_extra_data(world):
    from htn import schema
    ob = world.onboard(world.worker, world.worker_rec)
    for e in (ob, world.rotate(world.worker, ob, world.worker_new, at=T0),
              world.recover(world.worker_rec, ob, world.courier2, since=T0 + 1, at=T0 + 2)):
        schema.validate(e)
    # The recovery key itself is not revealed at onboarding, only its hash.
    assert world.worker_rec.pubkey not in json.dumps(ob)
    assert {e["kind"] for e in world.events} == {ev.ONBOARD, ev.ROTATE, ev.RECOVER}


def test_revoke_only_then_replace_later(world):
    """Nucleus 8: 'recovery key rotates or revokes'. Revoke now, name a new key later."""
    ob = world.onboard(world.worker, world.worker_rec)
    revoke = world.emit(world.worker_rec, ev.RECOVER,
                        [["op", ob["id"]], ["since", str(T0)]], T0 + 10)
    late = world.vouch(world.worker, world.job(at=T0 + 20), at=T0 + 30)
    rot = world.rotate(world.worker, ob, world.thief, at=T0 + 40)
    led = build(world)
    assert revoke["id"] in led.accepted
    assert op_of(world, led, ob).current is None
    assert led.rejected[late["id"]].startswith("disputable") and rot["id"] in led.rejected
    # Later the operator names a fresh key with the recovery key.
    world.recover(world.worker_rec, ob, world.worker_new, since=T0 + 50, at=T0 + 60)
    led = build(world)
    assert op_of(world, led, ob).current == world.worker_new.pubkey
