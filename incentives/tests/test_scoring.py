"""Scoring must be deterministic: same public events in, same scores out."""
import copy
import json
import random

from conftest import DAY, T0

from htn import scoring


def busy_world(world, chain=None):
    jobs = [world.job(at=T0 + i) for i in range(4)]
    for j in jobs[:3]:
        world.complete(world.client, j)
    world.complete(world.worker, jobs[3])  # invalid: worker self-completion
    v_clean, _, _ = world.bonded_vouch(world.voucher, jobs[0], chain)
    world.clear(world.voucher, v_clean)
    v_bad, _, _ = world.bonded_vouch(world.voucher, jobs[1], chain)
    d = world.dispute(world.client, jobs[1])
    world.resolve(world.founder, d, "upheld")
    world.clear(world.voucher, v_bad)  # invalid: vouch was forfeited
    return world.events


def test_known_scores(world, chain):
    """Weights 1 / 2 / -5 (DECISIONS #11)."""
    result = scoring.score_all(busy_world(world, chain), world.config, chain=chain)
    w = result["operators"][world.worker.pubkey]
    assert w == {"keys": [world.worker.pubkey], "completed_jobs": 2, "upheld_disputes": 1,
                 "forfeited_vouches": 0, "lost_disputes": 1, "clean_vouches": 0,
                 "clean_vouches_not_counted": 0, "active_vouches": 0, "score": 2 * 1 - 5}
    v = result["operators"][world.voucher.pubkey]
    assert v["clean_vouches"] == 1 and v["forfeited_vouches"] == 1 and v["score"] == 2 - 5
    assert result["rejected_events"] == 2
    assert result["chain_tip"] == chain.tip() and result["weights"]["lost_dispute"] == -5


def test_two_independent_runs_agree(world, chain):
    evs = busy_world(world, chain)
    a = scoring.score_all(copy.deepcopy(evs), world.config, as_of=T0 + 9 * DAY, chain=chain)
    b = scoring.score_all(copy.deepcopy(evs), world.config, as_of=T0 + 9 * DAY, chain=chain)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_vouch_without_live_bond_earns_nothing(world, chain):
    """#43: a vouch counts only if its bond exists on chain, meets the minimum and is unspent,
    or was spent by the voucher's honest reclaim after T (#47)."""
    from htn import bond
    from htn.ledger import Ledger
    world.config = world.cfg(max_active_vouches=6)   # six vouches by one voucher in this test
    cases = {}
    for name in ("live", "spent", "missing", "too_small", "too_early", "reclaimed"):
        j = world.job(at=T0 + len(cases), job_id=f"{len(cases):02x}" * 32)
        kw = {"chain": chain}
        if name == "missing":
            kw = {"chain": None}
        if name == "too_small":
            kw["sats"] = world.config.bond_min_sats - 1
        if name == "too_early":
            kw["blocktime"] = T0 - 30 * DAY
        v, _, txid = world.bonded_vouch(world.voucher, j, at=T0 + 100 + len(cases), **kw)
        world.clear(world.voucher, v)
        cases[name] = (v["id"], txid)
    led = Ledger.build(world.events, world.config)
    chain.spend(cases["spent"][1], bond.terms_for_vouch(led, cases["spent"][0]), "forfeit")
    chain.spend(cases["reclaimed"][1], bond.terms_for_vouch(led, cases["reclaimed"][0]), "reclaim")
    result = scoring.score_all(world.events, world.config, chain=chain)
    checks = result["bond_checks"]
    assert [n for n, (vid, _) in cases.items() if checks[vid]["live"]] == ["live"]
    assert [n for n, (vid, _) in cases.items() if checks[vid]["counts"]] == ["live", "reclaimed"]
    assert checks[cases["reclaimed"][0]]["reclaimed_by"]
    assert "spent" in str(checks[cases["spent"][0]]["problems"])
    assert "not found" in str(checks[cases["missing"][0]]["problems"])
    assert "minimum" in str(checks[cases["too_small"][0]]["problems"])
    assert "before the job" in str(checks[cases["too_early"][0]]["problems"])
    v = result["operators"][world.voucher.pubkey]
    assert v["clean_vouches"] == 2 and v["clean_vouches_not_counted"] == 4 and v["score"] == 4
    # Without chain access no vouch carries weight.
    offline = scoring.score_all(world.events, world.config)["operators"][world.voucher.pubkey]
    assert offline["clean_vouches"] == 0 and offline["score"] == 0


def test_unbonded_vouch_earns_nothing(world, chain):
    j = world.job()
    world.clear(world.voucher, world.vouch(world.voucher, j))
    v = scoring.score_all(world.events, world.config, chain=chain)["operators"][world.voucher.pubkey]
    assert v["clean_vouches"] == 0 and v["score"] == 0


def test_order_and_duplicates_do_not_matter(world):
    evs = busy_world(world)
    baseline = json.dumps(scoring.score_all(evs, world.config), sort_keys=True)
    rng = random.Random(7)
    for _ in range(20):
        shuffled = copy.deepcopy(evs) + copy.deepcopy(rng.sample(evs, 5))
        rng.shuffle(shuffled)
        assert json.dumps(scoring.score_all(shuffled, world.config), sort_keys=True) == baseline


def test_forged_and_junk_events_change_nothing(world):
    evs = busy_world(world)
    baseline = scoring.score_all(evs, world.config)
    forged = copy.deepcopy(evs[4])
    forged["created_at"] += 1  # breaks the id/signature
    noisy = evs + [forged, "junk", {"id": "x"}]
    result = scoring.score_all(noisy, world.config)
    assert result["operators"] == baseline["operators"]
    assert result["event_set_hash"] == baseline["event_set_hash"]


def test_event_set_hash_changes_with_new_valid_event(world):
    evs = busy_world(world)
    h1 = scoring.score_all(evs, world.config)["event_set_hash"]
    world.complete(world.client, world.job(at=T0 + 2 * DAY), at=T0 + 3 * DAY)
    assert scoring.score_all(world.events, world.config)["event_set_hash"] != h1


def test_undecided_dispute_pending_then_lapses(world):
    j = world.job()
    world.complete(world.client, j)
    world.dispute(world.client, j)
    inside = scoring.score_all(world.events, world.config, as_of=T0 + DAY)
    after = scoring.score_all(world.events, world.config, as_of=T0 + 8 * DAY)
    no_time = scoring.score_all(world.events, world.config)
    for result, credited in ((inside, 0), (after, 1), (no_time, 0)):
        rec = result["operators"][world.worker.pubkey]
        assert rec["completed_jobs"] == credited and rec["upheld_disputes"] == 0
    assert after["as_of"] == T0 + 8 * DAY  # the reference time is part of the output


def test_rejected_dispute_keeps_credit(world):
    j = world.job()
    world.complete(world.client, j)
    d = world.dispute(world.client, j)
    world.resolve(world.founder, d, "rejected")
    rec = scoring.score_all(world.events, world.config)["operators"][world.worker.pubkey]
    assert rec["completed_jobs"] == 1 and rec["score"] == 1


def test_same_second_records_apply_in_natural_order(world):
    """Offer, acceptance, handoffs and completion all signed in the same second."""
    import itertools
    from htn.ledger import Ledger
    j = world.job(at=T0, accept=False)
    world.accept(world.worker, j, at=T0)
    world.handoff(world.worker, j, world.courier2, 1, at=T0)
    world.handoff(world.courier2, j, world.recipient, 2, at=T0)
    world.complete(world.client, j, at=T0)
    for perm in itertools.islice(itertools.permutations(world.events), 30):
        led = Ledger.build(list(perm), world.config)
        assert not led.rejected, led.rejected
