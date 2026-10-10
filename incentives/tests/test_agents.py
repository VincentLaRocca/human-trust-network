"""Phase 2b: agent keys delegated by an operator (Nucleus section 5)."""
from conftest import DAY, T0

from htn import scoring
from htn.ledger import Ledger


def build(world):
    return Ledger.build(world.events, world.config)


def setup(world, scope="job_accepted,handoff", **kw):
    ob = world.onboard(world.worker, world.worker_rec)
    d = world.delegate(world.worker, ob, world.agent, scope, at=T0 - 100, **kw)
    return ob, d


def test_agent_acts_for_operator_within_scope(world):
    ob, d = setup(world)
    j = world.job(accept=False)
    acc = world.accept(world.agent, j, at=T0 + 1)          # agent accepts for the worker
    h = world.handoff(world.agent, j, world.courier2, 1, at=T0 + 2)
    world.complete(world.client, j, at=T0 + 3)
    led = build(world)
    assert d["id"] in led.accepted and acc["id"] in led.accepted and h["id"] in led.accepted
    assert led.ident(world.agent.pubkey) == ob["id"]
    assert scoring.operator_record(led, ob["id"])["completed_jobs"] == 1


def test_agent_cannot_act_outside_scope(world):
    setup(world, scope="handoff")
    j = world.job(accept=False)
    acc = world.accept(world.agent, j, at=T0 + 1)
    assert "not authorised" in build(world).rejected[acc["id"]]


def test_agent_cannot_sign_off_its_operators_work(world):
    setup(world, scope="completion")
    j = world.job()
    c = world.complete(world.agent, j)
    assert c["id"] in build(world).rejected


def test_operator_revokes_agent_without_rotating(world):
    ob, _ = setup(world)
    world.revoke_agent(world.worker, ob, world.agent, at=T0)
    j = world.job(accept=False, at=T0 + 10)
    acc = world.accept(world.agent, j, at=T0 + 11)
    led = build(world)
    assert "revoked" in led.rejected[acc["id"]]
    assert led.registry.operators[ob["id"]].current == world.worker.pubkey  # human key unchanged


def test_recovery_key_can_revoke_agent(world):
    ob, _ = setup(world)
    r = world.revoke_agent(world.worker_rec, ob, world.agent, at=T0)
    assert r["id"] in build(world).accepted


def test_stranger_cannot_revoke_or_delegate(world):
    ob, _ = setup(world)
    r = world.revoke_agent(world.stranger, ob, world.agent, at=T0)
    d = world.delegate(world.stranger, ob, world.courier2, "handoff", at=T0)
    led = build(world)
    assert r["id"] in led.rejected and d["id"] in led.rejected


def test_delegation_expires(world):
    setup(world, expires=T0 + 5)
    j = world.job(accept=False)
    late = world.accept(world.agent, j, at=T0 + 6)
    assert "expired" in build(world).rejected[late["id"]]


def test_agent_cannot_be_given_identity_powers(world):
    ob = world.onboard(world.worker, world.worker_rec)
    bad = world.delegate(world.worker, ob, world.agent, "rotate", at=T0)
    unknown = world.delegate(world.worker, ob, world.courier2, "pay_me", at=T0 + 1)
    led = build(world)
    assert bad["id"] in led.rejected and unknown["id"] in led.rejected
    # And an agent can never rotate the operator's key.
    ok = world.delegate(world.worker, ob, world.agent, "handoff", at=T0 + 2)
    rot = world.rotate(world.agent, ob, world.thief, at=T0 + 3)
    led = build(world)
    assert ok["id"] in led.accepted and rot["id"] in led.rejected


def test_thief_delegation_overridden_by_recovery(world):
    """A thief with the stolen key delegates to their own 'agent'; recovery voids it."""
    ob = world.onboard(world.worker, world.worker_rec)
    stolen = T0 + 100
    world.delegate(world.worker, ob, world.thief, "job_accepted,vouch_issued", at=stolen + 1)
    j = world.job(client=world.stranger, worker=world.courier2, at=stolen + 2)
    v = world.vouch(world.thief, j, at=stolen + 3)
    world.recover(world.worker_rec, ob, world.worker_new, since=stolen, at=stolen + DAY)
    led = build(world)
    assert led.rejected[v["id"]].startswith("disputable")


def test_thief_cannot_revoke_legit_agent(world):
    ob, _ = setup(world)
    stolen = T0 + 100
    world.revoke_agent(world.worker, ob, world.agent, at=stolen + 1)   # thief, stolen key
    world.recover(world.worker_rec, ob, world.worker_new, since=stolen, at=stolen + 50)
    j = world.job(worker=world.worker_new, accept=False, at=stolen + 60)
    acc = world.accept(world.agent, j, at=stolen + 61)  # the legit agent still works
    assert acc["id"] in build(world).accepted


def test_agent_key_cannot_be_reused(world):
    ob, _ = setup(world)
    world.onboard(world.voucher, world.stranger, at=T0 - 50)
    again = world.onboard(world.agent, world.courier2, at=T0 - 40)
    rot = world.rotate(world.worker, ob, world.agent, at=T0)
    led = build(world)
    assert again["id"] in led.rejected and rot["id"] in led.rejected
