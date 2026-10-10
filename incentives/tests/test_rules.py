"""Who may sign what, dispute windows, recusal and vouch limits."""
from conftest import DAY, T0

from htn.ledger import Ledger


def build(world, **cfg):
    return Ledger.build(world.events, world.cfg(**cfg) if cfg else world.config)


# -- counterparty-only completions and disputes -----------------------------

def test_client_completion_accepted(world):
    j = world.job()
    c = world.complete(world.client, j)
    assert c["id"] in build(world).accepted


def test_recipient_completion_accepted(world):
    j = world.job(recipient=world.recipient)
    c = world.complete(world.recipient, j)
    assert c["id"] in build(world).accepted


def test_worker_cannot_complete_own_job(world):
    j = world.job()
    c = world.complete(world.worker, j)
    led = build(world)
    assert "not the worker" in led.rejected[c["id"]]
    assert led.jobs[world.job_id(j)].completion is None


def test_stranger_cannot_complete(world):
    j = world.job()
    c = world.complete(world.stranger, j)
    assert c["id"] in build(world).rejected


def test_completion_must_name_the_real_worker(world):
    j = world.job()
    c = world.complete(world.client, j, worker=world.stranger.pubkey)
    assert c["id"] in build(world).rejected


def test_only_first_completion_counts(world):
    j = world.job(recipient=world.recipient)
    world.complete(world.client, j)
    second = world.complete(world.recipient, j, at=T0 + 7200)
    assert "already completed" in build(world).rejected[second["id"]]


def test_worker_cannot_file_dispute(world):
    j = world.job()
    d = world.dispute(world.worker, j)
    assert d["id"] in build(world).rejected


def test_client_cannot_also_be_worker(world):
    j = world.job(client=world.worker, worker=world.worker)
    assert j["id"] in build(world).rejected


def test_job_id_cannot_be_reused(world):
    j1 = world.job()
    j2 = world.job(job_id=world.job_id(j1), at=T0 + 1)
    assert j2["id"] in build(world).rejected


def test_unknown_job_rejected(world):
    j = world.job()
    world.events.clear()  # the job event is never published
    c = world.complete(world.client, j)
    assert build(world).rejected[c["id"]] == "unknown job"


# -- dispute window and arbiters --------------------------------------------

def test_dispute_after_window_rejected(world):
    j = world.job()
    d = world.dispute(world.client, j, at=T0 + 7 * DAY + 1)
    assert "outside" in build(world).rejected[d["id"]]


def test_founder_resolves_dispute(world):
    j = world.job()
    d = world.dispute(world.client, j)
    r = world.resolve(world.founder, d, "upheld")
    led = build(world)
    assert r["id"] in led.accepted and led.jobs[world.job_id(j)].upheld


def test_random_key_cannot_resolve(world):
    j = world.job()
    d = world.dispute(world.client, j)
    r = world.resolve(world.stranger, d, "rejected")
    assert r["id"] in build(world).rejected


def test_worker_cannot_resolve_in_own_favour(world):
    j = world.job()
    d = world.dispute(world.client, j)
    r = world.resolve(world.worker, d, "rejected")
    assert r["id"] in build(world).rejected


def test_filer_can_withdraw_but_not_uphold(world):
    j = world.job()
    d1 = world.dispute(world.client, j)
    up = world.resolve(world.client, d1, "upheld")
    wd = world.resolve(world.client, d1, "withdrawn", at=T0 + 3 * DAY)
    led = build(world)
    assert up["id"] in led.rejected and wd["id"] in led.accepted


def test_founder_recuses_when_a_party(world):
    # Founder is the client here, so only the backup arbiter may resolve.
    j = world.job(client=world.founder)
    d = world.dispute(world.founder, j)
    by_founder = world.resolve(world.founder, d, "upheld")
    by_backup = world.resolve(world.backup, d, "upheld", at=T0 + 3 * DAY)
    led = build(world)
    assert "acting arbiter" in led.rejected[by_founder["id"]]
    assert by_backup["id"] in led.accepted


def test_founder_recuses_when_vouching(world):
    j = world.job()
    world.vouch(world.founder, j)
    d = world.dispute(world.client, j)
    r = world.resolve(world.founder, d, "rejected")
    assert r["id"] in build(world).rejected


def test_resolution_after_window_rejected(world):
    j = world.job()
    d = world.dispute(world.client, j)
    r = world.resolve(world.founder, d, "upheld", at=T0 + 8 * DAY)
    assert r["id"] in build(world).rejected


def test_no_arbiter_configured(world):
    j = world.job()
    d = world.dispute(world.client, j)
    r = world.resolve(world.founder, d, "upheld")
    led = build(world, founder_arbiter="", backup_arbiter="")
    assert "no eligible arbiter" in led.rejected[r["id"]]


# -- vouches ----------------------------------------------------------------

def test_vouch_clears_after_window(world):
    j = world.job()
    v = world.vouch(world.voucher, j)
    early = world.clear(world.voucher, v, at=T0 + 6 * DAY)
    late = world.clear(world.voucher, v, at=T0 + 8 * DAY)
    led = build(world)
    assert "not closed" in led.rejected[early["id"]]
    assert late["id"] in led.accepted and led.vouches[v["id"]].status == "cleared"


def test_upheld_dispute_forfeits_vouch(world):
    j = world.job()
    v = world.vouch(world.voucher, j)
    d = world.dispute(world.client, j)
    world.resolve(world.founder, d, "upheld")
    c = world.clear(world.voucher, v)
    led = build(world)
    assert led.vouches[v["id"]].status == "forfeited"
    assert c["id"] in led.rejected


def test_undecided_dispute_lapses_and_voucher_reclaims(world):
    """Nucleus 2/8: arbiter silent until the window closes -> voucher reclaims."""
    j = world.job()
    v = world.vouch(world.voucher, j)
    world.dispute(world.client, j)
    c = world.clear(world.voucher, v)
    led = build(world)
    assert c["id"] in led.accepted and led.vouches[v["id"]].status == "cleared"


# -- offer / acceptance -----------------------------------------------------

def test_nothing_happens_before_the_worker_accepts(world):
    j = world.job(accept=False)
    c = world.complete(world.client, j)
    d = world.dispute(world.client, j)
    v = world.vouch(world.voucher, j)
    h = world.handoff(world.worker, j, world.courier2, 1)
    led = build(world)
    for e in (c, d, v, h):
        assert "not accepted" in led.rejected[e["id"]]


def test_only_named_worker_accepts_once(world):
    j = world.job(accept=False)
    by_client = world.accept(world.client, j, at=T0 + 1)
    by_stranger = world.accept(world.stranger, j, at=T0 + 2)
    ok = world.accept(world.worker, j, at=T0 + 3)
    again = world.accept(world.worker, j, at=T0 + 4)
    led = build(world)
    assert by_client["id"] in led.rejected and by_stranger["id"] in led.rejected
    assert ok["id"] in led.accepted and "already accepted" in led.rejected[again["id"]]


def test_only_voucher_can_clear(world):
    j = world.job()
    v = world.vouch(world.voucher, j)
    c = world.clear(world.stranger, v)
    assert c["id"] in build(world).rejected


def test_parties_cannot_vouch_for_own_job(world):
    j = world.job(recipient=world.recipient)
    vs = [world.vouch(k, j) for k in (world.client, world.worker, world.recipient)]
    led = build(world)
    assert all(v["id"] in led.rejected for v in vs)


def test_bond_amount_limits(world):
    j = world.job()
    low = world.vouch(world.voucher, j, amount=9_999)
    high = world.vouch(world.stranger, j, amount=1_000_001)
    ok = world.vouch(world.founder, j, amount=10_000)
    led = build(world)
    assert low["id"] in led.rejected and high["id"] in led.rejected and ok["id"] in led.accepted


def test_max_active_vouches(world):
    vouches = [world.vouch(world.voucher, world.job(at=T0 + i), at=T0 + 100 + i) for i in range(6)]
    led = build(world)
    assert [v["id"] in led.accepted for v in vouches] == [True] * 5 + [False]
    assert "maximum" in led.rejected[vouches[5]["id"]]


def test_clearing_frees_a_vouch_slot(world):
    first = [world.vouch(world.voucher, world.job(at=T0 + i), at=T0 + 100 + i) for i in range(5)]
    world.clear(world.voucher, first[0], at=T0 + 8 * DAY)
    later_job = world.job(at=T0 + 8 * DAY + 10)
    sixth = world.vouch(world.voucher, later_job, at=T0 + 8 * DAY + 20)
    assert sixth["id"] in build(world).accepted


def test_vouch_after_window_rejected(world):
    j = world.job()
    v = world.vouch(world.voucher, j, at=T0 + 7 * DAY)
    assert v["id"] in build(world).rejected


# -- custody chain ----------------------------------------------------------

def test_handoff_chain(world):
    j = world.job(recipient=world.recipient)
    h1 = world.handoff(world.worker, j, world.courier2, 1, at=T0 + 10)
    bad = world.handoff(world.worker, j, world.recipient, 2, at=T0 + 20)  # worker no longer holds it
    h2 = world.handoff(world.courier2, j, world.recipient, 2, at=T0 + 30)
    led = build(world)
    assert h1["id"] in led.accepted and h2["id"] in led.accepted
    assert "current holder" in led.rejected[bad["id"]]


def test_handoff_sequence_enforced(world):
    j = world.job()
    h = world.handoff(world.worker, j, world.courier2, 2)
    assert "sequence" in build(world).rejected[h["id"]]
