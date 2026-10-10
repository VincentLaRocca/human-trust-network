"""Schema enforcement - the privacy guarantee lives here.

If any event carries a field outside the allowed schema, these tests fail.
"""
import pytest

from htn import events as ev
from htn import schema
from htn.ledger import Ledger


def full_scenario(world):
    j = world.job(recipient=world.recipient)
    world.handoff(world.worker, j, world.courier2, 1)
    world.handoff(world.courier2, j, world.recipient, 2, at=world.events[-1]["created_at"] + 60)
    v = world.vouch(world.voucher, j)
    world.complete(world.recipient, j)
    d = world.dispute(world.client, j)
    world.resolve(world.founder, d, "rejected")
    world.clear(world.voucher, v)
    return world.events


def test_every_event_kind_produced_passes_schema(world):
    evs = full_scenario(world)
    assert {e["kind"] for e in evs} == set(ev.KIND_NAMES) - ev.IDENTITY_KINDS
    for e in evs:
        schema.validate(e)
    led = Ledger.build(evs, world.config)
    assert not led.rejected, led.rejected


def test_no_private_text_leaks_into_events(world):
    import json
    blob = json.dumps(full_scenario(world))
    for secret in ("private terms", "seal 1", "broken seal"):
        assert secret not in blob


def resign(world, key, kind, tags, content="", extra=None, created_at=1_700_000_000):
    e = {"pubkey": key.pubkey, "created_at": created_at, "kind": kind, "tags": tags, "content": content}
    e["id"] = ev.compute_id(e)
    e["sig"] = key.sign(bytes.fromhex(e["id"]))
    if extra:
        e.update(extra)
    return e


def good_tags(world):
    return [["job", ev.make_job_id(b"t")[0]], ["p", world.worker.pubkey, "worker"],
            ["p", world.recipient.pubkey, "recipient"]]


@pytest.mark.parametrize("mutate,why", [
    (lambda w, t: (t, "Deliver to Jane Smith", None), "content"),
    (lambda w, t: (t + [["name", "Jane Smith"]], "", None), "extra tag"),
    (lambda w, t: (t + [["address", "12 Main St"]], "", None), "address tag"),
    (lambda w, t: (t + [["p", w.client.pubkey, "client_name"]], "", None), "unknown p role"),
    (lambda w, t: (t, "", {"client": "Jane"}), "extra top-level field"),
    (lambda w, t: ([["job", "smith-delivery-12-main-st"]] + t[1:], "", None), "readable job id"),
    (lambda w, t: (t[:2] + [["p", "Jane Smith", "recipient"]], "", None), "plaintext in key field"),
    (lambda w, t: (t + [["p", "cd" * 32, "recipient"]], "", None), "duplicate tag"),
    (lambda w, t: (t[:1], "", None), "missing required tag"),
    (lambda w, t: (t[:1] + [["p", w.worker.pubkey, "worker", "extra"]] + t[2:], "", None), "long p tag"),
    (lambda w, t: (t[:2] + [["p", "AB" * 32, "recipient"]], "", None), "uppercase hex"),
    (lambda w, t: (t + [["terms", "ab" * 32]], "", None), "tag not in this kind's schema"),
])
def test_schema_rejects(world, mutate, why):
    tags, content, extra = mutate(world, good_tags(world))
    e = resign(world, world.client, ev.JOB_OFFER, tags, content, extra)
    with pytest.raises(schema.SchemaError):
        schema.validate(e)
    led = Ledger.build([e], world.config)
    assert e["id"] in led.rejected and not led.accepted, why


def test_schema_accepts_good_event(world):
    schema.validate(resign(world, world.client, ev.JOB_OFFER, good_tags(world)))


@pytest.mark.parametrize("bad", [
    {"kind": 1}, {"kind": "3910"}, {"created_at": "now"}, {"created_at": True},
    {"created_at": 0}, {"tags": "x"}, {"tags": [["job"]]}, {"tags": [[1, 2]]}, {"sig": "00"},
])
def test_schema_rejects_bad_types(world, bad):
    e = {**resign(world, world.client, ev.JOB_OFFER, good_tags(world)), **bad}
    with pytest.raises(schema.SchemaError):
        schema.validate(e)


def test_non_dict_events_counted_as_malformed(world):
    led = Ledger.build(["junk", 42, None, {"no": "id"}], world.config)
    assert led.malformed == 4 and not led.accepted


def test_store_refuses_to_save_out_of_schema_event(world, tmp_path):
    from htn.store import Store
    e = resign(world, world.client, ev.JOB_OFFER, good_tags(world), content="Jane Smith")
    with pytest.raises(schema.SchemaError):
        Store(tmp_path).save_event(e)
    assert not (tmp_path / "events").exists()
