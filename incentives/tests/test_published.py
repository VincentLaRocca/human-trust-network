"""What leaves the machine: nonces never published; one job's chain can be rebuilt and checked."""
import json

from conftest import T0
from htn.chain import job_chain
from htn.ledger import Ledger
from test_cli import last_id, run  # noqa: F401  (run is a fixture)

DAY = 24 * 3600


def busy_job(run):
    """A job that touches every kind of hash commitment."""
    f = str(run.private)
    _, out = run("job-offer", "--as", "client", "--worker", "worker", "--terms-file", f, "--at", str(T0))
    job = out.split("job id ")[1].strip()
    run("accept", "--as", "worker", "--job", job, "--at", str(T0 + 5))
    run("handoff", "--as", "worker", "--job", job, "--to", "voucher", "--item-file", f, "--at", str(T0 + 10))
    run("complete", "--as", "client", "--job", job, "--receipt-file", f, "--at", str(T0 + 60))
    _, out = run("dispute-file", "--as", "client", "--job", job, "--reason-file", f, "--at", str(T0 + 70))
    run("dispute-resolve", "--as", "founder", "--dispute", last_id(out), "--outcome", "rejected",
        "--ruling-file", f, "--at", str(T0 + 80))
    return job


def published_bytes(home):
    out = b""
    for folder in ("events", "proofs"):
        for p in sorted((home / folder).glob("*")):
            out += p.read_bytes()
    return out


def test_nonces_and_salts_never_published(run):
    busy_job(run)
    secrets = []
    for p in (run.home / "private").glob("*.json"):
        for entries in json.loads(p.read_text()).values():
            secrets += [e["salt"] for e in entries]
    assert len(secrets) >= 5  # job nonce, item, receipt, reason, ruling
    public = published_bytes(run.home)
    for s in secrets:
        assert s.encode() not in public.lower()            # as hex text
        assert bytes.fromhex(s) not in public               # as raw bytes (e.g. inside proofs)
    assert run.private.read_bytes() not in public           # nor the private terms themselves
    for p in (run.home / "events").glob("*.json"):
        event = json.loads(p.read_text())
        assert event["content"] == ""


def test_job_chain_verifier(run):
    job = busy_job(run)
    code, out = run("verify-job", job)
    report = json.loads(out)
    assert code == 0 and report["ok"], report["problems"]
    kinds = [s["kind"] for s in report["steps"]]
    assert kinds == ["job_offer", "job_accepted", "handoff", "completion",
                     "dispute_filed", "dispute_resolved"]
    assert all(s["timestamp"] not in ("missing", "invalid") for s in report["steps"])
    assert report["summary"]["completed"] and report["summary"]["disputes"][0]["outcome"] == "rejected"


def test_job_chain_flags_problems(world):
    job = world.job()
    world.complete(world.worker, job, worker=world.worker.pubkey)   # worker signs own completion
    jid = world.job_id(job)
    report = job_chain(world.events, world.config, jid)
    assert not report["ok"]
    assert any("not the worker" in p for p in report["problems"])
    # A missing earlier event is noticed: drop the offer.
    report = job_chain(world.events[1:], world.config, jid)
    assert not report["ok"] and any("no accepted job offer" in p for p in report["problems"])
    assert job_chain(world.events, world.config, "ff" * 32)["ok"] is False


def test_job_chain_flags_missing_proof(run):
    job = busy_job(run)
    proof = next((run.home / "proofs").glob("*.ots"))
    proof.unlink()
    code, out = run("verify-job", job)
    assert code == 1 and "timestamp proof missing" in out
