"""End-to-end through the command-line tool, in a throwaway folder."""
import json

import pytest

from htn import keys
from htn.cli import main

T0 = 1_700_000_000
DAY = 24 * 3600


@pytest.fixture
def run(tmp_path, capsys):
    home, kdir = tmp_path / "data", tmp_path / "keys"
    for n in ("client", "worker", "voucher", "founder", "backup", "worker-new", "thief"):
        keys.save(keys.generate(n), kdir)
    rec = keys.generate("worker-rec")                      # recovery key: its own folder
    keys.save(rec, tmp_path / "recovery", role="recovery")
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'[arbiters]\nfounder = "{keys.load("founder", kdir).pubkey}"\n'
                   f'backup = "{keys.load("backup", kdir).pubkey}"\n')
    private = tmp_path / "terms.txt"
    private.write_text("Deliver sealed case to Jane Smith, 12 Main St")

    def _run(*args):
        code = main(["--home", str(home), "--keys-dir", str(kdir), "--config", str(cfg), *args])
        out = capsys.readouterr()
        return code, out.out + out.err
    _run.home, _run.private = home, private
    _run.rec_pub, _run.rec_file = rec.pubkey, str(tmp_path / "recovery" / "worker-rec.json")
    return _run


def last_id(out):
    return [line.split()[-1] for line in out.splitlines() if " event " in line][-1]


def test_full_flow(run):
    f = str(run.private)
    code, out = run("job-offer", "--as", "client", "--worker", "worker", "--terms-file", f, "--at", str(T0))
    assert code == 0, out
    job = out.split("job id ")[1].strip()
    assert run("accept", "--as", "worker", "--job", job, "--at", str(T0 + 5))[0] == 0
    job_event = last_id(out)

    code, out = run("complete", "--as", "worker", "--job", job, "--receipt-file", f, "--at", str(T0 + 60))
    assert code == 1 and "refused" in out  # worker cannot complete own job

    assert run("complete", "--as", "client", "--job", job, "--receipt-file", f, "--at", str(T0 + 60))[0] == 0
    code, out = run("vouch-issue", "--as", "voucher", "--job", job, "--amount", "20000", "--at", str(T0 + 30))
    vouch = last_id(out)
    assert run("vouch-clear", "--as", "voucher", "--vouch", vouch, "--at", str(T0 + 8 * DAY))[0] == 0

    code, out = run("verify", job_event)
    assert code == 0 and json.loads(out)["status"] == "pending"

    code, out = run("check")
    assert code == 0 and "REJECTED" not in out

    code, out = run("score", "worker")
    rec = next(iter(json.loads(out)["operators"].values()))
    assert rec["completed_jobs"] == 1 and rec["score"] == 1

    # Nothing private ever reached the public event store.
    for p in (run.home / "events").glob("*.json"):
        text = p.read_text()
        assert "Jane" not in text and "Main St" not in text
    # Every event has a proof.
    events = {p.stem for p in (run.home / "events").glob("*.json")}
    proofs = {p.stem for p in (run.home / "proofs").glob("*.ots")}
    assert events == proofs


def test_dispute_flow_with_arbiter(run):
    f = str(run.private)
    _, out = run("job-offer", "--as", "client", "--worker", "worker", "--terms-file", f, "--at", str(T0))
    job = out.split("job id ")[1].strip()
    assert run("accept", "--as", "worker", "--job", job, "--at", str(T0 + 5))[0] == 0
    _, out = run("dispute-file", "--as", "client", "--job", job, "--reason-file", f, "--at", str(T0 + DAY))
    dispute = last_id(out)
    assert run("dispute-resolve", "--as", "worker", "--dispute", dispute, "--outcome", "rejected",
               "--at", str(T0 + DAY + 1))[0] == 1
    assert run("dispute-resolve", "--as", "founder", "--dispute", dispute, "--outcome", "upheld",
               "--at", str(T0 + DAY + 2))[0] == 0
    rec = next(iter(json.loads(run("score", "worker")[1])["operators"].values()))
    assert rec["upheld_disputes"] == 1 and rec["score"] == -5


def test_unknown_key_is_a_clean_error(run):
    code, out = run("job-offer", "--as", "nobody", "--worker", "worker",
                    "--terms-file", str(run.private))
    assert code == 1 and "no key named" in out


def test_stolen_key_recovery_flow(run):
    f = str(run.private)
    code, out = run("onboard", "--as", "worker", "--recovery-pub", run.rec_pub, "--at", str(T0 - DAY))
    assert code == 0 and "OFFLINE" in out, out
    op = out.split("operator id ")[1].split()[0]
    _, out = run("job-offer", "--as", "client", "--worker", "worker", "--terms-file", f, "--at", str(T0))
    job = out.split("job id ")[1].strip()
    assert run("accept", "--as", "worker", "--job", job, "--at", str(T0 + 5))[0] == 0
    run("complete", "--as", "client", "--job", job, "--receipt-file", f, "--at", str(T0 + 10))

    # Thief with the stolen key rotates to their own key.
    assert run("rotate", "--as", "worker", "--new", "thief", "--at", str(T0 + 100))[0] == 0
    # Owner recovers, marking everything since the theft as compromised.
    code, out = run("recover", "--recovery-file", run.rec_file, "--new", "worker-new",
                    "--since", str(T0 + 50), "--at", str(T0 + 200))
    assert code == 0, out

    code, out = run("identity", "worker")
    assert "COMPROMISED" in out and keys.load("worker-new", run.home.parent / "keys").pubkey in out
    code, out = run("check")
    assert "DISPUTABLE" in out  # the thief's rotation
    rec = json.loads(run("score", op)[1])["operators"][op]
    assert rec["completed_jobs"] == 1 and len(rec["keys"]) == 3
    # Thief can no longer act.
    code, out = run("rotate", "--as", "thief", "--new", "client", "--operator", op, "--at", str(T0 + 300))
    assert code == 1 and "refused" in out


def test_recovery_key_is_kept_apart(run, tmp_path):
    """Recovery keys live in their own folder and normal commands refuse to load them."""
    code, out = run("recovery-keygen", "op-rec", "--out", str(tmp_path / "rec2"))
    assert code == 0 and (tmp_path / "rec2" / "op-rec.json").exists()
    assert not (tmp_path / "keys" / "op-rec.json").exists()
    code, out = run("recovery-keygen", "bad", "--out", str(tmp_path / "keys"))
    assert code == 1 and "must not live" in out
    # Even if a recovery key file is dropped into the everyday folder, it is refused.
    keys.save(keys.generate("stray-rec"), tmp_path / "keys", role="recovery")
    code, out = run("job-offer", "--as", "stray-rec", "--worker", "worker",
                    "--terms-file", str(run.private))
    assert code == 1 and "RECOVERY key" in out
    code, out = run("keys")
    assert "stray-rec" not in out
    # An operational key can't be used to recover.
    code, out = run("recover", "--recovery-file", str(tmp_path / "keys" / "worker.json"), "--new", "thief")
    assert code == 1 and "not a recovery key" in out


def test_agent_delegation_flow(run):
    f = str(run.private)
    kdir = run.home.parent / "keys"
    keys.save(keys.generate("bot"), kdir)
    _, out = run("onboard", "--as", "worker", "--recovery-pub", run.rec_pub, "--at", str(T0 - DAY))
    assert run("delegate", "--as", "worker", "--agent", "bot", "--scope", "job_accepted",
               "--at", str(T0 - 10))[0] == 0
    _, out = run("job-offer", "--as", "client", "--worker", "worker", "--terms-file", f, "--at", str(T0))
    job = out.split("job id ")[1].strip()
    assert run("accept", "--as", "bot", "--job", job, "--at", str(T0 + 1))[0] == 0
    code, out = run("identity", "worker")
    assert "agent" in out and "active" in out
    assert run("revoke-agent", "--recovery-file", run.rec_file, "--agent", "bot", "--at", str(T0 + 2))[0] == 0
    _, out = run("job-offer", "--as", "client", "--worker", "worker", "--terms-file", f, "--at", str(T0 + 3))
    job2 = out.split("job id ")[1].strip()
    code, out = run("accept", "--as", "bot", "--job", job2, "--at", str(T0 + 4))
    assert code == 1 and "revoked" in out


from htn import sandbox as _sb

_live = pytest.mark.skipif(
    not ((_sb.BIN / "bitcoin-cli.exe").exists() and _sb._bitcoind_up() and _sb._lnd_up("client")),
    reason="sandbox not running")


@_live
def test_live_payment_flow_through_cli(run):
    import time as _t
    f = str(run.private)
    keys.save(keys.generate("recipient"), run.home.parent / "keys")
    _, out = run("job-offer", "--as", "client", "--worker", "worker", "--recipient", "recipient",
                 "--terms-file", f)
    job = out.split("job id ")[1].strip()
    assert run("accept", "--as", "worker", "--job", job)[0] == 0
    _, out = run("pay-secret", "--job", job)
    h = out.split("payment hash ")[1].split()[0]
    code, out = run("invoice", "--job", job, "--hash", h, "--amount", "15000", "--expected-minutes", "999")
    assert code == 1 and "escrow" in out                       # longer than 6 hours: refused
    code, out = run("invoice", "--job", job, "--hash", h, "--amount", "15000", "--expected-minutes", "90")
    assert code == 0, out
    pr = out.split("payment request ")[1].split()[0]
    assert run("pay", pr)[0] == 0
    for _ in range(60):
        if "ACCEPTED" in run("hold-check")[1]:
            break
        _t.sleep(1)
    _t.sleep(1)  # created_at is whole seconds; keep the completion after the acceptance
    code, out = run("receipt", "--as", "recipient", "--job", job)
    assert code == 0, out
    receipt_file = out.split("receipt saved to ")[1].split(";")[0]
    code, out = run("settle", "--job", job, "--receipt", receipt_file)
    assert code == 0, out
    assert "SETTLED" in run("hold-check")[1]
    # The public record has the hash but never the secret.
    secret = json.loads(open(receipt_file).read())["secret"]
    public = " ".join(p.read_text() for p in (run.home / "events").glob("*.json"))
    assert h in public and secret not in public
