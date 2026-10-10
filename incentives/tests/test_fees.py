"""Fee-share payouts (DECISIONS #35): network now, voucher only after the window."""
import dataclasses

import pytest

from conftest import DAY, T0
from htn import fees
from htn.ledger import Ledger

AMOUNT = 20_000  # 85/10/5 -> 17,000 / 2,000 / 1,000


def shares_for(world, *vouchers, cfg=None):
    job = world.job()
    for i, v in enumerate(vouchers):
        world.vouch(v, job, at=T0 + 600 + i)
    led = Ledger.build(world.events, cfg or world.config)
    return job, led, fees.accrue(led, world.job_id(job), AMOUNT, cfg or world.config)


def test_network_share_due_at_once_voucher_share_withheld(world):
    job, led, shares = shares_for(world, world.voucher)
    net, vou = shares
    assert (net.kind, net.sats, vou.kind, vou.sats) == ("network", 2_000, "voucher", 1_000)
    assert fees.status(net, led, T0)["due"]
    end = job["created_at"] + world.config.dispute_window_seconds
    assert not fees.status(vou, led, end)["due"]                       # window still open
    assert fees.status(vou, led, end + 1) == {"due": True, "payee": "voucher", "why": "due"}
    with pytest.raises(fees.FeeError, match="withheld"):
        fees.check_payable(vou, led, world.config, end, 1_000)


def test_forfeited_vouch_share_goes_to_client(world):
    job, led, shares = shares_for(world, world.voucher)
    world.resolve(world.founder, world.dispute(world.client, job), "upheld")
    led = Ledger.build(world.events, world.config)
    st = fees.status(shares[1], led, T0 + 8 * DAY)
    assert st["due"] and st["payee"] == "client"


def test_voucher_share_split_between_vouchers(world):
    _, _, shares = shares_for(world, world.voucher, world.stranger, world.courier2)
    vs = [s for s in shares if s.kind == "voucher"]
    assert sorted(s.sats for s in vs) == [333, 333, 334] and sum(s.sats for s in vs) == 1_000


def test_unvouched_share_per_config(world):
    _, _, shares = shares_for(world)
    assert [(s.kind, s.sats) for s in shares] == [("network", 2_000)]   # worker keeps the 5%
    cfg = dataclasses.replace(world.config, fee_unvouched_share="network")
    world.events.clear()
    _, _, shares = shares_for(world, cfg=cfg)
    assert [(s.kind, s.sats) for s in shares] == [("network", 3_000)]


def test_invoice_must_match_and_mode_is_respected(world):
    _, led, shares = shares_for(world, world.voucher)
    with pytest.raises(fees.FeeError, match="invoice is for"):
        fees.check_payable(shares[0], led, world.config, T0, 1_999)
    sweep = dataclasses.replace(world.config, fee_payout="sweep")
    with pytest.raises(fees.FeeError, match="swept"):
        fees.check_payable(shares[0], led, sweep, T0, 2_000)
    with pytest.raises(fees.FeeError, match="sweep_address"):
        fees.sweepable(shares, led, sweep, T0)
    with pytest.raises(fees.FeeError, match="lightning"):
        fees.sweepable(shares, led, world.config, T0)


def test_settling_twice_cannot_double_the_shares(world):
    _, _, shares = shares_for(world, world.voucher)
    assert fees.merge(shares, list(shares)) == shares


def test_sweep_address_must_be_test_network():
    from htn.config import Config, ConfigError
    with pytest.raises(ConfigError):
        Config(fee_sweep_address="b" + "c1qexample")


# -- live, through the command-line tool --------------------------------------

from htn import payments as pay           # noqa: E402
from htn import sandbox as sb             # noqa: E402
from test_cli import last_id, run         # noqa: E402,F401  (run is a fixture)

live = pytest.mark.skipif(
    not ((sb.BIN / "bitcoin-cli.exe").exists() and sb._bitcoind_up() and sb._lnd_up("client")),
    reason="sandbox not running (python -m htn sandbox up)")


def paid_job(run, now):
    """A vouched job paid through a hold invoice and settled; returns the job id."""
    f = str(run.private)
    _, out = run("job-offer", "--as", "client", "--worker", "worker", "--terms-file", f, "--at", str(now))
    job = out.split("job id ")[1].strip()
    run("accept", "--as", "worker", "--job", job, "--at", str(now + 1))
    run("vouch-issue", "--as", "voucher", "--job", job, "--amount", "20000", "--at", str(now + 2))
    _, out = run("pay-secret", "--job", job)
    h = out.split("payment hash ")[1].split()[0]
    _, out = run("invoice", "--job", job, "--hash", h, "--amount", str(AMOUNT), "--expected-minutes", "30")
    pr = out.split("payment request ")[1].split()[0]
    pay.LndNode("client").pay(pr)
    worker = pay.LndNode("worker")
    for _ in range(60):
        if worker.state(h) == "ACCEPTED":
            break
        __import__("time").sleep(1)
    run("receipt", "--as", "client", "--job", job, "--at", str(now + 30))
    code, out = run("settle", "--job", job, "--receipt",
                    str(run.home / "private" / "receipts" / f"{job}.json"))
    assert code == 0 and "fee share owed: network 2000" in out and "voucher 1000" in out, out
    return job


def share_ids(out):
    return {line.split()[1]: line.split()[0] for line in out.splitlines() if "sats" in line}


@live
def test_live_fee_shares_paid_by_lightning(run):
    now = int(__import__("time").time())
    paid_job(run, now)
    code, out = run("fees")
    ids = share_ids(out)
    payee = pay.LndNode("client")           # stands in for the network / the voucher
    code, out = run("fees-pay", ids["network"], "--invoice", payee.add_invoice(1_999))
    assert code == 1 and "invoice is for 1999" in out
    code, out = run("fees-pay", ids["network"], "--invoice", payee.add_invoice(2_000))
    assert code == 0 and "paid 2000 sats to the network" in out, out
    code, out = run("fees-pay", ids["voucher"], "--invoice", payee.add_invoice(1_000))
    assert code == 1 and "withheld until the dispute window closes" in out
    after = str(now + 8 * DAY)
    code, out = run("fees-pay", ids["voucher"], "--invoice", payee.add_invoice(1_000), "--at", after)
    assert code == 0 and "paid 1000 sats to the voucher" in out, out
    code, out = run("fees", "--at", after)
    assert out.count("paid") == 2


@live
def test_live_network_shares_swept_onchain(run, tmp_path):
    sweep_to = sb.lncli("client", "newaddress", "p2tr")["address"]
    cfg = tmp_path / "config.toml"
    cfg.write_text(cfg.read_text() + f'[fees]\npayout = "sweep"\nsweep_address = "{sweep_to}"\n')
    worker_addr = sb.lncli("worker", "newaddress", "p2tr")["address"]
    sb.fund_address(worker_addr, 100_000)  # the worker needs on-chain coins to sweep from
    now = int(__import__("time").time())
    paid_job(run, now)
    paid_job(run, now + 10)
    code, out = run("fees-sweep")
    assert code == 0 and "swept 4000 sats (2 shares)" in out, out
    txid = out.split("txid ")[1].split()[0]
    sb.mine(1)
    outs = sb.get_tx(txid)["vout"]
    assert any(o["scriptPubKey"].get("address") == sweep_to and round(o["value"] * 1e8) == 4_000
               for o in outs)
    assert run("fees-sweep")[1].strip() == "nothing to sweep"
