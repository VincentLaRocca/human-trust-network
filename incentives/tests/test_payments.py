"""Phase 4: hold-invoice payments.

Offline tests use a fake Lightning network; the `live_*` tests run the same
flows on the real regtest sandbox and are skipped when it isn't running.
"""
import dataclasses
import json
import time

import pytest

from conftest import T0
from htn import events as ev
from htn import payments as pay
from htn import sandbox as sb
from htn.config import Config

AMOUNT = 20_000
CFG = Config()


@pytest.fixture
def fake():
    net = pay.FakeLightning({"client": 100_000, "worker": 0})
    return net.node("client"), net.node("worker")


def start(world, client_node, worker_node, cfg=CFG, expected=3600):
    """Recipient makes the secret; worker invoices on its hash; client pays."""
    secret, h = pay.new_payment_secret()
    job = world.job(recipient=world.recipient)
    inv = pay.create_hold_invoice(worker_node, cfg, world.job_id(job), h, AMOUNT, expected)
    handle = client_node.pay(inv.payment_request)
    return job, secret, inv, handle


def signers(world):
    return {world.recipient.pubkey, world.client.pubkey}


# -- offline ----------------------------------------------------------------

def test_happy_path(world, fake):
    client, worker = fake
    job, secret, inv, handle = start(world, client, worker)
    assert worker.state(inv.payment_hash) == "ACCEPTED"          # money is held
    assert client.channel_sats() == 100_000 - AMOUNT and worker.channel_sats() == 0
    receipt = pay.sign_receipt(world.recipient, world.job_id(job), inv.payment_hash, secret, T0 + 60)
    pay.settle_with_receipt(worker, inv, receipt, signers(world))
    assert handle.wait(1) == "SUCCEEDED" and worker.channel_sats() == AMOUNT


def test_recipient_never_signs_client_refunded(world, fake):
    client, worker = fake
    job, secret, inv, handle = start(world, client, worker)
    assert not pay.enforce_max_hold(worker, inv, held_since=T0, now=T0 + CFG.max_hold_seconds - 1, config=CFG)
    assert pay.enforce_max_hold(worker, inv, held_since=T0, now=T0 + CFG.max_hold_seconds, config=CFG)
    assert worker.state(inv.payment_hash) == "CANCELED"
    assert handle.wait(1) == "FAILED" and client.channel_sats() == 100_000


def test_worker_cannot_settle_without_secret(world, fake):
    client, worker = fake
    job, secret, inv, handle = start(world, client, worker)
    with pytest.raises(pay.PaymentError):
        worker.settle("00" * 32)                                   # guessing doesn't work
    forged = pay.sign_receipt(world.worker, world.job_id(job), inv.payment_hash, secret, T0)
    with pytest.raises(pay.PaymentError, match="not signed by"):
        pay.settle_with_receipt(worker, inv, forged, signers(world))   # worker can't sign its own receipt
    tampered = dict(pay.sign_receipt(world.recipient, world.job_id(job), inv.payment_hash, secret, T0))
    tampered["secret"] = "11" * 32
    with pytest.raises(pay.PaymentError):
        pay.settle_with_receipt(worker, inv, tampered, signers(world))
    assert worker.state(inv.payment_hash) == "ACCEPTED" and handle.status is None


def test_receipt_for_other_job_rejected(world, fake):
    client, worker = fake
    job, secret, inv, _ = start(world, client, worker)
    other = pay.sign_receipt(world.recipient, "ab" * 32, inv.payment_hash, secret, T0)
    with pytest.raises(pay.PaymentError, match="different job"):
        pay.settle_with_receipt(worker, inv, other, signers(world))


def test_recipient_cannot_sign_wrong_secret(world):
    _, h = pay.new_payment_secret()
    with pytest.raises(pay.PaymentError):
        pay.sign_receipt(world.recipient, "ab" * 32, h, "22" * 32, T0)


def test_long_jobs_rejected_from_hold_flow(world, fake):
    _, worker = fake
    _, h = pay.new_payment_secret()
    with pytest.raises(pay.PaymentError, match="escrow"):
        pay.create_hold_invoice(worker, CFG, "ab" * 32, h, AMOUNT, CFG.max_hold_seconds + 1)
    pay.create_hold_invoice(worker, CFG, "ab" * 32, h, AMOUNT, CFG.max_hold_seconds)  # exactly the limit is ok


def test_cltv_backstop_covers_max_hold():
    blocks = pay.cltv_delta_for(CFG)
    # LND auto-cancels `holdexpirydelta` blocks before expiry; that must still be after max hold.
    assert (blocks - pay.LND_HOLD_EXPIRY_DELTA) * 600 >= CFG.max_hold_seconds
    assert blocks < 144  # and well under a day


def test_fee_split():
    assert pay.fee_split(20_000, CFG) == {"worker": 17_000, "network": 2_000, "voucher_held": 1_000}
    s = pay.fee_split(999, CFG)
    assert sum(s.values()) == 999 and s["worker"] == 999 - 99 - 49  # remainder to worker


def test_secret_never_in_public_events(world, fake):
    client, worker = fake
    job, secret, inv, _ = start(world, client, worker)
    completion = world.emit(world.recipient, ev.COMPLETION, [
        ["job", world.job_id(job)], ["e", job["id"]], ["p", world.worker.pubkey, "worker"],
        ["receipt", ev.commit(b"r")[0]], ["payment", inv.payment_hash]], T0 + 100)
    from htn.ledger import Ledger
    led = Ledger.build(world.events, world.config)
    assert completion["id"] in led.accepted
    assert secret not in json.dumps(world.events)


# -- live, on the regtest sandbox --------------------------------------------

live = pytest.mark.skipif(
    not ((sb.BIN / "bitcoin-cli.exe").exists() and sb._bitcoind_up() and sb._lnd_up("client")),
    reason="sandbox not running (python -m htn sandbox up)")


@pytest.fixture
def lnd():
    return pay.LndNode("client"), pay.LndNode("worker")


def wait_state(node, h, want, timeout=60):
    for _ in range(timeout):
        if node.state(h) == want:
            return True
        time.sleep(1)
    return False


@live
def test_live_happy_path(world, lnd):
    client, worker = lnd
    before = worker.channel_sats()
    job, secret, inv, handle = start(world, client, worker)
    assert wait_state(worker, inv.payment_hash, "ACCEPTED")
    receipt = pay.sign_receipt(world.recipient, world.job_id(job), inv.payment_hash, secret, T0 + 60)
    pay.settle_with_receipt(worker, inv, receipt, signers(world))
    assert handle.wait(60) == "SUCCEEDED"
    assert worker.state(inv.payment_hash) == "SETTLED"
    assert worker.channel_sats() == before + AMOUNT


@live
def test_live_recipient_never_signs_watchdog_refunds(world, lnd):
    client, worker = lnd
    before = client.channel_sats()
    cfg = dataclasses.replace(CFG, max_hold_seconds=2)
    job, secret, inv, handle = start(world, client, worker, cfg=cfg, expected=1)
    assert wait_state(worker, inv.payment_hash, "ACCEPTED")
    held_since = int(time.time())
    assert client.channel_sats() < before                           # money is held
    assert pay.enforce_max_hold(worker, inv, held_since, held_since + 3, cfg)
    assert handle.wait(60) == "FAILED"
    assert worker.state(inv.payment_hash) == "CANCELED"
    assert client.channel_sats() == before                          # refunded in full


@live
def test_live_lightning_backstop_cancels_even_if_worker_does_nothing(world, lnd):
    """No watchdog at all: LND cancels the hold itself as the block deadline nears."""
    client, worker = lnd
    before = client.channel_sats()
    job, secret, inv, handle = start(world, client, worker)
    assert wait_state(worker, inv.payment_hash, "ACCEPTED")
    deadline = pay.cltv_delta_for(CFG)
    sb.mine(deadline - pay.LND_HOLD_EXPIRY_DELTA)  # payer adds 3 blocks of padding, so still 3 short
    assert worker.state(inv.payment_hash) == "ACCEPTED"             # still held inside the limit
    for _ in range(6):
        sb.mine(1)
        if worker.state(inv.payment_hash) == "CANCELED":
            break
    assert worker.state(inv.payment_hash) == "CANCELED"
    assert handle.wait(60) == "FAILED" and client.channel_sats() == before


@live
def test_live_worker_cannot_settle_without_secret(world, lnd):
    client, worker = lnd
    job, secret, inv, handle = start(world, client, worker)
    assert wait_state(worker, inv.payment_hash, "ACCEPTED")
    with pytest.raises(pay.PaymentError):
        worker.settle("33" * 32)
    assert worker.state(inv.payment_hash) == "ACCEPTED"
    worker.cancel(inv.payment_hash)                                 # clean up: refund
    assert handle.wait(60) == "FAILED"
