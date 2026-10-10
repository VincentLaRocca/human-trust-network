"""Hold-invoice payments for same-day jobs (Nucleus section 1, brief Phase 4).

Flow:
  1. Recipient makes a random 32-byte secret and gives only its SHA-256 hash
     to the worker.
  2. Worker creates a Lightning hold invoice locked to that hash, but only
     if the job's expected duration fits within `max_hold_seconds`.
  3. Client pays. The money is now held: it has left the client but can't be
     claimed without the secret.
  4. On delivery the recipient signs a PRIVATE receipt containing the secret
     and hands it to the worker (it is never published). The recipient also
     publishes the normal completion event, which carries only the hash.
  5. Worker checks the receipt (right signer, right job, secret matches the
     hash) and settles. The client's payment completes.

If no receipt arrives in time, the hold is cancelled and the client's money
returns. Two layers enforce that:
  - the worker's watchdog (`enforce_max_hold`) cancels once max_hold_seconds
    has passed since the payment arrived;
  - a hard backstop in Lightning itself: the invoice's CLTV delta is sized so
    LND cancels the hold automatically when the HTLC nears its block
    deadline, even if the worker does nothing.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import threading
from dataclasses import dataclass

from . import keys
from .config import SECONDS_PER_BLOCK, Config

RECEIPT_TYPE = "htn-receipt-v1"
# LND cancels a held payment this many blocks before its deadline (measured: the
# sandbox sets `--invoices.holdexpirydelta` to this explicitly).
LND_HOLD_EXPIRY_DELTA = 18
LND_MIN_CLTV_DELTA = 25      # LND refuses hold invoices with a smaller final CLTV delta
CLTV_SAFETY_BLOCKS = 6


class PaymentError(Exception):
    pass


# -- secrets, eligibility, fee split -------------------------------------------

def new_payment_secret() -> tuple[str, str]:
    """Recipient side. Returns (secret_hex, payment_hash_hex). Keep the secret private."""
    secret = os.urandom(32)
    return secret.hex(), hashlib.sha256(secret).hexdigest()


def check_hold_eligible(config: Config, expected_seconds: int) -> None:
    if expected_seconds <= 0:
        raise PaymentError("expected job duration must be positive")
    if expected_seconds > config.max_hold_seconds:
        raise PaymentError(
            f"job expected to take {expected_seconds}s, longer than the {config.max_hold_seconds}s "
            "hold-invoice limit: use a fresh hold invoice near completion, or on-chain escrow")


def cltv_delta_for(config: Config) -> int:
    """Blocks of HTLC lifetime: covers the max hold, plus LND's auto-cancel margin."""
    blocks = math.ceil(config.max_hold_seconds / SECONDS_PER_BLOCK) + LND_HOLD_EXPIRY_DELTA + CLTV_SAFETY_BLOCKS
    return max(blocks, LND_MIN_CLTV_DELTA)


def fee_split(amount_sats: int, config: Config) -> dict:
    """Worker / network / voucher shares. Rounding remainders go to the worker.

    The voucher share is only released after the dispute window closes on a
    clean vouch; until then it is reported as held.
    """
    network = amount_sats * config.fee_network_pct // 100
    voucher = amount_sats * config.fee_voucher_pct // 100
    return {"worker": amount_sats - network - voucher, "network": network, "voucher_held": voucher}


# -- the private receipt -------------------------------------------------------

def _receipt_digest(body: dict) -> bytes:
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).digest()


def sign_receipt(recipient: keys.Key, job_id: str, payment_hash: str, secret_hex: str, at: int) -> dict:
    """Recipient's signed delivery receipt. PRIVATE: give it to the worker, never publish."""
    if hashlib.sha256(bytes.fromhex(secret_hex)).hexdigest() != payment_hash:
        raise PaymentError("secret does not match the payment hash")
    body = {"type": RECEIPT_TYPE, "job": job_id, "payment_hash": payment_hash,
            "secret": secret_hex, "created_at": at, "pubkey": recipient.pubkey}
    return {**body, "sig": recipient.sign(_receipt_digest(body))}


def verify_receipt(receipt: dict, job_id: str, payment_hash: str, allowed_signers: set[str]) -> str:
    """Check a receipt before settling. Returns the secret, or raises PaymentError."""
    body = {k: receipt.get(k) for k in ("type", "job", "payment_hash", "secret", "created_at", "pubkey")}
    if body["type"] != RECEIPT_TYPE:
        raise PaymentError("not a receipt")
    if body["job"] != job_id or body["payment_hash"] != payment_hash:
        raise PaymentError("receipt is for a different job or payment")
    if body["pubkey"] not in allowed_signers:
        raise PaymentError("receipt not signed by the job's recipient or client")
    if not keys.verify(body["pubkey"], receipt.get("sig", ""), _receipt_digest(body)):
        raise PaymentError("bad receipt signature")
    try:
        ok = hashlib.sha256(bytes.fromhex(body["secret"])).hexdigest() == payment_hash
    except (TypeError, ValueError):
        ok = False
    if not ok:
        raise PaymentError("receipt secret does not unlock this payment")
    return body["secret"]


# -- Lightning nodes -----------------------------------------------------------

class PayHandle:
    """A payment in flight. With hold invoices, it resolves when the worker settles or cancels."""

    def __init__(self):
        self.done = threading.Event()
        self.status: str | None = None  # SUCCEEDED / FAILED
        self.detail = ""

    def finish(self, status: str, detail: str = "") -> None:
        self.status, self.detail = status, detail
        self.done.set()

    def wait(self, timeout: float = 120) -> str | None:
        self.done.wait(timeout)
        return self.status


class LndNode:
    """One LND node of the regtest sandbox (see sandbox.py)."""

    def __init__(self, name: str):
        from . import sandbox
        self.name, self._sb = name, sandbox

    def _cli(self, *args, timeout=60):
        try:
            return self._sb.lncli(self.name, *args, timeout=timeout)
        except self._sb.SandboxError as e:
            raise PaymentError(str(e)) from e

    def add_hold_invoice(self, payment_hash: str, amount_sats: int, config: Config) -> str:
        return self._cli("addholdinvoice", payment_hash, f"--amt={amount_sats}",
                         f"--expiry={max(config.max_hold_seconds, 600)}",  # time allowed to pay
                         f"--cltv_expiry_delta={cltv_delta_for(config)}")["payment_request"]

    def state(self, payment_hash: str) -> str:
        return self._cli("lookupinvoice", payment_hash)["state"]

    def settle(self, secret_hex: str) -> None:
        self._cli("settleinvoice", secret_hex)

    def cancel(self, payment_hash: str) -> None:
        self._cli("cancelinvoice", payment_hash)

    def pay(self, payment_request: str) -> PayHandle:
        handle = PayHandle()

        def run():
            try:
                out = self._cli("payinvoice", "--force", "--json", payment_request,
                                timeout=24 * 3600)
                handle.finish(out.get("status", "FAILED"), out.get("failure_reason", ""))
            except PaymentError as e:
                handle.finish("FAILED", str(e))
        threading.Thread(target=run, daemon=True).start()
        return handle

    def channel_sats(self) -> int:
        return sum(int(c["local_balance"]) for c in self._cli("listchannels").get("channels", []))

    def held_since(self, payment_hash: str) -> int | None:
        """Unix time the payment arrived and started being held, from LND's own record."""
        htlcs = self._cli("lookupinvoice", payment_hash).get("htlcs", [])
        times = [int(h["accept_time"]) for h in htlcs if int(h.get("accept_time", 0))]
        return min(times) if times else None

    # -- ordinary (non-hold) payments, used for fee shares --------------------
    def add_invoice(self, amount_sats: int) -> str:
        return self._cli("addinvoice", f"--amt={amount_sats}")["payment_request"]

    def invoice_sats(self, payment_request: str) -> int:
        return int(self._cli("decodepayreq", payment_request)["num_satoshis"])

    def pay_now(self, payment_request: str) -> str:
        """Pay and wait. Returns the payment hash; raises PaymentError on failure."""
        out = self._cli("payinvoice", "--force", "--json", payment_request, timeout=120)
        if out.get("status") != "SUCCEEDED":
            raise PaymentError(f"payment failed: {out.get('failure_reason', out.get('status'))}")
        return out["payment_hash"]

    def send_onchain(self, address: str, amount_sats: int) -> str:
        if not address.startswith(("bcrt1", "tb1")):
            raise PaymentError("refusing to send to a non-test-network address")
        return self._cli("sendcoins", f"--addr={address}", f"--amt={amount_sats}")["txid"]

    def pay_in_background(self, payment_request: str) -> None:
        """Start a payment that outlives this process (used by the CLI)."""
        self._sb.pay_detached(self.name, payment_request)


class FakeLightning:
    """Offline stand-in for two Lightning nodes sharing a channel (unit tests only)."""

    def __init__(self, balances: dict[str, int]):
        self.balances = dict(balances)
        self.invoices: dict[str, dict] = {}

    def node(self, name: str) -> "FakeNode":
        return FakeNode(self, name)


class FakeNode:
    def __init__(self, net: FakeLightning, name: str):
        self.net, self.name = net, name

    def add_hold_invoice(self, payment_hash, amount_sats, config):
        self.net.invoices[payment_hash] = {"owner": self.name, "amount": amount_sats,
                                           "state": "OPEN", "payer": None, "handle": None}
        return f"lnfake:{payment_hash}"

    def state(self, payment_hash):
        return self.net.invoices[payment_hash]["state"]

    def pay(self, payment_request):
        inv = self.net.invoices[payment_request.split(":")[1]]
        handle = PayHandle()
        if inv["state"] != "OPEN" or self.net.balances[self.name] < inv["amount"]:
            handle.finish("FAILED", "cannot pay")
            return handle
        self.net.balances[self.name] -= inv["amount"]
        inv.update(state="ACCEPTED", payer=self.name, handle=handle)
        return handle

    def settle(self, secret_hex):
        h = hashlib.sha256(bytes.fromhex(secret_hex)).hexdigest()
        inv = self.net.invoices.get(h)
        if inv is None or inv["owner"] != self.name or inv["state"] != "ACCEPTED":
            raise PaymentError("unable to locate an accepted invoice for this secret")
        inv["state"] = "SETTLED"
        self.net.balances[self.name] += inv["amount"]
        inv["handle"].finish("SUCCEEDED")

    def cancel(self, payment_hash):
        inv = self.net.invoices[payment_hash]
        if inv["state"] == "ACCEPTED":
            self.net.balances[inv["payer"]] += inv["amount"]
            inv["handle"].finish("FAILED", "invoice canceled")
        inv["state"] = "CANCELED"

    def channel_sats(self):
        return self.net.balances[self.name]


# -- worker-side steps ---------------------------------------------------------

@dataclass
class HoldInvoice:
    job_id: str
    payment_hash: str
    amount_sats: int
    payment_request: str


def create_hold_invoice(worker_node, config: Config, job_id: str, payment_hash: str,
                        amount_sats: int, expected_seconds: int) -> HoldInvoice:
    check_hold_eligible(config, expected_seconds)
    if amount_sats <= 0:
        raise PaymentError("amount must be positive")
    pr = worker_node.add_hold_invoice(payment_hash, amount_sats, config)
    return HoldInvoice(job_id, payment_hash, amount_sats, pr)


def settle_with_receipt(worker_node, invoice: HoldInvoice, receipt: dict,
                        allowed_signers: set[str]) -> None:
    secret = verify_receipt(receipt, invoice.job_id, invoice.payment_hash, allowed_signers)
    if worker_node.state(invoice.payment_hash) != "ACCEPTED":
        raise PaymentError("payment is not being held (not paid yet, or already settled/cancelled)")
    worker_node.settle(secret)


def enforce_max_hold(worker_node, invoice: HoldInvoice, held_since: int, now: int,
                     config: Config) -> bool:
    """Cancel (refund the client) once a payment has been held too long. True if cancelled."""
    if worker_node.state(invoice.payment_hash) != "ACCEPTED":
        return False
    if now - held_since < config.max_hold_seconds:
        return False
    worker_node.cancel(invoice.payment_hash)
    return True
