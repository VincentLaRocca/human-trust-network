"""Paying out the network and voucher fee shares (DECISIONS #35). Test networks only.

A hold invoice pays the worker the full job amount. The worker then owes:

  network share  due at once. Paid either as its own Lightning payment
                 (payout = "lightning") or accumulated and swept on-chain to
                 `fees.sweep_address` (payout = "sweep").
  voucher share  WITHHELD until the job's dispute window closes; then paid to
                 each voucher (split evenly) as a Lightning payment. If the
                 vouch was forfeited, that share goes to the client instead.
                 If nobody vouched, `fees.unvouched_share` decides: the worker
                 keeps it, or it is added to the network share.

The list of shares is private bookkeeping (data/private/fees.json); nothing
here is published.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

from .config import Config
from .payments import fee_split


class FeeError(Exception):
    pass


@dataclass
class Share:
    id: str
    job_id: str
    kind: str              # "network" | "voucher"
    sats: int
    vouch: str | None      # vouch event id, for voucher shares
    due_after: int         # unix time; 0 = due at once
    status: str = "owed"   # owed | paid | swept
    paid_ref: str = ""     # payment hash or sweep txid

    def to_dict(self) -> dict:
        return asdict(self)


def _share_id(job_id: str, kind: str, vouch: str | None) -> str:
    return hashlib.sha256(f"{job_id}:{kind}:{vouch or ''}".encode()).hexdigest()[:16]


def accrue(ledger, job_id: str, amount_sats: int, config: Config) -> list[Share]:
    """Shares owed on a settled payment of `amount_sats` for `job_id`."""
    job = ledger.jobs.get(job_id)
    if job is None:
        raise FeeError("unknown job")
    split = fee_split(amount_sats, config)
    network, voucher_total = split["network"], split["voucher_held"]
    vouches = sorted((v for v in job.vouches if v.status != "forfeited"), key=lambda v: v.event_id)
    shares = []
    if not vouches and config.fee_unvouched_share == "network":
        network += voucher_total
    if network:
        shares.append(Share(_share_id(job_id, "network", None), job_id, "network", network, None, 0))
    if vouches and voucher_total:
        each, rest = divmod(voucher_total, len(vouches))
        window_end = job.created_at + ledger.window
        for i, v in enumerate(vouches):
            sats = each + (rest if i == 0 else 0)
            if sats:
                shares.append(Share(_share_id(job_id, "voucher", v.event_id), job_id, "voucher",
                                    sats, v.event_id, window_end))
    return shares


def status(share: Share, ledger, now: int) -> dict:
    """Where a share stands right now: who should receive it and whether it is due."""
    if share.status != "owed":
        return {"due": False, "payee": None, "why": share.status}
    if share.kind == "network":
        return {"due": True, "payee": "network", "why": "due"}
    v = ledger.vouches.get(share.vouch)
    if now <= share.due_after:
        return {"due": False, "payee": None, "why": "withheld until the dispute window closes"}
    if v is not None and v.status == "forfeited":
        return {"due": True, "payee": "client", "why": "vouch forfeited: share goes to the client"}
    return {"due": True, "payee": "voucher", "why": "due"}


def check_payable(share: Share, ledger, config: Config, now: int, invoice_sats: int) -> str:
    """Raise unless this share may be paid now by a Lightning invoice of `invoice_sats`.
    Returns the payee ("network", "voucher" or "client")."""
    st = status(share, ledger, now)
    if not st["due"]:
        raise FeeError(f"share {share.id} is not payable: {st['why']}")
    if share.kind == "network" and config.fee_payout == "sweep":
        raise FeeError("network shares are swept on-chain in this config (fees-sweep)")
    if invoice_sats != share.sats:
        raise FeeError(f"invoice is for {invoice_sats} sats; this share is {share.sats}")
    return st["payee"]


def sweepable(shares: list[Share], ledger, config: Config, now: int) -> list[Share]:
    if config.fee_payout != "sweep":
        raise FeeError('fees.payout is "lightning": pay network shares one by one with fees-pay')
    if not config.fee_sweep_address:
        raise FeeError("set fees.sweep_address in config.toml first")
    return [s for s in shares if s.kind == "network" and status(s, ledger, now)["due"]]


def merge(existing: list[Share], new: list[Share]) -> list[Share]:
    """Add new shares, never duplicating one (settling twice can't double what's owed)."""
    have = {s.id for s in existing}
    return existing + [s for s in new if s.id not in have]
