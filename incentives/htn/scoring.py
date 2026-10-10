"""Public, deterministic operator scoring. The formula is documented in SCORING.md.

Scores belong to operators (all their keys over time), not to single keys.
A key that never onboarded is its own operator.

Inputs: the public events, the config, an as-of time and (optionally) a view of
the chain for checking vouch bonds. Same inputs, same scores.
"""
from __future__ import annotations

from typing import Iterable

from .config import Config
from .ledger import Ledger

FORMULA_VERSION = "v1"
NO_CHAIN = "bonds not checked (no chain access): vouches carry no weight"


def dispute_pending(ledger: Ledger, job, as_of: int | None) -> bool:
    """An undecided dispute is pending until the window closes, then it lapses.

    Without an `as_of` time we can't know the window has closed, so undecided
    disputes are treated as pending (credit withheld, nothing lost).
    """
    if not job.unresolved:
        return False
    return as_of is None or as_of <= job.created_at + ledger.window


def bond_checks(ledger: Ledger, chain=None) -> dict[str, dict]:
    """Bond status for every cleared vouch (the only ones that can earn weight)."""
    from .bond import check_bond
    out = {}
    for vid, v in sorted(ledger.vouches.items()):
        if v.status != "cleared":
            continue
        out[vid] = (check_bond(ledger, vid, chain) if chain is not None
                    else {"vouch": vid, "live": False, "counts": False, "problems": [NO_CHAIN]})
    return out


def operator_record(ledger: Ledger, identity: str, as_of: int | None = None,
                    bonds: dict[str, dict] | None = None) -> dict:
    c = ledger.config
    bonds = bonds or {}
    jobs = [j for j in ledger.jobs.values() if ledger.ident(j.worker) == identity]
    vouches = [v for v in ledger.vouches.values() if ledger.ident(v.voucher) == identity]
    cleared = [v for v in vouches if v.status == "cleared"]
    rec = {
        "keys": ledger.registry.keys_of(identity),
        "completed_jobs": sum(1 for j in jobs if j.completion and not j.upheld
                              and not dispute_pending(ledger, j, as_of)),
        "upheld_disputes": sum(1 for j in jobs if j.upheld),
        "forfeited_vouches": sum(1 for v in vouches if v.status == "forfeited"),
        "clean_vouches": sum(1 for v in cleared if bonds.get(v.event_id, {}).get("counts")),
        "clean_vouches_not_counted": sum(1 for v in cleared
                                         if not bonds.get(v.event_id, {}).get("counts")),
        "active_vouches": sum(1 for v in vouches if v.status == "active"),
    }
    rec["lost_disputes"] = rec["upheld_disputes"] + rec["forfeited_vouches"]
    rec["score"] = (c.score_clean_completion * rec["completed_jobs"]
                    + c.score_clean_vouch * rec["clean_vouches"]
                    + c.score_lost_dispute * rec["lost_disputes"])
    return rec


def score_all(events: Iterable, config: Config, as_of: int | None = None, chain=None) -> dict:
    ledger = Ledger.build(events, config)
    bonds = bond_checks(ledger, chain)
    operators = ({ledger.ident(j.worker) for j in ledger.jobs.values()}
                 | {ledger.ident(v.voucher) for v in ledger.vouches.values()}
                 | set(ledger.registry.operators))
    return {
        "formula": FORMULA_VERSION,
        "weights": {"clean_completion": config.score_clean_completion,
                    "clean_vouch": config.score_clean_vouch,
                    "lost_dispute": config.score_lost_dispute},
        "as_of": as_of,
        "chain_tip": chain.tip() if chain is not None else None,
        "event_set_hash": ledger.event_set_hash(),
        "accepted_events": len(ledger.accepted),
        "rejected_events": len(ledger.rejected) + ledger.malformed,
        "disputable_events": len(ledger.disputable()),
        "bond_checks": bonds,
        "operators": {op: operator_record(ledger, op, as_of, bonds) for op in sorted(operators)},
    }
