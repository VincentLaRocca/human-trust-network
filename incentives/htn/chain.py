"""Job-chain verifier: rebuild and check one job's full history from the public record.

Given a job ID, collect every public event that names it, apply the same rules
the ledger uses, and report each step: who signed, whether it was accepted,
what it references, and whether its timestamp proof checks out.
"""
from __future__ import annotations

from typing import Callable, Iterable

from . import events as ev
from . import schema
from .config import Config
from .ledger import Ledger, order_key


def _job_of(event) -> str | None:
    try:
        schema.validate(event)
        return schema.tag_values(event).get("job")
    except schema.SchemaError:
        return None


def job_chain(events: Iterable[dict], config: Config, job_id: str,
              proof_status: Callable[[dict], str] | None = None) -> dict:
    """`proof_status(event)` returns the timestamp status ("bitcoin", "pending", "missing",
    "invalid", ...). Without it, proofs are not checked."""
    events = list(events)
    led = Ledger.build(events, config)
    by_id = {e["id"]: e for e in events if isinstance(e, dict) and "id" in e}
    mine = sorted({e["id"]: e for e in events if _job_of(e) == job_id}.values(), key=order_key)
    job = led.jobs.get(job_id)
    steps, problems = [], []
    if job is None:
        problems.append("no accepted job offer with this job ID")
    for e in mine:
        t = schema.tag_values(e)
        if e["id"] in led.accepted:
            status = "accepted"
        else:
            status = led.rejected.get(e["id"], "rejected")
            problems.append(f"{ev.KIND_NAMES[e['kind']]} {e['id'][:16]}...: {status}")
        ref = t.get("e")
        if ref and ref not in by_id:
            problems.append(f"{e['id'][:16]}... references a missing event {ref[:16]}...")
        step = {"id": e["id"], "kind": ev.KIND_NAMES[e["kind"]], "signer": e["pubkey"],
                "operator": led.ident(e["pubkey"]), "created_at": e["created_at"],
                "status": status, "references": ref}
        if proof_status:
            step["timestamp"] = proof_status(e)
            if step["timestamp"] in ("missing", "invalid"):
                problems.append(f"{e['id'][:16]}...: timestamp proof {step['timestamp']}")
        steps.append(step)
    summary = None
    if job:
        summary = {
            "client": job.client, "worker": job.worker, "recipient": job.recipient,
            "accepted": bool(job.accepted), "handoffs": job.handoffs,
            "completed": bool(job.completion),
            "disputes": [{"id": d.event_id, "outcome": d.outcome or "undecided"} for d in job.disputes],
            "vouches": [{"id": v.event_id, "status": v.status, "amount": v.amount, "bond": v.bond}
                        for v in job.vouches],
        }
    return {"job": job_id, "ok": not problems, "summary": summary, "steps": steps,
            "problems": problems}
