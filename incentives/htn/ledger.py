"""The rules engine: turns a pile of public events into an agreed record.

Given the same set of events (in any order, with duplicates), everyone gets the
same result. Events are processed in (created_at, id) order. Each event is
either accepted or rejected with a plain-English reason; rejected events have
no effect on anything.

Identity events (onboard/rotate/recover) are resolved first (see identity.py).
After that, every rule that asks "is this the same party?" compares operators,
not raw keys, so rotating a key never resets anyone's record or limits.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Iterable

from . import events as ev
from . import schema
from .config import Config
from .identity import Registry


@dataclass
class Dispute:
    event_id: str
    job_id: str
    filer: str
    created_at: int
    outcome: str | None = None  # None = unresolved


@dataclass
class Vouch:
    event_id: str
    job_id: str
    voucher: str
    amount: int
    created_at: int
    status: str = "active"  # active | cleared | forfeited
    bond: str | None = None     # funding txid of the Taproot bond (Phase 3)
    arbiter: str | None = None  # arbiter key written into the bond (recusal applied)
    bond_key: str | None = None # the bond's dedicated key (never an operational key)


@dataclass
class Job:
    event_id: str
    job_id: str
    client: str
    worker: str
    recipient: str | None
    created_at: int
    holder: str = ""
    accepted: str | None = None  # job_accepted event id
    handoffs: int = 0
    completion: str | None = None
    disputes: list[Dispute] = field(default_factory=list)
    vouches: list[Vouch] = field(default_factory=list)

    @property
    def upheld(self) -> bool:
        return any(d.outcome == "upheld" for d in self.disputes)

    @property
    def unresolved(self) -> bool:
        return any(d.outcome is None for d in self.disputes)


class Rejected(Exception):
    pass


# Within the same second, records are applied in their natural sequence, so an
# offer and its acceptance signed in the same second never land out of order.
KIND_ORDER = {kind: i for i, kind in enumerate([
    ev.ONBOARD, ev.ROTATE, ev.RECOVER, ev.DELEGATE, ev.AGENT_REVOKE,
    ev.JOB_OFFER, ev.JOB_ACCEPTED, ev.HANDOFF, ev.VOUCH_ISSUED, ev.COMPLETION,
    ev.DISPUTE_FILED, ev.DISPUTE_RESOLVED, ev.VOUCH_CLEARED])}


def order_key(event: dict) -> tuple:
    """Deterministic processing order: time, then natural sequence, then id."""
    seq = 0
    if event["kind"] == ev.HANDOFF:  # handoffs 1, 2, 3 in the same second
        seq = int(schema.tag_values(event)["seq"])
    return (event["created_at"], KIND_ORDER[event["kind"]], seq, event["id"])


def _canonical(event: dict) -> str:
    return json.dumps(event, sort_keys=True, separators=(",", ":"))


class Ledger:
    def __init__(self, config: Config):
        self.config = config
        self.registry = Registry()
        self.jobs: dict[str, Job] = {}
        self.disputes: dict[str, Dispute] = {}
        self.vouches: dict[str, Vouch] = {}
        self.accepted: list[str] = []
        self.rejected: dict[str, str] = {}
        self.malformed = 0
        self.known_keys: set[str] = set()  # every key that signs or is named in a record

    @classmethod
    def build(cls, events: Iterable, config: Config) -> "Ledger":
        led = cls(config)
        valid: dict[str, dict] = {}
        for event in events:
            try:
                schema.validate(event)
            except schema.SchemaError as e:
                if isinstance(event, dict) and isinstance(event.get("id"), str):
                    led.rejected.setdefault(event["id"], f"schema: {e}")
                else:
                    led.malformed += 1
                continue
            if not ev.verify_signature(event):
                led.rejected.setdefault(event["id"], "bad id or signature")
                continue
            # Same id = same signed content; pick one copy deterministically.
            prior = valid.get(event["id"])
            if prior is None or _canonical(event) < _canonical(prior):
                valid[event["id"]] = event
        for event_id in valid:
            led.rejected.pop(event_id, None)
        ordered = sorted(valid.values(), key=order_key)
        for e in ordered:
            led.known_keys.add(e["pubkey"])
            led.known_keys.update(t[1] for t in e["tags"] if t[0] == "p")

        led.registry = Registry.build([e for e in ordered if e["kind"] in ev.IDENTITY_KINDS])
        led.accepted.extend(led.registry.accepted)
        led.rejected.update(led.registry.rejected)
        for event in ordered:
            if event["kind"] not in ev.IDENTITY_KINDS:
                led._apply(event)
        return led

    # -- helpers -----------------------------------------------------------
    @property
    def window(self) -> int:
        return self.config.dispute_window_seconds

    def ident(self, pubkey: str | None) -> str | None:
        return self.registry.identity(pubkey) if pubkey else None

    def counterparties(self, job: Job) -> set[str]:
        return {self.ident(k) for k in (job.client, job.recipient) if k}

    def parties(self, job: Job) -> set[str]:
        return (self.counterparties(job) | {self.ident(job.worker)}
                | {self.ident(v.voucher) for v in job.vouches})

    def acting_arbiter(self, job: Job, extra_voucher: str | None = None) -> str | None:
        """Founder, unless the founder is a party; then the backup (mandatory recusal).

        `extra_voucher` asks: who would arbitrate if this key also vouched?
        """
        founder, backup = self.config.founder_arbiter, self.config.backup_arbiter
        parties = self.parties(job) | ({self.ident(extra_voucher)} if extra_voucher else set())
        if founder and self.ident(founder) not in parties:
            return founder
        if founder and backup and self.ident(backup) not in parties:
            return backup
        return None

    def active_vouches(self, identity: str) -> int:
        return sum(1 for v in self.vouches.values()
                   if self.ident(v.voucher) == identity and v.status == "active")

    def disputable(self) -> dict[str, str]:
        return {k: v for k, v in self.rejected.items() if v.startswith("disputable")}

    def event_set_hash(self) -> str:
        """Fingerprint of the accepted events, so two people can confirm they scored the same set."""
        return hashlib.sha256("\n".join(sorted(self.accepted)).encode()).hexdigest()

    def _job_for(self, t: dict) -> Job:
        job = self.jobs.get(t["job"])
        if job is None:
            raise Rejected("unknown job")
        return job

    def _accepted_job_for(self, t: dict) -> Job:
        job = self._job_for(t)
        if job.accepted is None:
            raise Rejected("the worker has not accepted this job")
        return job

    # -- rules -------------------------------------------------------------
    def _apply(self, event: dict) -> None:
        try:
            reason = self.registry.exclusion(event)
            if reason:
                raise Rejected(reason)
            handler = getattr(self, "_on_" + ev.KIND_NAMES[event["kind"]])
            handler(event, schema.tag_values(event), event["pubkey"], event["created_at"])
        except Rejected as e:
            self.rejected[event["id"]] = str(e)
        else:
            self.accepted.append(event["id"])

    def _on_job_offer(self, event, t, signer, at):
        if t["job"] in self.jobs:
            raise Rejected("job id already used")
        worker, recipient = t["p:worker"], t.get("p:recipient")
        if self.ident(worker) == self.ident(signer):
            raise Rejected("client and worker must be different parties")
        if recipient and self.ident(recipient) in (self.ident(signer), self.ident(worker)):
            raise Rejected("recipient must differ from client and worker")
        self.jobs[t["job"]] = Job(event["id"], t["job"], signer, worker, recipient, at, holder=worker)

    def _on_job_accepted(self, event, t, signer, at):
        job = self._job_for(t)
        if t["e"] != job.event_id:
            raise Rejected("acceptance must reference the job offer")
        if self.ident(signer) != self.ident(job.worker):
            raise Rejected("only the named worker can accept the job")
        if job.accepted:
            raise Rejected("job already accepted")
        if at < job.created_at:
            raise Rejected("acceptance predates the offer")
        job.accepted = event["id"]

    def _on_handoff(self, event, t, signer, at):
        job = self._accepted_job_for(t)
        if t["e"] != job.event_id:
            raise Rejected("handoff must reference the job's creation event")
        if self.ident(signer) != self.ident(job.holder):
            raise Rejected("only the current holder can hand off")
        if self.ident(t["p:to"]) == self.ident(signer):
            raise Rejected("cannot hand off to yourself")
        if int(t["seq"]) != job.handoffs + 1:
            raise Rejected("handoff sequence number out of order")
        if at < job.created_at:
            raise Rejected("handoff predates the job")
        job.handoffs += 1
        job.holder = t["p:to"]

    def _on_completion(self, event, t, signer, at):
        job = self._accepted_job_for(t)
        if t["e"] != job.event_id or t["p:worker"] != job.worker:
            raise Rejected("completion does not match the job")
        if self.ident(signer) not in self.counterparties(job):
            raise Rejected("completion must be signed by the client or recipient, not the worker")
        if job.completion:
            raise Rejected("job already completed")
        if at < job.created_at:
            raise Rejected("completion predates the job")
        job.completion = event["id"]

    def _on_dispute_filed(self, event, t, signer, at):
        job = self._accepted_job_for(t)
        if t["e"] != job.event_id or t["p:worker"] != job.worker:
            raise Rejected("dispute does not match the job")
        if self.ident(signer) not in self.counterparties(job):
            raise Rejected("dispute must be filed by the client or recipient")
        if not job.created_at <= at <= job.created_at + self.window:
            raise Rejected("dispute filed outside the dispute window")
        d = Dispute(event["id"], job.job_id, signer, at)
        job.disputes.append(d)
        self.disputes[d.event_id] = d

    def _on_dispute_resolved(self, event, t, signer, at):
        d = self.disputes.get(t["e"])
        if d is None or d.job_id != t["job"]:
            raise Rejected("unknown dispute")
        job = self.jobs[d.job_id]
        if d.outcome is not None:
            raise Rejected("dispute already resolved")
        if not d.created_at <= at <= job.created_at + self.window:
            raise Rejected("resolution outside the dispute window")
        is_withdrawal = self.ident(signer) == self.ident(d.filer) and t["outcome"] == "withdrawn"
        if not is_withdrawal:
            arbiter = self.acting_arbiter(job)
            if arbiter is None:
                raise Rejected("no eligible arbiter configured for this dispute")
            if signer != arbiter:
                raise Rejected("resolution not signed by the acting arbiter")
        d.outcome = t["outcome"]
        if d.outcome == "upheld":
            for v in job.vouches:
                if v.status == "active":
                    v.status = "forfeited"

    def _on_vouch_issued(self, event, t, signer, at):
        job = self._accepted_job_for(t)
        if t["e"] != job.event_id or t["p:worker"] != job.worker:
            raise Rejected("vouch does not match the job")
        me = self.ident(signer)
        if me in (self.ident(job.client), self.ident(job.worker), self.ident(job.recipient)):
            raise Rejected("client, worker and recipient cannot vouch on their own job")
        if any(self.ident(v.voucher) == me for v in job.vouches):
            raise Rejected("already vouched on this job")
        amount = int(t["amount"])
        if not self.config.bond_min_sats <= amount <= self.config.bond_max_sats:
            raise Rejected("bond amount outside allowed range")
        if not job.created_at <= at < job.created_at + self.window:
            raise Rejected("vouch must be issued inside the dispute window")
        if job.upheld:
            raise Rejected("job already has an upheld dispute")
        if self.active_vouches(me) >= self.config.max_active_vouches:
            raise Rejected("voucher has reached the maximum number of active vouches")
        arbiter = None
        if self.config.founder_arbiter:
            arbiter = self.acting_arbiter(job, extra_voucher=signer)
            if arbiter is None:
                raise Rejected("no eligible arbiter: founder and backup would both be parties")
            if job.vouches and arbiter != self.acting_arbiter(job):
                # Earlier bonds already name the arbiter in their script.
                raise Rejected("this vouch would change the arbiter of existing bonds on the job")
        bond, bond_key = t.get("bond"), t.get("bondkey")
        if bool(bond) != bool(bond_key):
            raise Rejected("a bond and its bond key must be named together")
        if bond:
            if arbiter is None:
                raise Rejected("a bonded vouch needs a configured arbiter")
            if any(x.bond == bond for x in self.vouches.values()):
                raise Rejected("this bond already backs another vouch")
            if any(x.bond_key == bond_key for x in self.vouches.values()):
                raise Rejected("bond key already used for another bond")
            if bond_key in self.known_keys or bond_key in (
                    self.config.founder_arbiter, self.config.backup_arbiter):
                raise Rejected("bond key must be a fresh key, not an operational or agent key")
        v = Vouch(event["id"], job.job_id, signer, amount, at, bond=bond, arbiter=arbiter,
                  bond_key=bond_key)
        job.vouches.append(v)
        self.vouches[v.event_id] = v

    def _on_vouch_cleared(self, event, t, signer, at):
        v = self.vouches.get(t["e"])
        if v is None or v.job_id != t["job"]:
            raise Rejected("unknown vouch")
        if self.ident(signer) != self.ident(v.voucher):
            raise Rejected("only the voucher can clear their vouch")
        if v.status != "active":
            raise Rejected(f"vouch is {v.status}")
        job = self.jobs[v.job_id]
        if at <= job.created_at + self.window:
            raise Rejected("dispute window has not closed")
        # Any dispute still undecided now has lapsed: decisions must fall inside
        # the window (Nucleus section 2/8: arbiter silent -> voucher reclaims).
        v.status = "cleared"
