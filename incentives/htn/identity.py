"""Operator identities: onboarding, key rotation, recovery-key override.

An operator is identified by the id of their onboarding event. Over time they
may hold several operational keys; all of them map to the same identity.

- Onboarding (signed by the first operational key) publishes a commitment to a
  recovery key: SHA-256 of its 32-byte public key. The recovery key stays offline.
- Rotation (signed by the current operational key) names the next key. The old
  key is retired: anything it signs afterwards is rejected.
- Recovery (signed by the recovery key) names a new operational key and a
  `since` time. Every operational key the operator held at or after `since` is
  marked compromised from `since`. Events those keys signed from then on are
  disputable and excluded. That includes a thief's rotations, so a rotation is
  never final against the recovery key.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import events as ev
from . import schema


@dataclass
class Operator:
    op_id: str
    recovery_commitment: str
    created_at: int
    current: str | None  # None after a revoke-only recovery
    history: list[list] = field(default_factory=list)  # [key, start, end or None]
    last_recovery_at: int | None = None


@dataclass
class Agent:
    """An agent key acting for an operator within a limited scope (Nucleus section 5)."""
    key: str
    op_id: str
    scope: frozenset[int]          # event kinds the agent may sign
    start: int
    expires: int | None
    delegated_by: str              # signing key of the delegation
    revoked_at: int | None = None
    revoked_by: str | None = None
    overridden: bool = False       # delegation was signed by a compromised key


class Rejected(Exception):
    pass


class Registry:
    def __init__(self):
        self.operators: dict[str, Operator] = {}
        self.owner: dict[str, str] = {}        # operational key -> operator id
        self.compromised: dict[str, int] = {}  # key -> compromised since (unix time)
        self.retired: dict[str, int] = {}      # key -> retired by ordinary rotation at
        self.agents: dict[str, Agent] = {}     # agent key -> delegation
        self.accepted: list[str] = []
        self.rejected: dict[str, str] = {}
        self._signers: dict[str, tuple[str, int, int]] = {}  # event id -> (signer, time, kind)

    @classmethod
    def build(cls, ordered_events: list[dict]) -> "Registry":
        """ordered_events: schema- and signature-checked identity events, sorted."""
        reg = cls()
        for event in ordered_events:
            handler = getattr(reg, "_on_" + ev.KIND_NAMES[event["kind"]])
            try:
                handler(event, schema.tag_values(event), event["pubkey"], event["created_at"])
            except Rejected as e:
                reg.rejected[event["id"]] = str(e)
            else:
                reg.accepted.append(event["id"])
                reg._signers[event["id"]] = (event["pubkey"], event["created_at"], event["kind"])
        # A recovery can reach back in time: rotations signed by a key after it
        # became compromised are overridden.
        for eid in list(reg.accepted):
            signer, at, kind = reg._signers[eid]
            if kind in (ev.ROTATE, ev.DELEGATE, ev.AGENT_REVOKE) and reg.is_compromised(signer, at):
                reg.accepted.remove(eid)
                reg.rejected[eid] = (f"disputable: {ev.KIND_NAMES[kind]} signed by a compromised key; "
                                     "overridden by recovery")
        for agent in reg.agents.values():
            if reg.is_compromised(agent.delegated_by, agent.start):
                agent.overridden = True
            if agent.revoked_by and reg.is_compromised(agent.revoked_by, agent.revoked_at):
                agent.revoked_at = agent.revoked_by = None  # a thief's revocation doesn't stand
        return reg

    # -- queries -------------------------------------------------------------
    def identity(self, pubkey: str) -> str:
        """Operator id for an operator's key; a key with no operator is its own identity."""
        return self.owner.get(pubkey, pubkey)

    def keys_of(self, identity: str) -> list[str]:
        op = self.operators.get(identity)
        return [k for k, _, _ in op.history] if op else [identity]

    def is_compromised(self, key: str, at: int) -> bool:
        since = self.compromised.get(key)
        return since is not None and at >= since

    def exclusion(self, event: dict) -> str | None:
        """Why a (non-identity) event must not count, or None."""
        signer, at = event["pubkey"], event["created_at"]
        if self.is_compromised(signer, at):
            return "disputable: signed by a key after it was marked compromised"
        if signer in self.retired and at > self.retired[signer]:
            return "signed by a retired key; use the operator's current key"
        agent = self.agents.get(signer)
        if agent:
            if agent.overridden:
                return "disputable: agent was delegated by a compromised key"
            if event["kind"] not in agent.scope:
                return f"agent is not authorised to sign {ev.KIND_NAMES[event['kind']]}"
            if at < agent.start:
                return "signed before the agent was delegated"
            if agent.expires is not None and at >= agent.expires:
                return "agent delegation has expired"
            if agent.revoked_at is not None and at >= agent.revoked_at:
                return "agent key has been revoked"
        if event["kind"] == ev.JOB_OFFER:
            worker = schema.tag_values(event)["p:worker"]
            if self.is_compromised(worker, at):
                return "disputable: names a worker key after it was marked compromised"
        return None

    # -- rules -------------------------------------------------------------
    def _operator(self, t) -> Operator:
        op = self.operators.get(t["op"])
        if op is None:
            raise Rejected("unknown operator")
        return op

    def _check_new_key(self, op: Operator, new: str, signer: str) -> None:
        if new in self.owner:
            raise Rejected("new key already belongs to an operator or agent")
        if new == signer:
            raise Rejected("new key must differ from the signing key")
        if ev.recovery_commitment(new) == op.recovery_commitment:
            raise Rejected("the recovery key must stay offline; it cannot be an operational key")

    def _on_onboard(self, event, t, signer, at):
        if signer in self.owner:
            raise Rejected("key already belongs to an operator")
        if t["recovery"] == ev.recovery_commitment(signer):
            raise Rejected("recovery key must differ from the operational key")
        op = Operator(event["id"], t["recovery"], at, signer, [[signer, at, None]])
        self.operators[op.op_id] = op
        self.owner[signer] = op.op_id

    def _on_rotate(self, event, t, signer, at):
        op = self._operator(t)
        if signer != op.current:
            raise Rejected("only the operator's current key can rotate")
        if self.is_compromised(signer, at):
            raise Rejected("disputable: rotation signed by a compromised key")
        if at < op.history[-1][1]:
            raise Rejected("rotation predates the current key")
        new = t["p:new"]
        self._check_new_key(op, new, signer)
        op.history[-1][2] = at
        op.history.append([new, at, None])
        op.current = new
        self.owner[new] = op.op_id
        self.retired[signer] = at

    def _on_recover(self, event, t, signer, at):
        op = self._operator(t)
        if ev.recovery_commitment(signer) != op.recovery_commitment:
            raise Rejected("not signed by this operator's committed recovery key")
        since = int(t["since"])
        floor = op.last_recovery_at if op.last_recovery_at is not None else op.created_at
        if not floor < since <= at:
            raise Rejected("'since' must be after onboarding (or the last recovery) and not in the future")
        new = t.get("p:new")  # absent = revoke only; operator has no working key until next recovery
        if new:
            self._check_new_key(op, new, signer)
        for key, _start, end in op.history:
            if end is None or end > since:
                self.compromised[key] = min(self.compromised.get(key, since), since)
        if op.history and op.history[-1][2] is None:
            op.history[-1][2] = at
        if new:
            op.history.append([new, at, None])
            self.owner[new] = op.op_id
        op.current = new
        op.last_recovery_at = at

    def _on_delegate(self, event, t, signer, at):
        op = self._operator(t)
        if signer != op.current:
            raise Rejected("only the operator's current key can delegate to an agent")
        if self.is_compromised(signer, at):
            raise Rejected("disputable: delegation signed by a compromised key")
        agent = t["p:agent"]
        self._check_new_key(op, agent, signer)
        names = t["scope"].split(",")
        by_name = {name: kind for kind, name in ev.KIND_NAMES.items() if kind in ev.AGENT_KINDS}
        if any(n not in by_name for n in names) or len(set(names)) != len(names):
            raise Rejected("scope must list allowed record kinds, each once")
        expires = int(t["expires"]) if "expires" in t else None
        if expires is not None and expires <= at:
            raise Rejected("delegation expires before it starts")
        self.agents[agent] = Agent(agent, op.op_id, frozenset(by_name[n] for n in names),
                                   at, expires, signer)
        self.owner[agent] = op.op_id

    def _on_agent_revoke(self, event, t, signer, at):
        op = self._operator(t)
        agent = self.agents.get(t["p:agent"])
        if agent is None or agent.op_id != op.op_id:
            raise Rejected("not an agent of this operator")
        by_recovery = ev.recovery_commitment(signer) == op.recovery_commitment
        if not by_recovery and signer != op.current:
            raise Rejected("only the operator's current key or recovery key can revoke an agent")
        if agent.revoked_at is not None:
            raise Rejected("agent already revoked")
        agent.revoked_at = at
        agent.revoked_by = None if by_recovery else signer
