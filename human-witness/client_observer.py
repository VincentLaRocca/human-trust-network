#!/usr/bin/env python3
"""Observer-local accept step.

A script-path proposal names the revealed script and the stored genesis leaf.
It does not carry a witness lock, and this module cannot mint one. The lock
has to come from the regtest query. weigh() is not called on that path.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "btc-root"))

from operator_cold_leaf import cold_leaf_hash  # noqa: E402
from max_path import Edge, Neighborhood, Policy, weigh


class Reject(Exception):
    pass


class Outcome(Enum):
    GARBAGE = "garbage"
    UNANCHORED = "unanchored"
    SPENT_UNADVANCED = "spent_unadvanced"
    ADVANCED = "advanced"


@dataclass(frozen=True)
class AnchorProof:
    txid: bytes
    vout: int
    spent_txid: bytes
    spent_vout: int
    bundle: bytes
    confirmed: bool

    def __post_init__(self) -> None:
        if len(self.txid) != 32 or len(self.spent_txid) != 32 or len(self.bundle) != 32:
            raise Reject("anchor fields must be 32 bytes")
        if self.vout < 0 or self.spent_vout < 0:
            raise Reject("vout")


@dataclass(frozen=True)
class WitnessLock:
    kind: str
    script: bytes
    control: bytes
    mint: object


@dataclass(frozen=True)
class ScriptPath:
    script: bytes
    genesis_cold_leaf: bytes


@dataclass(frozen=True)
class Proposal:
    spent_seal: bytes
    new_seal: bytes
    metadata: bytes
    op_id: bytes
    sigs: dict[bytes, bytes]
    expected_bundle: bytes
    spent_txid: bytes
    spent_vout: int
    anchor: AnchorProof | None
    script_path: ScriptPath | None = None


@dataclass
class LocalView:
    title_seal: bytes
    spent: set[bytes] = field(default_factory=set)
    accepted: list[bytes] = field(default_factory=list)

    def note_spent(self, seal: bytes) -> None:
        self.spent.add(seal)

    def advance(self, new_seal: bytes, op_id: bytes) -> None:
        self.spent.add(self.title_seal)
        self.title_seal = new_seal
        self.accepted.append(op_id)


def objective(view: LocalView, proposal: Proposal, require) -> None:
    if proposal.spent_seal != view.title_seal:
        raise Reject("spend is not the current seal")
    if proposal.new_seal == proposal.spent_seal:
        raise Reject("reopen must be a new seal")
    if len(proposal.metadata) > 65535:
        raise Reject("metadata too long")
    if len(proposal.op_id) != 32 or len(proposal.expected_bundle) != 32:
        raise Reject("op id")
    require(proposal.op_id, proposal.sigs)


def cold_objective(view: LocalView, proposal: Proposal, lock: WitnessLock | None) -> None:
    from regtest_anchor import accepted

    path = proposal.script_path
    if path is None:
        raise Reject("not a script path")
    if not accepted(lock) or lock.kind != "script" or lock.script != path.script:
        raise Reject("witness lock was not returned by the regtest query")
    if not lock.control or lock.control[0] & 0xFE != 0xC0:
        raise Reject("control block")
    if proposal.spent_seal != view.title_seal:
        raise Reject("spend is not the current seal")
    if proposal.new_seal == proposal.spent_seal:
        raise Reject("reopen must be a new seal")
    if len(proposal.op_id) != 32 or len(proposal.expected_bundle) != 32:
        raise Reject("op id")
    leaf = path.genesis_cold_leaf
    if len(leaf) != 32 or cold_leaf_hash(path.script) != leaf:
        raise Reject("revealed script is not the genesis cold leaf")


def anchor_ok(proposal: Proposal) -> bool:
    proof = proposal.anchor
    if proof is None or not proof.confirmed:
        return False
    if proof.bundle != proposal.expected_bundle:
        return False
    return proof.spent_txid == proposal.spent_txid and proof.spent_vout == proposal.spent_vout


def consider(
    view: LocalView,
    proposal: Proposal,
    require,
    neighborhood: Neighborhood,
    observer: bytes,
    policy: Policy | None = None,
    witness_lock: WitnessLock | None = None,
) -> tuple[Outcome, str]:
    policy = policy or Policy()
    if proposal.script_path is not None:
        try:
            cold_objective(view, proposal, witness_lock)
        except Reject as exc:
            return Outcome.GARBAGE, str(exc)
        if not anchor_ok(proposal):
            return Outcome.UNANCHORED, "anchor does not match the bundle or the spent outpoint"
        view.advance(proposal.new_seal, proposal.op_id)
        return Outcome.ADVANCED, "cold leaf moved the title"
    try:
        objective(view, proposal, require)
    except Reject as exc:
        return Outcome.GARBAGE, str(exc)
    if not anchor_ok(proposal):
        return Outcome.UNANCHORED, "anchor does not match the bundle or the spent outpoint"
    signed = list(proposal.sigs)
    verdict = weigh(neighborhood, observer, signed, policy)
    if not signed or not all(ok for ok, _ in verdict.values()):
        view.note_spent(proposal.spent_seal)
        return Outcome.SPENT_UNADVANCED, "title held; L1 output marked spent"
    view.advance(proposal.new_seal, proposal.op_id)
    return Outcome.ADVANCED, "title moved"


def demo() -> None:
    observer, notary = (bytes([i]) for i in range(2))
    title = bytes([7]) * 32
    nxt = bytes([8]) * 32
    op = bytes([9]) * 32
    bundle = bytes([4]) * 32
    prev = bytes([3]) * 32
    neigh = Neighborhood([Edge(observer, notary, 0.8)])

    def require(op_id: bytes, sigs: dict[bytes, bytes]) -> None:
        if op_id != op or set(sigs) != {notary}:
            raise Reject("bad witness")

    proof = AnchorProof(bytes([1]) * 32, 0, prev, 1, bundle, True)
    good = Proposal(title, nxt, b"ok", op, {notary: b"\x11" * 64}, bundle, prev, 1, proof)
    view = LocalView(title)
    outcome, _ = consider(view, good, require, neigh, observer)
    assert outcome is Outcome.ADVANCED and view.title_seal == nxt, outcome

    script = b"\x20" + bytes([5]) * 32 + b"\xac"
    leaf = cold_leaf_hash(script)
    claimed = Proposal(title, nxt, b"cold", op, {}, bundle, prev, 1, proof, ScriptPath(script, leaf))
    outcome, _ = consider(LocalView(title), claimed, require, Neighborhood([]), observer)
    assert outcome is Outcome.GARBAGE
    forged = WitnessLock("script", script, bytes([0xC0]) + bytes([9]) * 32, object())
    outcome, _ = consider(LocalView(title), claimed, require, Neighborhood([]), observer, witness_lock=forged)
    assert outcome is Outcome.GARBAGE
    assert not hasattr(__import__("client_observer"), "mint_lock")
    print("client observer ok")


if __name__ == "__main__":
    demo()
