#!/usr/bin/env python3
"""Observer-local accept step.

The consignment is shared. Epistemic weight is not. Gates run in order:

1. Objective. Spent seal is current, new seal is distinct, BIP-340 threshold holds.
   Failure here means the handoff is garbage. Nothing is recorded.
2. Anchor. A supplied proof says the confirmed transaction spent the committed
   outpoint and committed the bundle. This module does not talk to a node.
3. Local score. max_path.weigh on the observer's neighborhood.

If 1 and 2 pass and 3 fails, the L1 output is marked spent and the title pointer
stays on the previous seal. Bitcoin does not unspend the output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

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
    """What a client already checked, or was handed by its Bitcoin backend."""

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
    """Shared checks. require(op_id, sigs) is WitnessSet.require. No mutation."""
    if proposal.spent_seal != view.title_seal:
        raise Reject("spend is not the current seal")
    if proposal.new_seal == proposal.spent_seal:
        raise Reject("reopen must be a new seal")
    if len(proposal.metadata) > 65535:
        raise Reject("metadata too long")
    if len(proposal.op_id) != 32 or len(proposal.expected_bundle) != 32:
        raise Reject("op id")
    require(proposal.op_id, proposal.sigs)


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
) -> tuple[Outcome, str]:
    policy = policy or Policy()
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

    view2 = LocalView(title)
    weak = Proposal(title, nxt, b"cut", op, {notary: b"\x11" * 64}, bundle, prev, 1, proof)
    outcome, why = consider(view2, weak, require, Neighborhood([Edge(observer, notary, 0.4)]), observer)
    assert outcome is Outcome.SPENT_UNADVANCED, outcome
    assert view2.title_seal == title and title in view2.spent, why

    garbage = Proposal(bytes([1]) * 32, nxt, b"", op, {notary: b"\x11" * 64}, bundle, prev, 1, proof)
    outcome, _ = consider(LocalView(title), garbage, require, neigh, observer)
    assert outcome is Outcome.GARBAGE

    unanchored = Proposal(title, nxt, b"", op, {notary: b"\x11" * 64}, bundle, prev, 1, None)
    outcome, _ = consider(LocalView(title), unanchored, require, neigh, observer)
    assert outcome is Outcome.UNANCHORED
    print("client observer ok")


if __name__ == "__main__":
    demo()
