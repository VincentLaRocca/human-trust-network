#!/usr/bin/env python3
"""Sponsor pairing against the gates that exist.

A bond does not bind a key to a person. Collusion and a bought introduction
are the cases that tell whether the edge is earning its keep.
"""

from __future__ import annotations

from client_observer import AnchorProof, LocalView, Outcome, Proposal, Reject, consider
from max_path import Edge, Neighborhood, Reject as PathReject
from sponsor import SponsorBond, cut_misses, merge


TITLE = bytes([7]) * 32
NXT = bytes([8]) * 32
OP = bytes([9]) * 32
BUNDLE = bytes([4]) * 32
PREV = bytes([3]) * 32
PROOF = AnchorProof(bytes([1]) * 32, 0, PREV, 1, BUNDLE, True)


def proposal(sigs):
    return Proposal(TITLE, NXT, b"sponsor", OP, sigs, BUNDLE, PREV, 1, PROOF)


def require_keys(expected: set[bytes]):
    def require(op_id: bytes, sigs: dict[bytes, bytes]) -> None:
        if op_id != OP or set(sigs) != expected or any(len(sig) != 64 for sig in sigs.values()):
            raise Reject("bad witness")
    return require


def self_sponsor_rejected() -> None:
    key = bytes([1])
    try:
        SponsorBond(key, key, 0.8)
    except PathReject:
        return
    raise SystemExit("self-sponsor accepted")


def trusted_sponsor_can_introduce() -> None:
    observer, sponsor, node = (bytes([i]) for i in range(3))
    bond = SponsorBond(sponsor, node, 0.9)
    neigh = merge(Neighborhood([Edge(observer, sponsor, 0.8)]), [bond])
    sigs = {node: b"\x11" * 64}
    view = LocalView(TITLE)
    outcome, _ = consider(view, proposal(sigs), require_keys(set(sigs)), neigh, observer, bonds=[bond])
    # 0.8 * 0.9 * gamma(0.65) = 0.468, over 0.45. The bond is an edge, not a boost.
    assert outcome is Outcome.ADVANCED and view.title_seal == NXT, outcome
    assert any(item.src == sponsor and item.dst == node for item in neigh.edges)


def miss_cuts_signer_and_sponsor() -> None:
    observer, sponsor, node = (bytes([i]) for i in range(3))
    bond = SponsorBond(sponsor, node, 0.5)
    neigh = merge(
        Neighborhood([Edge(observer, sponsor, 0.8), Edge(observer, node, 0.4)]),
        [bond],
    )
    sigs = {node: b"\x11" * 64}
    view = LocalView(TITLE)
    outcome, _ = consider(view, proposal(sigs), require_keys(set(sigs)), neigh, observer, bonds=[bond])
    assert outcome is Outcome.SPENT_UNADVANCED and view.title_seal == TITLE
    assert TITLE in view.spent
    dsts = {item.dst for item in neigh.edges if item.src == observer}
    assert node not in dsts and sponsor not in dsts
    assert not any(item.src == sponsor and item.dst == node for item in neigh.edges)


def bought_introduction_does_not_pass() -> None:
    observer, sponsor, node = (bytes([i]) for i in range(3))
    bond = SponsorBond(sponsor, node, 0.95)
    neigh = merge(Neighborhood([]), [bond])
    sigs = {node: b"\x11" * 64}
    view = LocalView(TITLE)
    outcome, _ = consider(view, proposal(sigs), require_keys(set(sigs)), neigh, observer, bonds=[bond])
    assert outcome is Outcome.SPENT_UNADVANCED and view.title_seal == TITLE
    assert cut_misses(Neighborhood([Edge(sponsor, node, 0.95)]), observer, {node}, [bond]) == []


def colluding_sponsor_is_cut_with_the_node() -> None:
    observer, sponsor, node = (bytes([i]) for i in range(3))
    bond = SponsorBond(sponsor, node, 0.9)
    neigh = merge(Neighborhood([Edge(observer, sponsor, 0.3)]), [bond])
    sigs = {sponsor: b"\x11" * 64, node: b"\x22" * 64}
    view = LocalView(TITLE)
    outcome, _ = consider(view, proposal(sigs), require_keys(set(sigs)), neigh, observer, bonds=[bond])
    assert outcome is Outcome.SPENT_UNADVANCED
    assert not any(item.dst in {sponsor, node} and item.src == observer for item in neigh.edges)
    assert not any(item.src == sponsor and item.dst == node for item in neigh.edges)


def main() -> None:
    self_sponsor_rejected()
    trusted_sponsor_can_introduce()
    miss_cuts_signer_and_sponsor()
    bought_introduction_does_not_pass()
    colluding_sponsor_is_cut_with_the_node()
    print("sponsor cases ok")


if __name__ == "__main__":
    main()
