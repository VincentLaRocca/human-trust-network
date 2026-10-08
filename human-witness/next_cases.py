#!/usr/bin/env python3
"""Four follow-on cases against the gates that exist.

No regtest node. No claim that a rate is a Bitcoin result.
"""

from __future__ import annotations

from client_observer import AnchorProof, LocalView, Outcome, Proposal, Reject, consider
from max_path import Edge, Neighborhood


TITLE = bytes([7]) * 32
NXT = bytes([8]) * 32
OP = bytes([9]) * 32
BUNDLE = bytes([4]) * 32
PREV = bytes([3]) * 32
PROOF = AnchorProof(bytes([1]) * 32, 0, PREV, 1, BUNDLE, True)


def proposal(sigs, proof=PROOF, spent=TITLE):
    return Proposal(spent, NXT, b"case", OP, sigs, BUNDLE, PREV, 1, proof)


def require_keys(expected: set[bytes]):
    def require(op_id: bytes, sigs: dict[bytes, bytes]) -> None:
        if op_id != OP or set(sigs) != expected or any(len(sig) != 64 for sig in sigs.values()):
            raise Reject("bad witness")
    return require


def threshold_split() -> None:
    hub, sybil, observer = (bytes([i]) for i in range(3))
    neigh = Neighborhood([Edge(observer, hub, 0.8)])
    both = {hub: b"\x11" * 64, sybil: b"\x22" * 64}
    view = LocalView(TITLE)
    outcome, _ = consider(view, proposal(both), require_keys(set(both)), neigh, observer)
    assert outcome is Outcome.SPENT_UNADVANCED, outcome
    assert view.title_seal == TITLE and TITLE in view.spent
    trusted = Neighborhood([Edge(observer, hub, 0.8), Edge(observer, sybil, 0.7)])
    view2 = LocalView(TITLE)
    outcome, _ = consider(view2, proposal(both), require_keys(set(both)), trusted, observer)
    assert outcome is Outcome.ADVANCED and view2.title_seal == NXT, outcome


def cold_path_does_not_skip_witnesses() -> None:
    observer = bytes([1])
    view = LocalView(TITLE)
    outcome, _ = consider(view, proposal({}), require_keys({bytes([9])}), Neighborhood([]), observer)
    assert outcome is Outcome.GARBAGE, outcome
    assert TITLE not in view.spent and view.title_seal == TITLE


def confirmed_spend_orders_the_pointer() -> None:
    hub, observer = bytes([1]), bytes([2])
    neigh = Neighborhood([Edge(observer, hub, 0.8)])
    sigs = {hub: b"\x11" * 64}
    view = LocalView(TITLE)
    first, _ = consider(view, proposal(sigs), require_keys(set(sigs)), neigh, observer)
    assert first is Outcome.ADVANCED and view.title_seal == NXT
    second, _ = consider(view, proposal(sigs), require_keys(set(sigs)), neigh, observer)
    assert second is Outcome.GARBAGE and view.title_seal == NXT
    other = LocalView(TITLE)
    missing, _ = consider(other, proposal(sigs, proof=None), require_keys(set(sigs)), neigh, observer)
    assert missing is Outcome.UNANCHORED and other.title_seal == TITLE and TITLE not in other.spent


def direct_edges_advance() -> None:
    signer, observer = bytes([1]), bytes([2])
    weak = Neighborhood([Edge(observer, signer, 0.4)])
    held, _ = consider(LocalView(TITLE), proposal({signer: b"\x11" * 64}), require_keys({signer}), weak, observer)
    assert held is Outcome.SPENT_UNADVANCED
    strong = Neighborhood([Edge(observer, signer, 0.5)])
    moved, _ = consider(LocalView(TITLE), proposal({signer: b"\x11" * 64}), require_keys({signer}), strong, observer)
    assert moved is Outcome.ADVANCED


def main() -> None:
    threshold_split()
    cold_path_does_not_skip_witnesses()
    confirmed_spend_orders_the_pointer()
    direct_edges_advance()
    print("next cases ok")


if __name__ == "__main__":
    main()
