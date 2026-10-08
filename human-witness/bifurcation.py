#!/usr/bin/env python3
"""Asset-view split after one confirmed spend signed by a hub.

Every observer sees the same proposal. require passes. The anchor proof is
confirmed. consider() then either advances the local title or marks the seal
spent and leaves the pointer. This file does not claim a quarantine.
"""

from __future__ import annotations

import math
import random

from client_observer import AnchorProof, LocalView, Outcome, Proposal, consider
from max_path import Edge, Neighborhood


def barabasi(n: int, mean_degree: int, rng: random.Random) -> list[dict[int, float]]:
    m = max(1, mean_degree // 2)
    adj: list[dict[int, float]] = [dict() for _ in range(n)]

    def link(a: int, b: int, weight: float) -> None:
        if a != b and b not in adj[a]:
            adj[a][b] = weight
            adj[b][a] = weight

    seed = max(m + 1, 4)
    for i in range(seed):
        for j in range(i + 1, seed):
            link(i, j, 0.55 + rng.random() * 0.4)
    bag: list[int] = []
    for i in range(seed):
        bag.extend([i] * max(1, len(adj[i])))
    for v in range(seed, n):
        chosen: set[int] = set()
        guard = 0
        while len(chosen) < m and guard < 40:
            chosen.add(bag[rng.randrange(len(bag))])
            guard += 1
        for u in chosen:
            link(v, u, 0.45 + rng.random() * 0.5)
        for u in chosen:
            bag.append(u)
            bag.append(v)
    return adj


def eigenvector(adj: list[dict[int, float]]) -> list[float]:
    n = len(adj)
    score = [1.0 / n] * n
    for _ in range(16):
        nxt = [0.0] * n
        for i in range(n):
            for j in adj[i]:
                nxt[i] += score[j]
        norm = math.sqrt(sum(x * x for x in nxt)) or 1.0
        score = [x / norm for x in nxt]
    return score


def neighborhood(adj: list[dict[int, float]], observer: int) -> Neighborhood:
    """Edges the observer can pull: own attestations and neighbor attestations."""
    edges: list[Edge] = []
    seen: set[tuple[int, int]] = set()
    nodes = {observer, *adj[observer]}
    for src in nodes:
        for dst, weight in adj[src].items():
            key = (src, dst)
            if key in seen:
                continue
            seen.add(key)
            edges.append(Edge(bytes([src]), bytes([dst]), weight))
    return Neighborhood(edges)


def split(n: int = 80, runs: int = 20, seed: int = 1000) -> dict[str, float]:
    if n > 256:
        raise SystemExit("node ids are one byte")
    title = bytes([7]) * 32
    nxt = bytes([8]) * 32
    op = bytes([9]) * 32
    bundle = bytes([4]) * 32
    prev = bytes([3]) * 32
    proof = AnchorProof(bytes([1]) * 32, 0, prev, 1, bundle, True)
    advanced = frozen = other = 0
    observers = 0
    for run in range(runs):
        rng = random.Random(seed + run)
        adj = barabasi(n, 6, rng)
        hub = max(range(n), key=lambda i: eigenvector(adj)[i])
        hub_key = bytes([hub])

        def require(op_id: bytes, sigs: dict[bytes, bytes], hub_key: bytes = hub_key) -> None:
            if op_id != op or set(sigs) != {hub_key}:
                raise RuntimeError("bad witness")

        proposal = Proposal(title, nxt, b"hub-signed", op, {hub_key: b"\x11" * 64}, bundle, prev, 1, proof)
        for observer in range(n):
            if observer == hub:
                continue
            observers += 1
            view = LocalView(title)
            outcome, _ = consider(view, proposal, require, neighborhood(adj, observer), bytes([observer]))
            if outcome is Outcome.ADVANCED:
                advanced += 1
                if view.title_seal != nxt or title not in view.spent:
                    raise SystemExit("advanced without moving the pointer")
            elif outcome is Outcome.SPENT_UNADVANCED:
                frozen += 1
                if view.title_seal != title or title not in view.spent:
                    raise SystemExit("spent-unadvanced did not hold the pointer")
            else:
                other += 1
    if other:
        raise SystemExit("objective or anchor gate failed")
    return {
        "advanced": advanced / observers,
        "spent_unadvanced": frozen / observers,
        "observers": float(observers),
    }


def demo() -> None:
    result = split()
    print(f"advanced {result['advanced']:.3f}")
    print(f"spent_unadvanced {result['spent_unadvanced']:.3f}")
    print(f"observers {int(result['observers'])}")
    if not 0.2 < result["advanced"] < 0.8:
        raise SystemExit("split collapsed; check the weight model")
    print("bifurcation ok")


if __name__ == "__main__":
    demo()
