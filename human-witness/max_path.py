#!/usr/bin/env python3
"""Client-side max-path witness score.

An observer scores witness keys from a local neighborhood. The score is the
strongest hop-damped chain, not a sum of paths and not a network max-flow.
There is no global certification budget to enforce, so a hub is not treated
as a scarce capacity shared across observers.

Default operating point from the BA sweeps: hop limit 2, threshold 0.45,
no degree penalty. A key is not a person.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class Reject(Exception):
    pass


@dataclass(frozen=True)
class Edge:
    src: bytes
    dst: bytes
    weight: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.weight <= 1.0:
            raise Reject("edge weight must be in [0, 1]")
        if self.src == self.dst:
            raise Reject("loop")


@dataclass
class Neighborhood:
    """Edges the observer already has. Directed attestations."""

    edges: list[Edge] = field(default_factory=list)

    def out(self) -> dict[bytes, list[tuple[bytes, float]]]:
        adj: dict[bytes, list[tuple[bytes, float]]] = {}
        for edge in self.edges:
            adj.setdefault(edge.src, []).append((edge.dst, edge.weight))
            adj.setdefault(edge.dst, [])
        return adj


@dataclass(frozen=True)
class Policy:
    tau: float = 0.45
    gamma: float = 0.65
    hops: int = 2

    def __post_init__(self) -> None:
        if not 0.0 < self.tau <= 1.0:
            raise Reject("tau must be in (0, 1]")
        if not 0.0 < self.gamma <= 1.0:
            raise Reject("gamma must be in (0, 1]")
        if self.hops < 1 or self.hops > 2:
            raise Reject("hop limit is 1 or 2")


def max_path(neigh: Neighborhood, src: bytes, policy: Policy) -> dict[bytes, float]:
    """Strongest chain from src. T(P) = prod(w) * gamma^(len-1), hops <= H."""
    adj = neigh.out()
    best: dict[bytes, float] = {src: 1.0}
    stack: list[tuple[bytes, float, int, frozenset[bytes]]] = [(src, 1.0, 0, frozenset([src]))]
    while stack:
        node, prod, hops, seen = stack.pop()
        if hops == policy.hops:
            continue
        for nxt, weight in adj.get(node, []):
            if nxt in seen:
                continue
            score = prod * weight * (1.0 if hops == 0 else policy.gamma)
            if score < 0.01 or score <= best.get(nxt, 0.0):
                continue
            best[nxt] = score
            stack.append((nxt, score, hops + 1, seen | frozenset([nxt])))
    best.pop(src, None)
    return best


def accepts(neigh: Neighborhood, observer: bytes, witness: bytes, policy: Policy | None = None) -> tuple[bool, float]:
    policy = policy or Policy()
    score = max_path(neigh, observer, policy).get(witness, 0.0)
    return score >= policy.tau, score


def weigh(neigh: Neighborhood, observer: bytes, witnesses: list[bytes], policy: Policy | None = None) -> dict[bytes, tuple[bool, float]]:
    """Score each witness key on a consignment. Missing keys score 0."""
    policy = policy or Policy()
    scores = max_path(neigh, observer, policy)
    return {key: (scores.get(key, 0.0) >= policy.tau, scores.get(key, 0.0)) for key in witnesses}


def demo() -> None:
    observer, hub, friend, sybil, other = (bytes([i]) for i in range(5))
    honest = Neighborhood([
        Edge(observer, hub, 0.8),
        Edge(observer, friend, 0.7),
        Edge(hub, friend, 0.6),
        Edge(friend, other, 0.9),
    ])
    policy = Policy()
    ok, score = accepts(honest, observer, friend, policy)
    assert ok and abs(score - 0.7) < 1e-9, score
    ok, score = accepts(honest, observer, other, policy)
    # hop 2: 0.7 * 0.9 * gamma = 0.4095, under 0.45. Direct contacts pass; weak chains do not.
    assert not ok and abs(score - 0.7 * 0.9 * policy.gamma) < 1e-9, score
    attacked = Neighborhood(honest.edges + [Edge(hub, sybil, 0.8)])
    ok, score = accepts(attacked, observer, sybil, policy)
    # single chain through the hub: 0.8 * 0.8 * gamma = 0.416, under 0.45
    assert not ok and abs(score - 0.8 * 0.8 * policy.gamma) < 1e-9, score
    loose = Policy(tau=0.25, hops=2)
    ok, score = accepts(attacked, observer, sybil, loose)
    assert ok, score
    try:
        Policy(hops=3)
    except Reject:
        pass
    else:
        raise SystemExit("hop limit not clamped")
    print("max-path", policy.tau, policy.hops)
    print("evaluator ok")


if __name__ == "__main__":
    demo()
