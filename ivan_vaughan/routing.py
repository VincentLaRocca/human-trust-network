"""Routing with Jaccard cost. (Law 4)

One proposal, max 2 hops, Jaccard cost on 2-hop neighborhoods.
The complement is the set-difference of derived roles.
Hollow-route is a local, revocable mask, never a graph write.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional, Set, FrozenSet

from .keys import NodeKey
from .edge import Edge


@dataclass(frozen=True)
class RouteProposal:
    """A single routing proposal to introduce two nodes."""

    source: bytes  # node_id of proposer
    target: bytes  # node_id of target
    via: Optional[bytes]  # node_id of intermediary (if 2-hop)
    artifact_hash: bytes
    jaccard_cost: float

    def hops(self) -> int:
        return 2 if self.via is not None else 1


@dataclass
class Neighborhood:
    """2-hop neighborhood of a node."""

    center: bytes  # node_id
    direct_edges: set[bytes] = field(default_factory=set)  # node_ids at hop 1
    two_hop_edges: set[bytes] = field(default_factory=set)  # node_ids at hop 2

    def all_reachable(self) -> set[bytes]:
        """All nodes reachable within 2 hops."""
        return self.direct_edges | self.two_hop_edges

    def complement(self, other: "Neighborhood") -> set[bytes]:
        """Set difference: nodes in self but not in other."""
        return self.all_reachable() - other.all_reachable()


def jaccard_similarity(set_a: set[bytes], set_b: set[bytes]) -> float:
    """Jaccard similarity coefficient: |A ∩ B| / |A ∪ B|"""
    if not set_a and not set_b:
        return 1.0  # Both empty = identical
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


def jaccard_cost(set_a: set[bytes], set_b: set[bytes]) -> float:
    """Jaccard distance: 1 - similarity. Used for routing cost."""
    return 1.0 - jaccard_similarity(set_a, set_b)


def build_neighborhood(
    node_id: bytes,
    edges: list[Edge],
    max_hops: int = 2,
) -> Neighborhood:
    """Build 2-hop neighborhood from edge list."""
    adj: dict[bytes, set[bytes]] = {}

    for edge in edges:
        a, b = edge.nodes
        adj.setdefault(a.node_id, set()).add(b.node_id)
        adj.setdefault(b.node_id, set()).add(a.node_id)

    direct = adj.get(node_id, set())
    two_hop: set[bytes] = set()

    if max_hops >= 2:
        for neighbor in direct:
            for second in adj.get(neighbor, set()):
                if second != node_id and second not in direct:
                    two_hop.add(second)

    return Neighborhood(center=node_id, direct_edges=direct, two_hop_edges=two_hop)


def find_route(
    source_id: bytes,
    target_id: bytes,
    all_edges: list[Edge],
    artifact_hash: bytes,
) -> Optional[RouteProposal]:
    """Find best route from source to target, max 2 hops.

    Returns the single best proposal (one proposal rule).
    Uses Jaccard cost on 2-hop neighborhoods for scoring.
    """
    adj: dict[bytes, set[bytes]] = {}
    for edge in all_edges:
        a, b = edge.nodes
        adj.setdefault(a.node_id, set()).add(b.node_id)
        adj.setdefault(b.node_id, set()).add(a.node_id)

    source_neigh = build_neighborhood(source_id, all_edges)
    target_neigh = build_neighborhood(target_id, all_edges)

    if target_id in source_neigh.direct_edges:
        cost = jaccard_cost(source_neigh.all_reachable(), target_neigh.all_reachable())
        return RouteProposal(
            source=source_id,
            target=target_id,
            via=None,
            artifact_hash=artifact_hash,
            jaccard_cost=cost,
        )

    best_route: Optional[RouteProposal] = None
    best_cost = float("inf")

    for via in source_neigh.direct_edges:
        if target_id in adj.get(via, set()):
            via_neigh = build_neighborhood(via, all_edges)
            cost = jaccard_cost(source_neigh.all_reachable(), target_neigh.all_reachable())
            cost += 0.1 * jaccard_cost(source_neigh.all_reachable(), via_neigh.all_reachable())

            if cost < best_cost:
                best_cost = cost
                best_route = RouteProposal(
                    source=source_id,
                    target=target_id,
                    via=via,
                    artifact_hash=artifact_hash,
                    jaccard_cost=cost,
                )

    return best_route


@dataclass
class HollowRoute:
    """A local, revocable mask on a route. Never a graph write.

    Used to temporarily hide a route from local pathfinding
    without modifying the actual graph.
    """

    source: bytes
    target: bytes
    via: Optional[bytes]
    revoked: bool = False

    def matches(self, proposal: RouteProposal) -> bool:
        """Check if this mask applies to a proposal."""
        return (
            proposal.source == self.source
            and proposal.target == self.target
            and proposal.via == self.via
        )


@dataclass
class RoutingState:
    """Local routing state for a node."""

    my_node_id: bytes
    hollow_routes: list[HollowRoute] = field(default_factory=list)

    def add_hollow_route(self, route: HollowRoute) -> None:
        """Add a local mask (hollow route). Revocable, never a graph write."""
        self.hollow_routes.append(route)

    def revoke_hollow_route(self, source: bytes, target: bytes, via: Optional[bytes]) -> bool:
        """Revoke a hollow route mask."""
        for hr in self.hollow_routes:
            if hr.source == source and hr.target == target and hr.via == via:
                hr.revoked = True
                return True
        return False

    def is_masked(self, proposal: RouteProposal) -> bool:
        """Check if a proposal is masked by any active hollow route."""
        for hr in self.hollow_routes:
            if not hr.revoked and hr.matches(proposal):
                return True
        return False

    def filter_proposals(self, proposals: list[RouteProposal]) -> list[RouteProposal]:
        """Filter out masked proposals."""
        return [p for p in proposals if not self.is_masked(p)]
