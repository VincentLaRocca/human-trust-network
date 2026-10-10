#!/usr/bin/env python3
"""Routing with 2-hop Jaccard cost and hollow-route mask.

Law 4: Routing: one proposal, max 2 hops, Jaccard cost on 2-hop neighborhoods,
complement is set-difference of derived roles. Hollow-route is a local revocable
mask, never a graph write.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional, Iterator, FrozenSet

try:
    from .edge_store import Edge, StoredEdge, EdgeStore
except ImportError:
    from ivan_vaughan.edge_store import Edge, StoredEdge, EdgeStore


class RoutingError(Exception):
    """Base exception for routing operations."""
    pass


@dataclass(frozen=True)
class Neighbor:
    """A neighbor in the 2-hop neighborhood."""
    key: bytes  # 32-byte x-only public key
    hop_distance: int  # 1 or 2
    via: Optional[bytes] = None  # The 1-hop intermediary for 2-hop neighbors


@dataclass
class TwoHopNeighborhood:
    """The 2-hop neighborhood of a node.
    
    Used for Jaccard cost computation in routing proposals.
    """
    center: bytes  # The center node's key
    one_hop: frozenset[bytes] = field(default_factory=frozenset)
    two_hop: frozenset[bytes] = field(default_factory=frozenset)
    
    @property
    def all_neighbors(self) -> frozenset[bytes]:
        """All neighbors within 2 hops."""
        return self.one_hop | self.two_hop
    
    def jaccard_similarity(self, other: "TwoHopNeighborhood") -> float:
        """Compute Jaccard similarity between two neighborhoods.
        
        J(A, B) = |A ∩ B| / |A ∪ B|
        """
        a = self.all_neighbors
        b = other.all_neighbors
        
        if not a and not b:
            return 1.0  # Both empty = identical
        
        intersection = a & b
        union = a | b
        
        return len(intersection) / len(union) if union else 0.0
    
    def jaccard_cost(self, other: "TwoHopNeighborhood") -> float:
        """Compute Jaccard cost (1 - similarity).
        
        Lower cost = more similar neighborhoods = better routing path.
        """
        return 1.0 - self.jaccard_similarity(other)


@dataclass(frozen=True)
class RouteProposal:
    """A routing proposal from source to destination.
    
    Law 4: One proposal, max 2 hops.
    """
    source: bytes
    destination: bytes
    path: tuple[bytes, ...]  # Intermediate nodes (0, 1, or 2 elements)
    cost: float  # Jaccard cost
    
    def __post_init__(self) -> None:
        if len(self.path) > 2:
            raise RoutingError("max 2 hops allowed")
        if self.source == self.destination:
            raise RoutingError("source cannot equal destination")
    
    @property
    def hop_count(self) -> int:
        """Number of hops in this route."""
        return len(self.path) + 1
    
    @property
    def full_path(self) -> tuple[bytes, ...]:
        """Complete path including source and destination."""
        return (self.source,) + self.path + (self.destination,)


@dataclass
class HollowRoute:
    """A hollow-route mask: local, revocable, never a graph write.
    
    Law 4: Hollow-route is a local revocable mask, never a graph write.
    
    A hollow route masks certain edges or nodes from routing consideration
    without modifying the underlying graph.
    """
    owner: bytes  # The node that owns this mask
    masked_nodes: set[bytes] = field(default_factory=set)
    masked_edges: set[bytes] = field(default_factory=set)  # canonical edge hashes
    
    def mask_node(self, node: bytes) -> None:
        """Mask a node from routing (local only)."""
        if node == self.owner:
            raise RoutingError("cannot mask self")
        self.masked_nodes.add(node)
    
    def mask_edge(self, edge_hash: bytes) -> None:
        """Mask an edge from routing (local only)."""
        self.masked_edges.add(edge_hash)
    
    def unmask_node(self, node: bytes) -> None:
        """Unmask a node (revoke the mask)."""
        self.masked_nodes.discard(node)
    
    def unmask_edge(self, edge_hash: bytes) -> None:
        """Unmask an edge (revoke the mask)."""
        self.masked_edges.discard(edge_hash)
    
    def is_node_masked(self, node: bytes) -> bool:
        """Check if a node is masked."""
        return node in self.masked_nodes
    
    def is_edge_masked(self, edge_hash: bytes) -> bool:
        """Check if an edge is masked."""
        return edge_hash in self.masked_edges
    
    def clear(self) -> None:
        """Clear all masks."""
        self.masked_nodes.clear()
        self.masked_edges.clear()


class Router:
    """Routes proposals through the graph with 2-hop max and Jaccard cost.
    
    Respects hollow-route masks which are local and never written to the graph.
    """
    
    def __init__(self, store: EdgeStore, local_key: bytes):
        self.store = store
        self.local_key = local_key
        self._hollow_route = HollowRoute(owner=local_key)
        self._neighborhood_cache: dict[bytes, TwoHopNeighborhood] = {}
    
    @property
    def hollow_route(self) -> HollowRoute:
        """The local hollow-route mask."""
        return self._hollow_route
    
    def _get_neighbors(self, node: bytes) -> frozenset[bytes]:
        """Get direct neighbors of a node."""
        neighbors = set()
        for stored in self.store.edges_for_signer(node):
            edge = stored.edge
            other = edge.signer_b if edge.signer_a == node else edge.signer_a
            
            # Check hollow-route masks
            if self._hollow_route.is_node_masked(other):
                continue
            if self._hollow_route.is_edge_masked(edge.canonical_hash):
                continue
            
            neighbors.add(other)
        return frozenset(neighbors)
    
    def compute_neighborhood(self, node: bytes) -> TwoHopNeighborhood:
        """Compute the 2-hop neighborhood of a node."""
        if node in self._neighborhood_cache:
            return self._neighborhood_cache[node]
        
        one_hop = self._get_neighbors(node)
        
        # Get 2-hop neighbors (neighbors of neighbors, excluding 1-hop and self)
        two_hop = set()
        for neighbor in one_hop:
            for second_hop in self._get_neighbors(neighbor):
                if second_hop != node and second_hop not in one_hop:
                    two_hop.add(second_hop)
        
        neighborhood = TwoHopNeighborhood(
            center=node,
            one_hop=one_hop,
            two_hop=frozenset(two_hop),
        )
        self._neighborhood_cache[node] = neighborhood
        return neighborhood
    
    def invalidate_cache(self, node: Optional[bytes] = None) -> None:
        """Invalidate neighborhood cache."""
        if node:
            self._neighborhood_cache.pop(node, None)
        else:
            self._neighborhood_cache.clear()
    
    def find_route(self, destination: bytes, max_hops: int = 2) -> Optional[RouteProposal]:
        """Find a route to the destination with minimum Jaccard cost.
        
        Law 4: One proposal, max 2 hops.
        """
        if max_hops > 2:
            raise RoutingError("max 2 hops allowed by protocol")
        
        if self.local_key == destination:
            raise RoutingError("cannot route to self")
        
        if self._hollow_route.is_node_masked(destination):
            return None  # Destination is masked
        
        source_hood = self.compute_neighborhood(self.local_key)
        dest_hood = self.compute_neighborhood(destination)
        
        best_proposal: Optional[RouteProposal] = None
        best_cost = float('inf')
        
        # Try direct route (0 intermediaries, 1 hop)
        if destination in source_hood.one_hop:
            cost = source_hood.jaccard_cost(dest_hood)
            if cost < best_cost:
                best_cost = cost
                best_proposal = RouteProposal(
                    source=self.local_key,
                    destination=destination,
                    path=(),
                    cost=cost,
                )
        
        # Try 1-intermediary routes (2 hops) if allowed
        if max_hops >= 2:
            for intermediate in source_hood.one_hop:
                if self._hollow_route.is_node_masked(intermediate):
                    continue
                    
                intermediate_hood = self.compute_neighborhood(intermediate)
                
                if destination in intermediate_hood.one_hop:
                    # Average cost through the intermediate
                    cost1 = source_hood.jaccard_cost(intermediate_hood)
                    cost2 = intermediate_hood.jaccard_cost(dest_hood)
                    total_cost = (cost1 + cost2) / 2
                    
                    if total_cost < best_cost:
                        best_cost = total_cost
                        best_proposal = RouteProposal(
                            source=self.local_key,
                            destination=destination,
                            path=(intermediate,),
                            cost=total_cost,
                        )
        
        return best_proposal
    
    def compute_complement(
        self,
        my_roles: FrozenSet[str],
        other_roles: FrozenSet[str],
    ) -> FrozenSet[str]:
        """Compute the complement as set-difference of derived roles.
        
        Law 4: Complement is set-difference of derived roles.
        """
        return my_roles - other_roles


def jaccard_similarity(set_a: FrozenSet[bytes], set_b: FrozenSet[bytes]) -> float:
    """Compute Jaccard similarity between two sets.
    
    J(A, B) = |A ∩ B| / |A ∪ B|
    """
    if not set_a and not set_b:
        return 1.0
    
    intersection = set_a & set_b
    union = set_a | set_b
    
    return len(intersection) / len(union) if union else 0.0


def jaccard_cost(set_a: FrozenSet[bytes], set_b: FrozenSet[bytes]) -> float:
    """Compute Jaccard cost (1 - similarity)."""
    return 1.0 - jaccard_similarity(set_a, set_b)
