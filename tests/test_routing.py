#!/usr/bin/env python3
"""Tests for routing with Jaccard cost.

Tests:
- 2-hop Jaccard routing
- Hollow-route mask not writing to graph
- Complement as set-difference of derived roles
"""

import pytest
import os
import hashlib

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from ivan_vaughan.routing import (
    Router,
    TwoHopNeighborhood,
    RouteProposal,
    HollowRoute,
    RoutingError,
    jaccard_similarity,
    jaccard_cost,
)
from ivan_vaughan.edge_store import Edge, EdgeStore
from ivan_vaughan.node import Node


class TestJaccardSimilarity:
    """Test Jaccard similarity computation."""
    
    def test_identical_sets(self):
        """Test Jaccard of identical sets."""
        a = frozenset([b'\x01', b'\x02', b'\x03'])
        b = frozenset([b'\x01', b'\x02', b'\x03'])
        
        assert jaccard_similarity(a, b) == 1.0
    
    def test_disjoint_sets(self):
        """Test Jaccard of disjoint sets."""
        a = frozenset([b'\x01', b'\x02'])
        b = frozenset([b'\x03', b'\x04'])
        
        assert jaccard_similarity(a, b) == 0.0
    
    def test_partial_overlap(self):
        """Test Jaccard with partial overlap."""
        a = frozenset([b'\x01', b'\x02', b'\x03'])
        b = frozenset([b'\x02', b'\x03', b'\x04'])
        
        # Intersection: {2, 3}, Union: {1, 2, 3, 4}
        # J = 2/4 = 0.5
        assert jaccard_similarity(a, b) == 0.5
    
    def test_empty_sets(self):
        """Test Jaccard of empty sets."""
        a: frozenset[bytes] = frozenset()
        b: frozenset[bytes] = frozenset()
        
        assert jaccard_similarity(a, b) == 1.0
    
    def test_cost_is_complement(self):
        """Test that cost = 1 - similarity."""
        a = frozenset([b'\x01', b'\x02', b'\x03'])
        b = frozenset([b'\x02', b'\x03', b'\x04'])
        
        sim = jaccard_similarity(a, b)
        cost = jaccard_cost(a, b)
        
        assert cost == 1.0 - sim


class TestTwoHopNeighborhood:
    """Test 2-hop neighborhood computation."""
    
    def test_jaccard_between_neighborhoods(self):
        """Test Jaccard similarity between neighborhoods."""
        n1 = TwoHopNeighborhood(
            center=b'\x00',
            one_hop=frozenset([b'\x01', b'\x02']),
            two_hop=frozenset([b'\x03']),
        )
        
        n2 = TwoHopNeighborhood(
            center=b'\x10',
            one_hop=frozenset([b'\x02', b'\x03']),
            two_hop=frozenset([b'\x04']),
        )
        
        # n1 neighbors: {1, 2, 3}
        # n2 neighbors: {2, 3, 4}
        # J = 2/4 = 0.5
        assert n1.jaccard_similarity(n2) == 0.5
    
    def test_jaccard_cost(self):
        """Test Jaccard cost computation."""
        n1 = TwoHopNeighborhood(
            center=b'\x00',
            one_hop=frozenset([b'\x01']),
            two_hop=frozenset(),
        )
        
        n2 = TwoHopNeighborhood(
            center=b'\x10',
            one_hop=frozenset([b'\x01']),
            two_hop=frozenset(),
        )
        
        # Same neighbors, J = 1, cost = 0
        assert n1.jaccard_cost(n2) == 0.0


class TestHollowRoute:
    """Test hollow-route mask."""
    
    def test_mask_is_local(self):
        """Test that hollow-route mask is local, not a graph write.
        
        Law 4: Hollow-route is a local revocable mask, never a graph write.
        """
        owner = b'\x01' * 32
        mask = HollowRoute(owner=owner)
        
        # Mask a node
        node_to_mask = b'\x02' * 32
        mask.mask_node(node_to_mask)
        
        assert mask.is_node_masked(node_to_mask)
        
        # The mask is only local state
        assert isinstance(mask.masked_nodes, set)
    
    def test_mask_revocable(self):
        """Test that masks can be revoked."""
        mask = HollowRoute(owner=b'\x01' * 32)
        node = b'\x02' * 32
        
        mask.mask_node(node)
        assert mask.is_node_masked(node)
        
        mask.unmask_node(node)
        assert not mask.is_node_masked(node)
    
    def test_cannot_mask_self(self):
        """Test that you cannot mask yourself."""
        owner = b'\x01' * 32
        mask = HollowRoute(owner=owner)
        
        with pytest.raises(RoutingError, match="cannot mask self"):
            mask.mask_node(owner)
    
    def test_mask_edge(self):
        """Test masking specific edges."""
        mask = HollowRoute(owner=b'\x01' * 32)
        edge_hash = hashlib.sha256(b"edge").digest()
        
        mask.mask_edge(edge_hash)
        
        assert mask.is_edge_masked(edge_hash)
    
    def test_clear_all_masks(self):
        """Test clearing all masks."""
        mask = HollowRoute(owner=b'\x01' * 32)
        
        mask.mask_node(b'\x02' * 32)
        mask.mask_edge(b'\x03' * 32)
        
        mask.clear()
        
        assert len(mask.masked_nodes) == 0
        assert len(mask.masked_edges) == 0


class TestRouteProposal:
    """Test route proposal constraints."""
    
    def test_max_two_hops(self):
        """Test that max 2 hops is enforced.
        
        Law 4: Routing: one proposal, max 2 hops.
        """
        with pytest.raises(RoutingError, match="max 2 hops"):
            RouteProposal(
                source=b'\x01' * 32,
                destination=b'\x04' * 32,
                path=(b'\x02' * 32, b'\x03' * 32, b'\x05' * 32),  # 3 intermediaries
                cost=0.5,
            )
    
    def test_zero_hop_route(self):
        """Test direct route (0 intermediaries)."""
        proposal = RouteProposal(
            source=b'\x01' * 32,
            destination=b'\x02' * 32,
            path=(),  # No intermediaries
            cost=0.2,
        )
        
        assert proposal.hop_count == 1
    
    def test_one_hop_route(self):
        """Test route with 1 intermediary (2 total hops)."""
        proposal = RouteProposal(
            source=b'\x01' * 32,
            destination=b'\x03' * 32,
            path=(b'\x02' * 32,),  # 1 intermediary
            cost=0.3,
        )
        
        assert proposal.hop_count == 2
    
    def test_cannot_route_to_self(self):
        """Test that source cannot equal destination."""
        with pytest.raises(RoutingError, match="cannot equal destination"):
            RouteProposal(
                source=b'\x01' * 32,
                destination=b'\x01' * 32,  # Same as source
                path=(),
                cost=0.0,
            )
    
    def test_full_path(self):
        """Test full_path property."""
        src = b'\x01' * 32
        dst = b'\x03' * 32
        intermediate = b'\x02' * 32
        
        proposal = RouteProposal(
            source=src,
            destination=dst,
            path=(intermediate,),
            cost=0.3,
        )
        
        assert proposal.full_path == (src, intermediate, dst)


class TestRouter:
    """Test the Router class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.store = EdgeStore(":memory:")
        self.local_node = Node.generate()
        self.router = Router(self.store, self.local_node.node_id.xonly)
    
    def teardown_method(self):
        """Clean up."""
        self.store.close()
    
    def _create_edge(self, signer_a: bytes, signer_b: bytes) -> Edge:
        """Create a test edge between two signers."""
        artifact_hash = hashlib.sha256(os.urandom(32)).digest()
        return Edge(
            artifact_hash=artifact_hash,
            signer_a=signer_a,
            signer_b=signer_b,
            signature_a=os.urandom(64),
            signature_b=os.urandom(64),
            parser_version="git_commit_v1",
        )
    
    def test_find_direct_route(self):
        """Test finding a direct route."""
        local_key = self.local_node.node_id.xonly
        dest_key = b'\x02' * 32
        
        # Create direct edge
        edge = self._create_edge(local_key, dest_key)
        self.store.store(edge)
        
        # Invalidate cache after adding edge
        self.router.invalidate_cache()
        
        route = self.router.find_route(dest_key)
        
        assert route is not None
        assert route.hop_count == 1
        assert route.path == ()
    
    def test_find_two_hop_route(self):
        """Test finding a 2-hop route."""
        local_key = self.local_node.node_id.xonly
        intermediate = b'\x02' * 32
        dest_key = b'\x03' * 32
        
        # Create edges: local -> intermediate -> dest
        edge1 = self._create_edge(local_key, intermediate)
        edge2 = self._create_edge(intermediate, dest_key)
        self.store.store(edge1)
        self.store.store(edge2)
        
        self.router.invalidate_cache()
        
        route = self.router.find_route(dest_key, max_hops=2)
        
        assert route is not None
        assert route.hop_count == 2
        assert route.path == (intermediate,)
    
    def test_hollow_route_excludes_node(self):
        """Test that hollow-route mask excludes nodes from routing."""
        local_key = self.local_node.node_id.xonly
        intermediate = b'\x02' * 32
        dest_key = b'\x03' * 32
        
        # Create edges
        edge1 = self._create_edge(local_key, intermediate)
        edge2 = self._create_edge(intermediate, dest_key)
        self.store.store(edge1)
        self.store.store(edge2)
        
        self.router.invalidate_cache()
        
        # Mask the intermediate node
        self.router.hollow_route.mask_node(intermediate)
        self.router.invalidate_cache()
        
        # Should not find route through masked node
        route = self.router.find_route(dest_key)
        
        # Either no route or route that doesn't go through intermediate
        if route:
            assert intermediate not in route.path
    
    def test_hollow_route_does_not_modify_graph(self):
        """Test that hollow-route does not write to the graph.
        
        Law 4: Hollow-route is a local revocable mask, never a graph write.
        """
        local_key = self.local_node.node_id.xonly
        other = b'\x02' * 32
        
        # Create edge
        edge = self._create_edge(local_key, other)
        self.store.store(edge)
        
        # Mask the node
        self.router.hollow_route.mask_node(other)
        
        # Edge should still exist in store
        assert self.store.has_edge(edge.canonical_hash)
        
        # Unmask and verify edge is still there
        self.router.hollow_route.unmask_node(other)
        self.router.invalidate_cache()
        
        route = self.router.find_route(other)
        assert route is not None
    
    def test_max_hops_enforced(self):
        """Test that max_hops > 2 raises error."""
        with pytest.raises(RoutingError, match="max 2 hops"):
            self.router.find_route(b'\x02' * 32, max_hops=3)
    
    def test_complement_is_set_difference(self):
        """Test complement computation.
        
        Law 4: Complement is set-difference of derived roles.
        """
        my_roles = frozenset(["repo:commit_author", "repo:reviewer"])
        other_roles = frozenset(["repo:reviewer"])
        
        complement = self.router.compute_complement(my_roles, other_roles)
        
        assert complement == frozenset(["repo:commit_author"])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
