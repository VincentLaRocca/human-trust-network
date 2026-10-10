"""Tests for routing with Jaccard cost (Law 4)."""

import hashlib
import os
import pytest

from ivan_vaughan.keys import NodeKeyPair
from ivan_vaughan.edge import Edge, create_edge_signature
from ivan_vaughan.parser import PARSER_VERSION
from ivan_vaughan.routing import (
    RouteProposal,
    Neighborhood,
    HollowRoute,
    RoutingState,
    jaccard_similarity,
    jaccard_cost,
    build_neighborhood,
    find_route,
)


def create_edge(alice: NodeKeyPair, bob: NodeKeyPair, artifact_seed: bytes) -> Edge:
    """Create a test edge."""
    artifact = hashlib.sha256(artifact_seed).digest()
    alice_nonce = os.urandom(32)
    bob_nonce = os.urandom(32)
    alice_sig = create_edge_signature(alice, artifact, bob_nonce, alice_nonce)
    bob_sig = create_edge_signature(bob, artifact, alice_nonce, bob_nonce)
    return Edge(artifact, "git_commit", PARSER_VERSION, alice_sig, bob_sig)


class TestJaccardCost:
    """Tests for Jaccard similarity/distance."""

    def test_identical_sets_similarity_one(self):
        """Identical sets have similarity 1."""
        a = {b"1", b"2", b"3"}
        assert jaccard_similarity(a, a) == 1.0

    def test_disjoint_sets_similarity_zero(self):
        """Disjoint sets have similarity 0."""
        a = {b"1", b"2"}
        b = {b"3", b"4"}
        assert jaccard_similarity(a, b) == 0.0

    def test_empty_sets_similarity_one(self):
        """Two empty sets have similarity 1."""
        assert jaccard_similarity(set(), set()) == 1.0

    def test_jaccard_cost_is_one_minus_similarity(self):
        """Jaccard cost = 1 - similarity."""
        a = {b"1", b"2", b"3"}
        b = {b"2", b"3", b"4"}
        sim = jaccard_similarity(a, b)
        cost = jaccard_cost(a, b)
        assert abs((1 - sim) - cost) < 1e-9

    def test_partial_overlap(self):
        """Partial overlap gives intermediate values."""
        a = {b"1", b"2", b"3"}
        b = {b"2", b"3", b"4"}
        # intersection = {2,3} = 2, union = {1,2,3,4} = 4
        assert abs(jaccard_similarity(a, b) - 0.5) < 1e-9


class TestNeighborhood:
    """Tests for neighborhood building."""

    def test_direct_edges(self):
        """Direct edges are at hop 1."""
        me = NodeKeyPair.generate_ed25519()
        friend = NodeKeyPair.generate_ed25519()
        edge = create_edge(me, friend, b"edge")

        neigh = build_neighborhood(me.node_id, [edge])
        assert friend.node_id in neigh.direct_edges

    def test_two_hop_edges(self):
        """Friends of friends are at hop 2."""
        me = NodeKeyPair.generate_ed25519()
        friend = NodeKeyPair.generate_ed25519()
        fof = NodeKeyPair.generate_ed25519()

        edge1 = create_edge(me, friend, b"e1")
        edge2 = create_edge(friend, fof, b"e2")

        neigh = build_neighborhood(me.node_id, [edge1, edge2])
        assert friend.node_id in neigh.direct_edges
        assert fof.node_id in neigh.two_hop_edges

    def test_self_not_in_neighborhood(self):
        """Self is not included in reachable set."""
        me = NodeKeyPair.generate_ed25519()
        friend = NodeKeyPair.generate_ed25519()
        edge = create_edge(me, friend, b"e")

        neigh = build_neighborhood(me.node_id, [edge])
        assert me.node_id not in neigh.all_reachable()

    def test_complement_is_set_difference(self):
        """Complement is set difference of derived roles."""
        neigh1 = Neighborhood(
            center=b"me",
            direct_edges={b"a", b"b"},
            two_hop_edges={b"c"},
        )
        neigh2 = Neighborhood(
            center=b"them",
            direct_edges={b"b", b"d"},
            two_hop_edges={b"e"},
        )

        complement = neigh1.complement(neigh2)
        assert b"a" in complement
        assert b"c" in complement
        assert b"b" not in complement


class TestRouting:
    """Tests for route finding."""

    def test_direct_route_one_hop(self):
        """Direct connection is 1 hop."""
        me = NodeKeyPair.generate_ed25519()
        target = NodeKeyPair.generate_ed25519()
        artifact = hashlib.sha256(b"artifact").digest()

        edge = create_edge(me, target, b"edge")
        route = find_route(me.node_id, target.node_id, [edge], artifact)

        assert route is not None
        assert route.hops() == 1
        assert route.via is None

    def test_two_hop_route(self):
        """Route through intermediary is 2 hops."""
        me = NodeKeyPair.generate_ed25519()
        via = NodeKeyPair.generate_ed25519()
        target = NodeKeyPair.generate_ed25519()
        artifact = hashlib.sha256(b"artifact").digest()

        edge1 = create_edge(me, via, b"e1")
        edge2 = create_edge(via, target, b"e2")

        route = find_route(me.node_id, target.node_id, [edge1, edge2], artifact)

        assert route is not None
        assert route.hops() == 2
        assert route.via == via.node_id

    def test_no_route_returns_none(self):
        """No path returns None."""
        me = NodeKeyPair.generate_ed25519()
        target = NodeKeyPair.generate_ed25519()
        artifact = hashlib.sha256(b"artifact").digest()

        route = find_route(me.node_id, target.node_id, [], artifact)
        assert route is None

    def test_max_two_hops(self):
        """No route beyond 2 hops (Law 4)."""
        nodes = [NodeKeyPair.generate_ed25519() for _ in range(4)]
        edges = [
            create_edge(nodes[0], nodes[1], b"e1"),
            create_edge(nodes[1], nodes[2], b"e2"),
            create_edge(nodes[2], nodes[3], b"e3"),  # 3 hops to reach
        ]
        artifact = hashlib.sha256(b"art").digest()

        route = find_route(nodes[0].node_id, nodes[3].node_id, edges, artifact)
        assert route is None

    def test_one_proposal_only(self):
        """Only one proposal returned (Law 4)."""
        me = NodeKeyPair.generate_ed25519()
        via1 = NodeKeyPair.generate_ed25519()
        via2 = NodeKeyPair.generate_ed25519()
        target = NodeKeyPair.generate_ed25519()

        edges = [
            create_edge(me, via1, b"e1"),
            create_edge(me, via2, b"e2"),
            create_edge(via1, target, b"e3"),
            create_edge(via2, target, b"e4"),
        ]
        artifact = hashlib.sha256(b"art").digest()

        route = find_route(me.node_id, target.node_id, edges, artifact)
        assert route is not None
        # Returns single best proposal, not a list


class TestHollowRoute:
    """Tests for hollow routes (local, revocable masks)."""

    def test_hollow_route_is_local_mask(self):
        """Hollow route is a local mask, not a graph write."""
        state = RoutingState(my_node_id=b"me")
        hr = HollowRoute(source=b"me", target=b"them", via=b"via")

        state.add_hollow_route(hr)
        assert len(state.hollow_routes) == 1

    def test_hollow_route_masks_proposal(self):
        """Hollow route masks matching proposals."""
        state = RoutingState(my_node_id=b"me")
        hr = HollowRoute(source=b"me", target=b"them", via=b"via")
        state.add_hollow_route(hr)

        proposal = RouteProposal(
            source=b"me",
            target=b"them",
            via=b"via",
            artifact_hash=bytes(32),
            jaccard_cost=0.5,
        )

        assert state.is_masked(proposal)

    def test_hollow_route_revocable(self):
        """Hollow route can be revoked."""
        state = RoutingState(my_node_id=b"me")
        hr = HollowRoute(source=b"me", target=b"them", via=None)
        state.add_hollow_route(hr)

        proposal = RouteProposal(b"me", b"them", None, bytes(32), 0.5)
        assert state.is_masked(proposal)

        state.revoke_hollow_route(b"me", b"them", None)
        assert not state.is_masked(proposal)

    def test_hollow_route_never_graph_write(self):
        """Hollow routes don't modify actual edge data."""
        me = NodeKeyPair.generate_ed25519()
        them = NodeKeyPair.generate_ed25519()
        edge = create_edge(me, them, b"edge")

        state = RoutingState(my_node_id=me.node_id)
        state.add_hollow_route(HollowRoute(me.node_id, them.node_id, None))

        # Edge still exists, hollow route is just a local filter
        neigh = build_neighborhood(me.node_id, [edge])
        assert them.node_id in neigh.direct_edges
