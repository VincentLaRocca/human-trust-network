"""Tests for lens and sink verification (Law 3)."""

import hashlib
import os
import pytest

from ivan_vaughan.keys import NodeKeyPair
from ivan_vaughan.edge import Edge, create_edge_signature
from ivan_vaughan.parser import PARSER_VERSION
from ivan_vaughan.lens import (
    SinkType,
    MerkleProof,
    SinkVerification,
    LocalBuildVerifier,
    WeightedEdge,
    Lens,
)


def create_test_edge() -> Edge:
    """Create a test edge."""
    alice = NodeKeyPair.generate_ed25519()
    bob = NodeKeyPair.generate_ed25519()
    artifact = hashlib.sha256(os.urandom(32)).digest()

    alice_nonce = os.urandom(32)
    bob_nonce = os.urandom(32)

    alice_sig = create_edge_signature(alice, artifact, bob_nonce, alice_nonce)
    bob_sig = create_edge_signature(bob, artifact, alice_nonce, bob_nonce)

    return Edge(artifact, "git_commit", PARSER_VERSION, alice_sig, bob_sig)


class TestMerkleProof:
    """Tests for Merkle proof verification."""

    def test_simple_proof_verification(self):
        """Simple Merkle proof verifies correctly."""
        leaf = hashlib.sha256(b"leaf").digest()
        sibling = hashlib.sha256(b"sibling").digest()
        root = hashlib.sha256(leaf + sibling).digest()

        proof = MerkleProof(
            root=root,
            leaf=leaf,
            path=[(sibling, False)],  # sibling is on right
            proof_type="test",
        )

        assert proof.verify()

    def test_invalid_proof_fails(self):
        """Invalid Merkle proof fails verification."""
        leaf = hashlib.sha256(b"leaf").digest()
        wrong_root = hashlib.sha256(b"wrong").digest()

        proof = MerkleProof(
            root=wrong_root,
            leaf=leaf,
            path=[],
            proof_type="test",
        )

        assert not proof.verify()


class TestSinkVerification:
    """Tests for sink verification (Law 3)."""

    def test_build_dependency_verified(self):
        """Build dependency can be verified."""
        artifact = hashlib.sha256(b"dependency").digest()
        build = hashlib.sha256(b"build").digest()

        build_graph = {build: [artifact]}
        verifier = LocalBuildVerifier(build_graph)

        result = verifier.verify_build_dependency(artifact, build)

        assert result.verified
        assert result.sink_type == SinkType.BUILD_DEPENDENCY
        assert result.is_structural

    def test_non_dependency_not_verified(self):
        """Non-dependency is not verified."""
        artifact = hashlib.sha256(b"not-a-dep").digest()
        build = hashlib.sha256(b"build").digest()

        build_graph = {build: []}  # No dependencies
        verifier = LocalBuildVerifier(build_graph)

        result = verifier.verify_build_dependency(artifact, build)

        assert not result.verified
        assert not result.is_structural


class TestWeightedEdge:
    """Tests for weighted edges."""

    def test_zero_weight_initially(self):
        """Edges start at weight 0."""
        edge = create_test_edge()
        weighted = WeightedEdge.zero(edge)

        assert weighted.weight == 0.0
        assert not weighted.sink_verified
        assert weighted.roles == []


class TestLens:
    """Tests for lens scoring."""

    def test_add_edge_at_weight_zero(self):
        """Edges are added at weight 0."""
        artifacts = {}
        lens = Lens(
            sink_verifier=None,
            artifact_fetcher=lambda h: artifacts.get(h),
        )

        edge = create_test_edge()
        lens.add_edge(edge)

        assert edge.edge_hash in lens.scored_edges
        assert lens.get_weight(edge.edge_hash) == 0.0

    def test_weight_remains_zero_without_sink(self):
        """Weight remains 0 until sink verified (Law 3)."""
        artifacts = {}
        lens = Lens(
            sink_verifier=None,  # No verifier
            artifact_fetcher=lambda h: artifacts.get(h),
        )

        edge = create_test_edge()
        lens.add_edge(edge)
        lens.score_edge(edge.edge_hash)

        assert lens.get_weight(edge.edge_hash) == 0.0

    def test_weight_positive_after_sink_verification(self):
        """Weight is positive after sink verification."""
        artifact = hashlib.sha256(b"code").digest()
        build = hashlib.sha256(b"build").digest()

        artifacts = {artifact: b"code"}
        build_graph = {build: [artifact]}

        lens = Lens(
            sink_verifier=LocalBuildVerifier(build_graph),
            artifact_fetcher=lambda h: artifacts.get(h),
        )

        alice = NodeKeyPair.generate_ed25519()
        bob = NodeKeyPair.generate_ed25519()
        alice_nonce = os.urandom(32)
        bob_nonce = os.urandom(32)
        alice_sig = create_edge_signature(alice, artifact, bob_nonce, alice_nonce)
        bob_sig = create_edge_signature(bob, artifact, alice_nonce, bob_nonce)
        edge = Edge(artifact, "git_commit", PARSER_VERSION, alice_sig, bob_sig)

        lens.add_edge(edge)
        result = lens.score_edge(edge.edge_hash, build)

        assert result.weight == 1.0
        assert result.sink_verified

    def test_fee_not_a_sink(self):
        """A fee, OP_RETURN, or payload flag is not a sink (Law 3)."""
        # The sink verifier only recognizes structural dependencies
        # It does not accept arbitrary payment or flag-based proofs

        artifact = hashlib.sha256(b"artifact").digest()
        fee_proof = hashlib.sha256(b"fee_paid").digest()

        # Build graph doesn't include fee as a dependency
        build_graph = {}
        verifier = LocalBuildVerifier(build_graph)

        result = verifier.verify_build_dependency(artifact, fee_proof)
        assert not result.is_structural

    def test_lens_async_scoring(self):
        """Lens scores asynchronously (doesn't block transport)."""
        artifacts = {}
        lens = Lens(
            sink_verifier=None,
            artifact_fetcher=lambda h: artifacts.get(h),
        )

        # Add multiple edges
        edges = [create_test_edge() for _ in range(5)]
        for edge in edges:
            lens.add_edge(edge)

        # All go to pending
        assert len(lens.pending_verification) == 5

        # Process pending
        lens.process_pending()

        # Still at weight 0 (no sink verifier)
        for edge in edges:
            assert lens.get_weight(edge.edge_hash) == 0.0

    def test_cascade_stops_at_artifact(self):
        """The cascade stops at that artifact (Law 3)."""
        # Verifying artifact A doesn't automatically verify
        # artifacts that depend on A

        artifact_a = hashlib.sha256(b"a").digest()
        artifact_b = hashlib.sha256(b"b").digest()
        build = hashlib.sha256(b"build").digest()

        # B depends on A, build depends on B
        # Verifying B doesn't cascade to A
        build_graph = {build: [artifact_b]}  # Only B is direct dep
        verifier = LocalBuildVerifier(build_graph)

        result_a = verifier.verify_build_dependency(artifact_a, build)
        result_b = verifier.verify_build_dependency(artifact_b, build)

        assert not result_a.is_structural  # A is not a direct dep
        assert result_b.is_structural  # B is a direct dep


class TestLensFiltering:
    """Tests for lens-based filtering."""

    def test_filter_by_weight(self):
        """Filter edges by weight threshold."""
        artifacts = {}
        lens = Lens(
            sink_verifier=None,
            artifact_fetcher=lambda h: artifacts.get(h),
        )

        edge1 = create_test_edge()
        edge2 = create_test_edge()
        lens.add_edge(edge1)
        lens.add_edge(edge2)

        # Manually set weight for testing
        lens.scored_edges[edge1.edge_hash] = WeightedEdge(
            edge=edge1, weight=1.0, roles=[], sink_verified=True
        )

        weighted = lens.filter_by_weight(min_weight=0.5)
        assert len(weighted) == 1
        assert weighted[0].edge.edge_hash == edge1.edge_hash
