"""Tests for edge creation and verification (Law 2).

Includes tests for canonical edge hash order-independence.
"""

import hashlib
import os
import pytest

from ivan_vaughan.keys import NodeKeyPair
from ivan_vaughan.edge import (
    Edge,
    EdgeSignature,
    PendingEdge,
    create_edge_signature,
    verify_edge,
    verify_edge_signature,
    edge_signing_payload,
)
from ivan_vaughan.parser import PARSER_VERSION
from ivan_vaughan.wire import encode, decode


class TestEdgeSignature:
    """Tests for EdgeSignature creation."""

    def test_signature_creation(self):
        """Create an edge signature."""
        kp = NodeKeyPair.generate_ed25519()
        artifact = hashlib.sha256(b"artifact").digest()
        my_nonce = os.urandom(32)
        peer_nonce = os.urandom(32)

        sig = create_edge_signature(kp, artifact, peer_nonce, my_nonce)
        assert sig.signer == kp.public
        assert len(sig.signature) > 0
        assert sig.nonce == my_nonce

    def test_signature_verification(self):
        """Signature verifies correctly."""
        kp = NodeKeyPair.generate_ed25519()
        artifact = hashlib.sha256(b"artifact").digest()
        my_nonce = os.urandom(32)
        peer_nonce = os.urandom(32)

        sig = create_edge_signature(kp, artifact, peer_nonce, my_nonce)
        assert verify_edge_signature(sig, artifact, peer_nonce)

    def test_wrong_artifact_fails(self):
        """Signature with wrong artifact fails."""
        kp = NodeKeyPair.generate_ed25519()
        artifact = hashlib.sha256(b"artifact").digest()
        wrong = hashlib.sha256(b"wrong").digest()
        my_nonce = os.urandom(32)
        peer_nonce = os.urandom(32)

        sig = create_edge_signature(kp, artifact, peer_nonce, my_nonce)
        assert not verify_edge_signature(sig, wrong, peer_nonce)

    def test_wrong_nonce_fails(self):
        """Signature with wrong counterparty nonce fails."""
        kp = NodeKeyPair.generate_ed25519()
        artifact = hashlib.sha256(b"artifact").digest()
        my_nonce = os.urandom(32)
        peer_nonce = os.urandom(32)
        wrong_nonce = os.urandom(32)

        sig = create_edge_signature(kp, artifact, peer_nonce, my_nonce)
        assert not verify_edge_signature(sig, artifact, wrong_nonce)

    def test_nonce_must_be_32_bytes(self):
        """Nonce must be 32 bytes."""
        kp = NodeKeyPair.generate_ed25519()
        with pytest.raises(ValueError, match="nonce must be 32 bytes"):
            EdgeSignature(kp.public, b"sig", bytes(16))


class TestEdge:
    """Tests for Edge creation and verification."""

    @pytest.fixture
    def two_parties(self):
        """Create two parties for edge testing."""
        alice = NodeKeyPair.generate_ed25519()
        bob = NodeKeyPair.generate_ed25519()
        return alice, bob

    @pytest.fixture
    def valid_edge(self, two_parties):
        """Create a valid dual-signed edge."""
        alice, bob = two_parties
        artifact = hashlib.sha256(b"shared artifact").digest()
        alice_nonce = os.urandom(32)
        bob_nonce = os.urandom(32)

        alice_sig = create_edge_signature(alice, artifact, bob_nonce, alice_nonce)
        bob_sig = create_edge_signature(bob, artifact, alice_nonce, bob_nonce)

        return Edge(
            artifact_hash=artifact,
            artifact_type="git_commit",
            parser_version=PARSER_VERSION,
            sig_a=alice_sig,
            sig_b=bob_sig,
        )

    def test_edge_creation(self, valid_edge):
        """Create a valid edge."""
        assert len(valid_edge.artifact_hash) == 32
        assert valid_edge.parser_version == PARSER_VERSION

    def test_edge_verification(self, valid_edge):
        """Edge with valid signatures passes verification."""
        valid, error = verify_edge(valid_edge)
        assert valid
        assert error is None

    def test_same_signer_rejected(self, two_parties):
        """Edge with same signer twice is rejected."""
        alice, _ = two_parties
        artifact = hashlib.sha256(b"artifact").digest()
        nonce1 = os.urandom(32)
        nonce2 = os.urandom(32)

        sig1 = create_edge_signature(alice, artifact, nonce2, nonce1)
        sig2 = create_edge_signature(alice, artifact, nonce1, nonce2)

        with pytest.raises(ValueError, match="two different nodes"):
            Edge(
                artifact_hash=artifact,
                artifact_type="git_commit",
                parser_version=PARSER_VERSION,
                sig_a=sig1,
                sig_b=sig2,
            )


class TestCanonicalEdgeHash:
    """Tests for canonical edge hash order-independence (REQUIRED)."""

    def test_edge_hash_order_independent_sig_a_b(self):
        """Edge hash is the same regardless of sig_a/sig_b order."""
        alice = NodeKeyPair.generate_ed25519()
        bob = NodeKeyPair.generate_ed25519()
        artifact = hashlib.sha256(b"artifact").digest()
        alice_nonce = os.urandom(32)
        bob_nonce = os.urandom(32)

        alice_sig = create_edge_signature(alice, artifact, bob_nonce, alice_nonce)
        bob_sig = create_edge_signature(bob, artifact, alice_nonce, bob_nonce)

        edge1 = Edge(
            artifact_hash=artifact,
            artifact_type="git_commit",
            parser_version=PARSER_VERSION,
            sig_a=alice_sig,
            sig_b=bob_sig,
        )
        edge2 = Edge(
            artifact_hash=artifact,
            artifact_type="git_commit",
            parser_version=PARSER_VERSION,
            sig_a=bob_sig,  # Swapped
            sig_b=alice_sig,  # Swapped
        )

        assert edge1.edge_hash == edge2.edge_hash

    def test_edge_hash_uses_sorted_keys(self):
        """Edge hash sorts by node_id to ensure determinism."""
        alice = NodeKeyPair.from_seed(b"alice_seed")
        bob = NodeKeyPair.from_seed(b"bob_seed")
        artifact = hashlib.sha256(b"artifact").digest()
        alice_nonce = os.urandom(32)
        bob_nonce = os.urandom(32)

        alice_sig = create_edge_signature(alice, artifact, bob_nonce, alice_nonce)
        bob_sig = create_edge_signature(bob, artifact, alice_nonce, bob_nonce)

        edge = Edge(
            artifact_hash=artifact,
            artifact_type="git_commit",
            parser_version=PARSER_VERSION,
            sig_a=alice_sig,
            sig_b=bob_sig,
        )

        sigs_sorted = sorted(
            [(alice.node_id, alice_sig.signature), (bob.node_id, bob_sig.signature)],
            key=lambda x: x[0]
        )
        expected = hashlib.sha256(
            artifact + sigs_sorted[0][1] + sigs_sorted[1][1]
        ).digest()

        assert edge.edge_hash == expected

    def test_different_artifacts_different_hash(self):
        """Different artifacts produce different edge hashes."""
        alice = NodeKeyPair.generate_ed25519()
        bob = NodeKeyPair.generate_ed25519()
        artifact1 = hashlib.sha256(b"artifact1").digest()
        artifact2 = hashlib.sha256(b"artifact2").digest()

        nonce_a = os.urandom(32)
        nonce_b = os.urandom(32)

        sig_a1 = create_edge_signature(alice, artifact1, nonce_b, nonce_a)
        sig_b1 = create_edge_signature(bob, artifact1, nonce_a, nonce_b)
        sig_a2 = create_edge_signature(alice, artifact2, nonce_b, nonce_a)
        sig_b2 = create_edge_signature(bob, artifact2, nonce_a, nonce_b)

        edge1 = Edge(artifact1, "git_commit", PARSER_VERSION, sig_a1, sig_b1)
        edge2 = Edge(artifact2, "git_commit", PARSER_VERSION, sig_a2, sig_b2)

        assert edge1.edge_hash != edge2.edge_hash


class TestEdgeNodes:
    """Tests for edge node extraction."""

    def test_nodes_returns_both_signers(self):
        """nodes property returns both signer keys."""
        alice = NodeKeyPair.generate_ed25519()
        bob = NodeKeyPair.generate_ed25519()
        artifact = hashlib.sha256(b"artifact").digest()

        sig_a = create_edge_signature(alice, artifact, os.urandom(32), os.urandom(32))
        sig_b = create_edge_signature(bob, artifact, sig_a.nonce, os.urandom(32))
        sig_a = create_edge_signature(alice, artifact, sig_b.nonce, sig_a.nonce)

        edge = Edge(artifact, "git_commit", PARSER_VERSION, sig_a, sig_b)
        nodes = edge.nodes

        assert len(nodes) == 2
        assert alice.public in nodes
        assert bob.public in nodes

    def test_nodes_canonical_order(self):
        """nodes returns in canonical (sorted by node_id) order."""
        alice = NodeKeyPair.generate_ed25519()
        bob = NodeKeyPair.generate_ed25519()
        artifact = hashlib.sha256(b"artifact").digest()

        sig_a = create_edge_signature(alice, artifact, os.urandom(32), os.urandom(32))
        sig_b = create_edge_signature(bob, artifact, sig_a.nonce, os.urandom(32))
        sig_a = create_edge_signature(alice, artifact, sig_b.nonce, sig_a.nonce)

        edge = Edge(artifact, "git_commit", PARSER_VERSION, sig_a, sig_b)
        nodes = edge.nodes

        assert nodes[0].node_id < nodes[1].node_id


class TestEdgeWireFormat:
    """Tests for edge serialization (CBOR, binary-safe)."""

    def test_wire_roundtrip(self):
        """Edge survives CBOR serialization roundtrip."""
        alice = NodeKeyPair.generate_ed25519()
        bob = NodeKeyPair.generate_ed25519()
        artifact = hashlib.sha256(b"artifact").digest()

        sig_a = create_edge_signature(alice, artifact, os.urandom(32), os.urandom(32))
        sig_b = create_edge_signature(bob, artifact, sig_a.nonce, os.urandom(32))
        sig_a = create_edge_signature(alice, artifact, sig_b.nonce, sig_a.nonce)

        edge = Edge(artifact, "git_commit", PARSER_VERSION, sig_a, sig_b)
        wire_data = edge.to_wire()
        restored = Edge.from_wire(wire_data)

        assert restored.edge_hash == edge.edge_hash
        assert restored.artifact_hash == edge.artifact_hash
        assert restored.sig_a.signature == edge.sig_a.signature
        assert restored.sig_b.signature == edge.sig_b.signature

    def test_signature_bytes_preserved(self):
        """Signature bytes are preserved exactly (no JSON corruption)."""
        alice = NodeKeyPair.generate_ed25519()
        bob = NodeKeyPair.generate_ed25519()
        artifact = hashlib.sha256(b"artifact").digest()

        sig_a = create_edge_signature(alice, artifact, os.urandom(32), os.urandom(32))
        sig_b = create_edge_signature(bob, artifact, sig_a.nonce, os.urandom(32))
        sig_a = create_edge_signature(alice, artifact, sig_b.nonce, sig_a.nonce)

        edge = Edge(artifact, "git_commit", PARSER_VERSION, sig_a, sig_b)

        for _ in range(10):
            wire_data = edge.to_wire()
            restored = Edge.from_wire(wire_data)
            assert restored.sig_a.signature == edge.sig_a.signature
            assert restored.sig_b.signature == edge.sig_b.signature
            edge = restored


class TestPendingEdge:
    """Tests for PendingEdge (edge under construction)."""

    def test_pending_edge_workflow(self):
        """Full workflow for building an edge."""
        alice = NodeKeyPair.generate_ed25519()
        bob = NodeKeyPair.generate_ed25519()
        artifact = hashlib.sha256(b"artifact").digest()

        pending = PendingEdge(artifact, "git_commit", PARSER_VERSION)
        assert not pending.is_complete()

        alice_nonce = os.urandom(32)
        bob_nonce = os.urandom(32)

        alice_sig = create_edge_signature(alice, artifact, bob_nonce, alice_nonce)
        bob_sig = create_edge_signature(bob, artifact, alice_nonce, bob_nonce)

        pending.add_initiator(alice_sig)
        assert not pending.is_complete()

        pending.add_responder(bob_sig)
        assert pending.is_complete()

        edge = pending.finalize()
        valid, _ = verify_edge(edge)
        assert valid
