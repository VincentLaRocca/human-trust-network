#!/usr/bin/env python3
"""Tests for edge storage and canonical hash computation.

Tests:
- Canonical edge hash order-independence
- Weight 0 on landing
- Hash-mismatch detection
"""

import pytest
import os
import hashlib

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from ivan_vaughan.edge_store import (
    Edge,
    EdgeStore,
    StoredEdge,
    EdgeStatus,
    EdgeError,
    canonical_edge_hash,
)
from ivan_vaughan.node import Node


class TestCanonicalEdgeHash:
    """Test canonical edge hash computation."""
    
    def test_order_independence(self):
        """Test that canonical hash is order-independent.
        
        Sort the two signatures by signer keys before hashing.
        """
        artifact_hash = hashlib.sha256(b"test artifact").digest()
        
        # Create two signers
        signer_a = bytes.fromhex('01' * 32)
        signer_b = bytes.fromhex('02' * 32)
        
        sig_a = os.urandom(64)
        sig_b = os.urandom(64)
        
        # Hash in both orders - should be the same
        hash1 = canonical_edge_hash(artifact_hash, signer_a, signer_b, sig_a, sig_b)
        hash2 = canonical_edge_hash(artifact_hash, signer_b, signer_a, sig_b, sig_a)
        
        assert hash1 == hash2
    
    def test_different_artifacts_different_hash(self):
        """Test that different artifacts produce different hashes."""
        artifact1 = hashlib.sha256(b"artifact 1").digest()
        artifact2 = hashlib.sha256(b"artifact 2").digest()
        
        signer_a = bytes.fromhex('01' * 32)
        signer_b = bytes.fromhex('02' * 32)
        sig_a = os.urandom(64)
        sig_b = os.urandom(64)
        
        hash1 = canonical_edge_hash(artifact1, signer_a, signer_b, sig_a, sig_b)
        hash2 = canonical_edge_hash(artifact2, signer_a, signer_b, sig_a, sig_b)
        
        assert hash1 != hash2
    
    def test_edge_canonical_hash_matches(self):
        """Test that Edge.canonical_hash matches standalone function."""
        artifact_hash = hashlib.sha256(b"test").digest()
        signer_a = bytes.fromhex('01' * 32)
        signer_b = bytes.fromhex('02' * 32)
        sig_a = os.urandom(64)
        sig_b = os.urandom(64)
        
        edge = Edge(
            artifact_hash=artifact_hash,
            signer_a=signer_a,
            signer_b=signer_b,
            signature_a=sig_a,
            signature_b=sig_b,
            parser_version="git_commit_v1",
        )
        
        expected = canonical_edge_hash(artifact_hash, signer_a, signer_b, sig_a, sig_b)
        
        assert edge.canonical_hash == expected


class TestEdgeStore:
    """Test edge store operations."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.store = EdgeStore(":memory:")
    
    def teardown_method(self):
        """Clean up."""
        self.store.close()
    
    def _create_edge(self) -> Edge:
        """Create a test edge."""
        return Edge(
            artifact_hash=hashlib.sha256(b"test artifact").digest(),
            signer_a=bytes.fromhex('01' * 32),
            signer_b=bytes.fromhex('02' * 32),
            signature_a=os.urandom(64),
            signature_b=os.urandom(64),
            parser_version="git_commit_v1",
            roles=("repo:commit_author",),
        )
    
    def test_weight_zero_on_landing(self):
        """Test that edges land with weight 0.
        
        Law 3: Weight is zero until the user's own lens verifies.
        """
        edge = self._create_edge()
        
        stored = self.store.store(edge)
        
        assert stored.weight == 0.0
        assert stored.status == EdgeStatus.PENDING
    
    def test_store_and_retrieve(self):
        """Test storing and retrieving an edge."""
        edge = self._create_edge()
        
        self.store.store(edge)
        retrieved = self.store.get(edge.canonical_hash)
        
        assert retrieved is not None
        assert retrieved.edge.artifact_hash == edge.artifact_hash
        assert retrieved.edge.signer_a == edge.signer_a
        assert retrieved.edge.signer_b == edge.signer_b
        assert retrieved.weight == 0.0
    
    def test_duplicate_store_idempotent(self):
        """Test that storing the same edge twice is idempotent."""
        edge = self._create_edge()
        
        self.store.store(edge)
        self.store.store(edge)  # Should not raise
        
        retrieved = self.store.get(edge.canonical_hash)
        assert retrieved is not None
    
    def test_edges_for_signer(self):
        """Test finding edges by signer."""
        edge = self._create_edge()
        self.store.store(edge)
        
        edges_a = list(self.store.edges_for_signer(edge.signer_a))
        edges_b = list(self.store.edges_for_signer(edge.signer_b))
        
        assert len(edges_a) == 1
        assert len(edges_b) == 1
        assert edges_a[0].edge.canonical_hash == edge.canonical_hash
    
    def test_update_weight(self):
        """Test updating edge weight after lens scoring."""
        edge = self._create_edge()
        self.store.store(edge)
        
        self.store.update_weight(edge.canonical_hash, 0.8, EdgeStatus.VALID)
        
        retrieved = self.store.get(edge.canonical_hash)
        assert retrieved is not None
        assert retrieved.weight == 0.8
        assert retrieved.status == EdgeStatus.VALID
        assert retrieved.scored_at is not None
    
    def test_pending_edges(self):
        """Test listing pending (unscored) edges."""
        edge = self._create_edge()
        self.store.store(edge)
        
        pending = list(self.store.pending_edges())
        
        assert len(pending) == 1
        assert pending[0].status == EdgeStatus.PENDING


class TestEdgeSerialization:
    """Test edge serialization for transport."""
    
    def test_round_trip(self):
        """Test serialization round-trip."""
        edge = Edge(
            artifact_hash=hashlib.sha256(b"test").digest(),
            signer_a=bytes.fromhex('01' * 32),
            signer_b=bytes.fromhex('02' * 32),
            signature_a=os.urandom(64),
            signature_b=os.urandom(64),
            parser_version="git_commit_v1",
            roles=("repo:commit_author", "repo:reviewer"),
        )
        
        serialized = edge.to_bytes()
        deserialized = Edge.from_bytes(serialized)
        
        assert deserialized.artifact_hash == edge.artifact_hash
        assert deserialized.signer_a == edge.signer_a
        assert deserialized.signer_b == edge.signer_b
        assert deserialized.signature_a == edge.signature_a
        assert deserialized.signature_b == edge.signature_b
        assert deserialized.parser_version == edge.parser_version
        assert deserialized.roles == edge.roles
    
    def test_binary_safe(self):
        """Test that serialization is binary-safe.
        
        PART 4.4: Binary-safe fetch, no JSON encoding.
        """
        # Include bytes that would be problematic for JSON
        edge = Edge(
            artifact_hash=b'\x00' * 32,  # Null bytes
            signer_a=b'\xff' * 32,  # High bytes
            signer_b=b'\x7f' * 32,
            signature_a=bytes(range(64)),  # All byte values 0-63
            signature_b=bytes(range(64, 128)),  # All byte values 64-127
            parser_version="git_commit_v1",
        )
        
        serialized = edge.to_bytes()
        deserialized = Edge.from_bytes(serialized)
        
        assert deserialized.artifact_hash == edge.artifact_hash
        assert deserialized.signature_a == edge.signature_a


class TestEdgeValidation:
    """Test edge validation rules."""
    
    def test_reject_self_referential(self):
        """Test that self-referential edges are rejected."""
        signer = bytes.fromhex('01' * 32)
        
        with pytest.raises(EdgeError, match="self-referential"):
            Edge(
                artifact_hash=hashlib.sha256(b"test").digest(),
                signer_a=signer,
                signer_b=signer,  # Same as signer_a
                signature_a=os.urandom(64),
                signature_b=os.urandom(64),
                parser_version="git_commit_v1",
            )
    
    def test_reject_wrong_key_length(self):
        """Test that wrong key lengths are rejected."""
        with pytest.raises(EdgeError, match="32-byte"):
            Edge(
                artifact_hash=hashlib.sha256(b"test").digest(),
                signer_a=bytes.fromhex('01' * 33),  # 33 bytes, not 32
                signer_b=bytes.fromhex('02' * 32),
                signature_a=os.urandom(64),
                signature_b=os.urandom(64),
                parser_version="git_commit_v1",
            )
    
    def test_reject_wrong_hash_length(self):
        """Test that wrong artifact hash length is rejected."""
        with pytest.raises(EdgeError, match="32 bytes"):
            Edge(
                artifact_hash=b"short",  # Not 32 bytes
                signer_a=bytes.fromhex('01' * 32),
                signer_b=bytes.fromhex('02' * 32),
                signature_a=os.urandom(64),
                signature_b=os.urandom(64),
                parser_version="git_commit_v1",
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
