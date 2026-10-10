#!/usr/bin/env python3
"""Tests for light client sink verification.

Tests:
- Merkle proof verification
- Weight 0 until verified
- Structural dependency validation (not fee/OP_RETURN/flag)
"""

import pytest
import hashlib

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from ivan_vaughan.light_client import (
    LightClient,
    Lens,
    MerkleProof,
    PatriciaProof,
    StructuralDependency,
    Endpoint,
    EndpointConfig,
    SinkError,
    compute_merkle_root,
    create_merkle_proof,
    is_structural_dependency,
)


class TestMerkleProof:
    """Test Merkle proof verification."""
    
    def test_single_leaf_proof(self):
        """Test proof for a single-leaf tree."""
        leaf = hashlib.sha256(b"leaf").digest()
        leaves = [leaf]
        
        proof = create_merkle_proof(leaves, 0)
        
        assert proof.verify()
    
    def test_multi_leaf_proof(self):
        """Test proof for multi-leaf tree."""
        leaves = [hashlib.sha256(f"leaf{i}".encode()).digest() for i in range(4)]
        
        for i in range(4):
            proof = create_merkle_proof(leaves, i)
            assert proof.verify(), f"Proof failed for leaf {i}"
    
    def test_invalid_proof_fails(self):
        """Test that invalid proofs fail verification."""
        leaf = hashlib.sha256(b"leaf").digest()
        wrong_root = hashlib.sha256(b"wrong").digest()
        
        proof = MerkleProof(
            leaf=leaf,
            proof=(),
            root=wrong_root,  # Wrong root
        )
        
        assert not proof.verify()
    
    def test_tampered_leaf_fails(self):
        """Test that tampered leaf fails verification."""
        leaves = [hashlib.sha256(f"leaf{i}".encode()).digest() for i in range(4)]
        proof = create_merkle_proof(leaves, 1)
        
        # Create proof with wrong leaf
        tampered = MerkleProof(
            leaf=hashlib.sha256(b"tampered").digest(),
            proof=proof.proof,
            root=proof.root,
        )
        
        assert not tampered.verify()


class TestStructuralDependency:
    """Test structural dependency validation."""
    
    def test_build_dependency_allowed(self):
        """Test that build dependency is structural."""
        dep = StructuralDependency(
            artifact_hash=hashlib.sha256(b"artifact").digest(),
            dependency_type="build",
        )
        
        assert dep.dependency_type == "build"
    
    def test_call_dependency_allowed(self):
        """Test that call dependency is structural."""
        dep = StructuralDependency(
            artifact_hash=hashlib.sha256(b"artifact").digest(),
            dependency_type="call",
        )
        
        assert dep.dependency_type == "call"
    
    def test_fee_dependency_rejected(self):
        """Test that fee is NOT a structural dependency.
        
        Law 3: A fee is not a sink.
        """
        with pytest.raises(SinkError, match="not a structural dependency"):
            StructuralDependency(
                artifact_hash=hashlib.sha256(b"artifact").digest(),
                dependency_type="fee",
            )
    
    def test_op_return_dependency_rejected(self):
        """Test that OP_RETURN is NOT a structural dependency.
        
        Law 3: An OP_RETURN is not a sink.
        """
        with pytest.raises(SinkError, match="not a structural dependency"):
            StructuralDependency(
                artifact_hash=hashlib.sha256(b"artifact").digest(),
                dependency_type="op_return",
            )
    
    def test_flag_dependency_rejected(self):
        """Test that payload flag is NOT a structural dependency.
        
        Law 3: A payload flag is not a sink.
        """
        with pytest.raises(SinkError, match="not a structural dependency"):
            StructuralDependency(
                artifact_hash=hashlib.sha256(b"artifact").digest(),
                dependency_type="flag",
            )


class TestIsStructuralDependency:
    """Test the is_structural_dependency helper."""
    
    def test_structural_types(self):
        """Test that structural types are recognized."""
        assert is_structural_dependency("build") is True
        assert is_structural_dependency("call") is True
        assert is_structural_dependency("import") is True
    
    def test_non_structural_types(self):
        """Test that non-structural types are rejected."""
        assert is_structural_dependency("fee") is False
        assert is_structural_dependency("op_return") is False
        assert is_structural_dependency("flag") is False
        assert is_structural_dependency("metadata") is False


class TestLightClient:
    """Test the LightClient class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.client = LightClient()
    
    def test_weight_zero_until_verified(self):
        """Test that weight is zero until verified.
        
        Law 3: Weight is zero until the user's own lens verifies.
        """
        artifact_hash = hashlib.sha256(b"artifact").digest()
        
        # Before verification
        weight = self.client.get_weight(artifact_hash)
        assert weight == 0.0
    
    def test_weight_after_verification(self):
        """Test that weight is positive after verification."""
        # Create a simple proof
        leaves = [hashlib.sha256(b"artifact").digest()]
        proof = create_merkle_proof(leaves, 0)
        
        dep = StructuralDependency(
            artifact_hash=leaves[0],
            dependency_type="build",
            proof=proof,
        )
        
        result = self.client.verify_structural_dependency(dep)
        
        assert result is True
        assert self.client.get_weight(leaves[0]) > 0.0
    
    def test_verify_merkle_proof(self):
        """Test Merkle proof verification via LightClient."""
        leaves = [hashlib.sha256(f"leaf{i}".encode()).digest() for i in range(8)]
        proof = create_merkle_proof(leaves, 3)
        
        assert self.client.verify_merkle_proof(proof)
    
    def test_is_verified_tracking(self):
        """Test that verified artifacts are tracked."""
        leaves = [hashlib.sha256(b"artifact").digest()]
        proof = create_merkle_proof(leaves, 0)
        
        dep = StructuralDependency(
            artifact_hash=leaves[0],
            dependency_type="build",
            proof=proof,
        )
        
        assert not self.client.is_verified(leaves[0])
        
        self.client.verify_structural_dependency(dep)
        
        assert self.client.is_verified(leaves[0])
    
    def test_clear_verification(self):
        """Test clearing verification."""
        leaves = [hashlib.sha256(b"artifact").digest()]
        proof = create_merkle_proof(leaves, 0)
        
        dep = StructuralDependency(
            artifact_hash=leaves[0],
            dependency_type="build",
            proof=proof,
        )
        
        self.client.verify_structural_dependency(dep)
        assert self.client.is_verified(leaves[0])
        
        self.client.clear_verification(leaves[0])
        assert not self.client.is_verified(leaves[0])


class TestEndpointConfig:
    """Test endpoint configuration."""
    
    def test_user_configurable(self):
        """Test that endpoints are user-configurable.
        
        Law: Not a shipped list of RPC providers.
        """
        config = EndpointConfig()
        
        # User adds their own endpoint
        config.add_endpoint(Endpoint(
            url="https://my.rpc.example.com",
            chain_id=1,
        ))
        
        assert len(config.endpoints) == 1
        assert config.endpoints[0].url == "https://my.rpc.example.com"
    
    def test_remove_endpoint(self):
        """Test removing an endpoint."""
        config = EndpointConfig()
        config.add_endpoint(Endpoint(url="https://rpc1.example.com"))
        config.add_endpoint(Endpoint(url="https://rpc2.example.com"))
        
        config.remove_endpoint("https://rpc1.example.com")
        
        assert len(config.endpoints) == 1
        assert config.endpoints[0].url == "https://rpc2.example.com"
    
    def test_filter_by_chain(self):
        """Test filtering endpoints by chain."""
        config = EndpointConfig()
        config.add_endpoint(Endpoint(url="https://eth.example.com", chain_id=1))
        config.add_endpoint(Endpoint(url="https://polygon.example.com", chain_id=137))
        
        eth_endpoints = config.get_endpoints(chain_id=1)
        
        assert len(eth_endpoints) == 1
        assert eth_endpoints[0].chain_id == 1
    
    def test_endpoint_requires_url(self):
        """Test that endpoint requires URL."""
        with pytest.raises(SinkError, match="URL required"):
            Endpoint(url="")


class TestLens:
    """Test the user's lens for scoring."""
    
    def test_score_with_dependency(self):
        """Test scoring with a verified dependency."""
        client = LightClient()
        lens = Lens(client)
        
        leaves = [hashlib.sha256(b"artifact").digest()]
        proof = create_merkle_proof(leaves, 0)
        
        dep = StructuralDependency(
            artifact_hash=leaves[0],
            dependency_type="build",
            proof=proof,
        )
        
        score = lens.score(leaves[0], dep)
        
        assert score > 0.0
    
    def test_score_unverified(self):
        """Test scoring without verification returns 0."""
        client = LightClient()
        lens = Lens(client)
        
        artifact_hash = hashlib.sha256(b"artifact").digest()
        
        score = lens.score(artifact_hash)
        
        assert score == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
