#!/usr/bin/env python3
"""Tests for DHT sync and GossipSub validation.

Tests:
- Unknown-parser-version IGNORE
- Fetch-timeout IGNORE leaving key unsynced
- Bad-signature REJECT
- Hash-mismatch REJECT
- Binary-safe fetch path
"""

import pytest
import asyncio
import os
import hashlib

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from ivan_vaughan.dht_sync import (
    ValidationResult,
    ValidationOutcome,
    GossipValidator,
    DHTSyncer,
    SyncState,
    PeerScore,
    validate_up_bit,
)
from ivan_vaughan.edge_store import Edge, EdgeStore
from ivan_vaughan.node import Node
from ivan_vaughan.canonical_parser import KNOWN_PARSER_VERSIONS, GIT_COMMIT_PARSER_V1


class TestValidationResult:
    """Test the tripartite validation result."""
    
    def test_three_states(self):
        """Test that all three states exist."""
        assert ValidationResult.ACCEPT.value == "accept"
        assert ValidationResult.REJECT.value == "reject"
        assert ValidationResult.IGNORE.value == "ignore"


class TestGossipValidator:
    """Test GossipSub message validation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.store = EdgeStore(":memory:")
        self.validator = GossipValidator(self.store)
        self.node_a = Node.generate()
        self.node_b = Node.generate()
    
    def teardown_method(self):
        """Clean up."""
        self.store.close()
    
    def _create_valid_edge(self) -> Edge:
        """Create a valid edge with real signatures."""
        artifact_hash = hashlib.sha256(b"test artifact").digest()
        
        sig_a = self.node_a.sign(artifact_hash)
        sig_b = self.node_b.sign(artifact_hash)
        
        return Edge(
            artifact_hash=artifact_hash,
            signer_a=self.node_a.node_id.xonly,
            signer_b=self.node_b.node_id.xonly,
            signature_a=sig_a,
            signature_b=sig_b,
            parser_version=GIT_COMMIT_PARSER_V1,
        )
    
    def _verify_sig(self, key: bytes, msg: bytes, sig: bytes) -> bool:
        """Verify a signature."""
        return Node.verify(key, msg, sig, "ed25519")
    
    def test_accept_valid_edge(self):
        """Test ACCEPT for a valid edge."""
        edge = self._create_valid_edge()
        payload = edge.to_bytes()
        peer_id = os.urandom(32)
        
        outcome = self.validator.validate_edge(
            raw_payload=payload,
            peer_id=peer_id,
            verify_signature=self._verify_sig,
        )
        
        assert outcome.result == ValidationResult.ACCEPT
        assert self.store.has_edge(edge.canonical_hash)
    
    def test_ignore_unknown_parser_version(self):
        """Test IGNORE for unknown parser version.
        
        Law 6: Unknown parser version = IGNORE (no penalty, no forward).
        """
        artifact_hash = hashlib.sha256(b"test").digest()
        sig_a = self.node_a.sign(artifact_hash)
        sig_b = self.node_b.sign(artifact_hash)
        
        # Create edge with unknown parser version
        edge = Edge(
            artifact_hash=artifact_hash,
            signer_a=self.node_a.node_id.xonly,
            signer_b=self.node_b.node_id.xonly,
            signature_a=sig_a,
            signature_b=sig_b,
            parser_version="unknown_parser_v999",  # Unknown version
        )
        
        payload = edge.to_bytes()
        peer_id = os.urandom(32)
        
        outcome = self.validator.validate_edge(
            raw_payload=payload,
            peer_id=peer_id,
            verify_signature=self._verify_sig,
        )
        
        assert outcome.result == ValidationResult.IGNORE
        assert "unknown parser version" in outcome.reason
        assert outcome.peer_score_delta == 0.0  # No penalty
    
    def test_reject_bad_signature(self):
        """Test REJECT for bad signature.
        
        Law 6: REJECT on bad signature.
        """
        artifact_hash = hashlib.sha256(b"test").digest()
        
        # Create edge with bad signature
        edge = Edge(
            artifact_hash=artifact_hash,
            signer_a=self.node_a.node_id.xonly,
            signer_b=self.node_b.node_id.xonly,
            signature_a=os.urandom(64),  # Random bytes, not a valid signature
            signature_b=self.node_b.sign(artifact_hash),
            parser_version=GIT_COMMIT_PARSER_V1,
        )
        
        payload = edge.to_bytes()
        peer_id = os.urandom(32)
        
        outcome = self.validator.validate_edge(
            raw_payload=payload,
            peer_id=peer_id,
            verify_signature=self._verify_sig,
        )
        
        assert outcome.result == ValidationResult.REJECT
        assert "invalid signature" in outcome.reason
        assert outcome.peer_score_delta < 0  # Penalty applied
    
    def test_peer_denylist(self):
        """Test that bad peers get added to denylist."""
        peer_id = os.urandom(32)
        
        # Submit many bad edges to trigger denylist
        for _ in range(10):
            bad_edge = Edge(
                artifact_hash=hashlib.sha256(os.urandom(32)).digest(),
                signer_a=self.node_a.node_id.xonly,
                signer_b=self.node_b.node_id.xonly,
                signature_a=os.urandom(64),  # Bad signature
                signature_b=os.urandom(64),
                parser_version=GIT_COMMIT_PARSER_V1,
            )
            self.validator.validate_edge(
                raw_payload=bad_edge.to_bytes(),
                peer_id=peer_id,
                verify_signature=self._verify_sig,
            )
        
        # Peer should be in denylist now
        assert self.validator.is_in_denylist(peer_id)
    
    def test_binary_safe_validation(self):
        """Test that validation works with binary data.
        
        PART 4.4: Binary-safe fetch, no JSON encoding.
        """
        # Create edge with problematic bytes for JSON
        artifact_hash = b'\x00\x01\x02' + b'\xff' * 29  # Includes null and high bytes
        
        # Sign with our nodes
        sig_a = self.node_a.sign(artifact_hash)
        sig_b = self.node_b.sign(artifact_hash)
        
        edge = Edge(
            artifact_hash=artifact_hash,
            signer_a=self.node_a.node_id.xonly,
            signer_b=self.node_b.node_id.xonly,
            signature_a=sig_a,
            signature_b=sig_b,
            parser_version=GIT_COMMIT_PARSER_V1,
        )
        
        # Serialize and validate - should work without JSON encoding
        payload = edge.to_bytes()
        peer_id = os.urandom(32)
        
        outcome = self.validator.validate_edge(
            raw_payload=payload,
            peer_id=peer_id,
            verify_signature=self._verify_sig,
        )
        
        assert outcome.result == ValidationResult.ACCEPT


class TestDHTSyncer:
    """Test DHT synchronization."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.store = EdgeStore(":memory:")
        self.node = Node.generate()
        self.validator = GossipValidator(self.store)
        self.syncer = DHTSyncer(self.store, self.node, self.validator)
    
    def teardown_method(self):
        """Clean up."""
        self.store.close()
    
    @pytest.mark.asyncio
    async def test_sync_key_success(self):
        """Test successful key sync."""
        key = self.node.node_id.xonly
        
        # Create a valid edge for this key
        other_node = Node.generate()
        artifact_hash = hashlib.sha256(b"test").digest()
        sig_a = self.node.sign(artifact_hash)
        sig_b = other_node.sign(artifact_hash)
        
        edge = Edge(
            artifact_hash=artifact_hash,
            signer_a=self.node.node_id.xonly,
            signer_b=other_node.node_id.xonly,
            signature_a=sig_a,
            signature_b=sig_b,
            parser_version=GIT_COMMIT_PARSER_V1,
        )
        
        # Mock DHT fetch
        async def fetch(k: bytes) -> list[bytes]:
            if k == key:
                return [edge.to_bytes()]
            return []
        
        def verify(k: bytes, msg: bytes, sig: bytes) -> bool:
            return Node.verify(k, msg, sig, "ed25519")
        
        result = await self.syncer.sync_key(key, fetch, verify)
        
        assert result is True
        assert self.syncer.is_key_synced(key)
    
    @pytest.mark.asyncio
    async def test_sync_key_with_ignore_not_synced(self):
        """Test that IGNORE results leave key unsynced.
        
        PART 4.2: Key synced only if all payloads resolve to ACCEPT or REJECT.
        """
        key = self.node.node_id.xonly
        
        # Create edge with unknown parser version
        other_node = Node.generate()
        artifact_hash = hashlib.sha256(b"test").digest()
        
        edge = Edge(
            artifact_hash=artifact_hash,
            signer_a=self.node.node_id.xonly,
            signer_b=other_node.node_id.xonly,
            signature_a=self.node.sign(artifact_hash),
            signature_b=other_node.sign(artifact_hash),
            parser_version="unknown_version",  # Will cause IGNORE
        )
        
        async def fetch(k: bytes) -> list[bytes]:
            return [edge.to_bytes()]
        
        def verify(k: bytes, msg: bytes, sig: bytes) -> bool:
            return Node.verify(k, msg, sig, "ed25519")
        
        result = await self.syncer.sync_key(key, fetch, verify)
        
        # Should NOT be synced because of IGNORE
        assert result is False
        assert not self.syncer.is_key_synced(key)
    
    @pytest.mark.asyncio
    async def test_fetch_timeout_leaves_unsynced(self):
        """Test that fetch timeout leaves key unsynced.
        
        Law 6: Fetch timeout = IGNORE.
        PART 4.2: Key stays unsynced for retry.
        """
        key = self.node.node_id.xonly
        
        async def fetch_timeout(k: bytes) -> list[bytes]:
            raise asyncio.TimeoutError()
        
        def verify(k: bytes, msg: bytes, sig: bytes) -> bool:
            return True
        
        result = await self.syncer.sync_key(key, fetch_timeout, verify)
        
        assert result is False
        assert not self.syncer.is_key_synced(key)


class TestSyncState:
    """Test sync state tracking."""
    
    def test_is_synced_no_ignore(self):
        """Test is_synced with no IGNORE results."""
        state = SyncState(key=b'\x01' * 32)
        state.record_result(ValidationResult.ACCEPT)
        state.record_result(ValidationResult.ACCEPT)
        state.record_result(ValidationResult.REJECT)
        state.completed = True
        
        assert state.is_synced is True
    
    def test_is_synced_with_ignore(self):
        """Test is_synced with IGNORE results."""
        state = SyncState(key=b'\x01' * 32)
        state.record_result(ValidationResult.ACCEPT)
        state.record_result(ValidationResult.IGNORE)  # This prevents sync
        state.completed = True
        
        assert state.is_synced is False
    
    def test_not_synced_if_not_completed(self):
        """Test that incomplete sync is not synced."""
        state = SyncState(key=b'\x01' * 32)
        state.record_result(ValidationResult.ACCEPT)
        # Not completed
        
        assert state.is_synced is False


class TestPeerScore:
    """Test peer scoring."""
    
    def test_penalty_for_forged_signature(self):
        """Test penalty for forged signature.
        
        Law 7: Peer scoring only for forged signatures and failed parses.
        """
        score = PeerScore(peer_id=b'\x01' * 32)
        initial = score.score
        
        score.penalize_forged_signature()
        
        assert score.score < initial
        assert score.forged_signatures == 1
    
    def test_penalty_for_failed_parse(self):
        """Test penalty for failed parse."""
        score = PeerScore(peer_id=b'\x01' * 32)
        initial = score.score
        
        score.penalize_failed_parse()
        
        assert score.score < initial
        assert score.failed_parses == 1
    
    def test_ban_after_many_penalties(self):
        """Test that peer gets banned after many penalties."""
        score = PeerScore(peer_id=b'\x01' * 32)
        
        # Apply many penalties
        for _ in range(10):
            score.penalize_forged_signature()
        
        assert score.is_banned() is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
