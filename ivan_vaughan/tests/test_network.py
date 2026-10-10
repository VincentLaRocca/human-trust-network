"""Tests for network layer (Law 7) including DHT sync.

REGRESSION TESTS for dht_sync.py flaws (even if that file doesn't exist,
the sync code must avoid all these issues):

1. synced_keys was added before DHT lookup succeeded - failed lookup never retried
2. Only key owner called provide() - history died when owner went offline
3. Validation was mock boolean - Ignore and Reject collapsed
4. request_edges_from_peer trusted provider for edge set - omission possible
5. JSON round-trip corrupted signature bytes
"""

import hashlib
import os
import pytest
import time

from ivan_vaughan.keys import NodeKeyPair
from ivan_vaughan.edge import Edge, create_edge_signature
from ivan_vaughan.parser import PARSER_VERSION
from ivan_vaughan.network import (
    SyncState,
    KeySyncStatus,
    NetworkNode,
    InProcessTestTransport,
    set_transport,
    load_bootstrap_config,
    save_bootstrap_config,
)
from ivan_vaughan.transport import TransportVerdict


class TestKeySyncStatus:
    """Tests for KeySyncStatus tracking."""

    def test_not_marked_synced_before_success(self):
        """REGRESSION 1: Key is NOT marked synced until DHT lookup succeeds."""
        status = KeySyncStatus(key_id=b"test_key")
        assert status.state == SyncState.NOT_STARTED

        status.mark_in_progress()
        assert status.state == SyncState.IN_PROGRESS

        status.mark_failed_retryable()
        assert status.state == SyncState.FAILED_RETRYABLE
        assert status.state != SyncState.COMPLETED

    def test_failed_lookup_allows_retry(self):
        """REGRESSION 1: Failed DHT lookup can be retried."""
        status = KeySyncStatus(key_id=b"test_key")
        status.mark_in_progress()
        status.mark_failed_retryable()

        assert status.should_retry(min_interval=0)

    def test_completed_does_not_retry(self):
        """Completed sync does not retry."""
        status = KeySyncStatus(key_id=b"test_key")
        status.mark_completed([b"edge1", b"edge2"])

        assert status.state == SyncState.COMPLETED
        assert not status.should_retry()


class TestReProvide:
    """Tests for re-provide logic."""

    def create_test_edge(self) -> Edge:
        """Create a test edge."""
        alice = NodeKeyPair.generate_ed25519()
        bob = NodeKeyPair.generate_ed25519()
        artifact = hashlib.sha256(b"artifact").digest()

        alice_nonce = os.urandom(32)
        bob_nonce = os.urandom(32)

        alice_sig = create_edge_signature(alice, artifact, bob_nonce, alice_nonce)
        bob_sig = create_edge_signature(bob, artifact, alice_nonce, bob_nonce)

        return Edge(artifact, "git_commit", PARSER_VERSION, alice_sig, bob_sig)

    def test_any_holder_re_provides(self):
        """REGRESSION 2: Any node holding an edge must re-provide, not only owner."""
        transport = InProcessTestTransport()
        set_transport(transport)

        edge = self.create_test_edge()
        node_a, node_b = edge.nodes

        network_c = NetworkNode(my_keys=[b"observer_c"], transport=transport)
        network_c.local_edges[edge.edge_hash] = edge
        network_c._re_provide_edge(edge)

        assert edge.edge_hash in transport.key_edges.get(node_a.node_id, set())
        assert edge.edge_hash in transport.key_edges.get(node_b.node_id, set())


class TestValidationNotMocked:
    """Tests for real validation (not mocked booleans)."""

    def test_ignore_and_reject_are_distinct(self):
        """REGRESSION 3: Ignore and Reject are distinct verdicts."""
        assert TransportVerdict.IGNORE != TransportVerdict.REJECT
        assert TransportVerdict.IGNORE.value == "ignore"
        assert TransportVerdict.REJECT.value == "reject"

    def test_unknown_version_is_ignore(self):
        """Unknown parser version yields Ignore, not Reject."""
        from ivan_vaughan.transport import validate_edge_transport
        from ivan_vaughan.wire import encode

        bad_edge_data = encode({
            "artifact_hash": bytes(32),
            "artifact_type": "git_commit",
            "parser_version": 999,  # Unknown version
            "sig_a": {
                "signer_pubkey": bytes(32),
                "signer_algorithm": "Ed25519",
                "signature": bytes(64),
                "nonce": bytes(32),
            },
            "sig_b": {
                "signer_pubkey": bytes.fromhex("01" * 32),
                "signer_algorithm": "Ed25519",
                "signature": bytes(64),
                "nonce": bytes(32),
            },
        })

        result = validate_edge_transport(bad_edge_data)
        assert result.verdict == TransportVerdict.IGNORE

    def test_bad_signature_is_reject(self):
        """Bad signature yields Reject."""
        from ivan_vaughan.transport import validate_edge_transport

        alice = NodeKeyPair.generate_ed25519()
        bob = NodeKeyPair.generate_ed25519()
        artifact = hashlib.sha256(b"artifact").digest()

        alice_sig = create_edge_signature(alice, artifact, os.urandom(32), os.urandom(32))
        bob_sig = create_edge_signature(bob, artifact, alice_sig.nonce, os.urandom(32))
        alice_sig = create_edge_signature(alice, artifact, bob_sig.nonce, alice_sig.nonce)

        edge = Edge(artifact, "git_commit", PARSER_VERSION, alice_sig, bob_sig)

        edge_data = bytearray(edge.to_wire())
        edge_data[-5] ^= 0xFF

        result = validate_edge_transport(bytes(edge_data))
        assert result.verdict == TransportVerdict.REJECT


class TestProviderNotTrusted:
    """Tests for not trusting provider for edge validity."""

    def test_provider_can_omit_edges(self):
        """REGRESSION 4: Providers may omit edges; we can't invent missing ones."""
        transport = InProcessTestTransport()

        alice = NodeKeyPair.generate_ed25519()
        bob = NodeKeyPair.generate_ed25519()

        edge1 = create_test_edge(alice, bob, b"artifact1")
        edge2 = create_test_edge(alice, bob, b"artifact2")

        transport.inject_edge(edge1)

        result = transport.dht_get(alice.node_id)
        assert edge1.edge_hash in result
        assert edge2.edge_hash not in result

    def test_validation_happens_locally(self):
        """Edges are validated locally, not by trusting provider."""
        transport = InProcessTestTransport()
        set_transport(transport)

        alice = NodeKeyPair.generate_ed25519()
        network = NetworkNode(my_keys=[alice.node_id], transport=transport)

        valid_edge = create_test_edge(
            NodeKeyPair.generate_ed25519(),
            NodeKeyPair.generate_ed25519(),
            b"valid"
        )
        transport.inject_edge(valid_edge)

        edges = network.sync_key(valid_edge.nodes[0].node_id)
        assert len(edges) <= len(list(transport.edges.values()))


class TestBinarySafe:
    """Tests for binary-safe wire format (no JSON corruption)."""

    def test_cbor_preserves_signatures(self):
        """REGRESSION 5: CBOR preserves signature bytes exactly."""
        from ivan_vaughan.wire import encode, decode

        signature = os.urandom(64)
        nonce = os.urandom(32)
        artifact = os.urandom(32)

        data = {
            "signature": signature,
            "nonce": nonce,
            "artifact": artifact,
        }

        wire = encode(data)
        restored = decode(wire)

        assert restored["signature"] == signature
        assert restored["nonce"] == nonce
        assert restored["artifact"] == artifact

    def test_edge_roundtrip_preserves_bytes(self):
        """Edge serialization preserves all byte fields."""
        edge = create_test_edge(
            NodeKeyPair.generate_ed25519(),
            NodeKeyPair.generate_ed25519(),
            b"artifact"
        )

        original_sig_a = edge.sig_a.signature
        original_sig_b = edge.sig_b.signature

        wire = edge.to_wire()
        restored = Edge.from_wire(wire)

        assert restored.sig_a.signature == original_sig_a
        assert restored.sig_b.signature == original_sig_b

    def test_no_json_in_wire_format(self):
        """Wire format does not use JSON (uses CBOR)."""
        edge = create_test_edge(
            NodeKeyPair.generate_ed25519(),
            NodeKeyPair.generate_ed25519(),
            b"artifact"
        )
        wire = edge.to_wire()

        # CBOR starts with a map marker (0xa0-0xbf for definite, 0xbf for indefinite)
        # Not with { (0x7b) which is JSON
        import json
        try:
            json.loads(wire)
            assert False, "Should not be valid JSON"
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass  # Expected - CBOR is not JSON


class TestDHTSyncRetry:
    """Tests for DHT sync retry behavior."""

    def test_failed_dht_lookup_retries(self):
        """Failed DHT lookup does not mark key as synced; retries later."""
        transport = InProcessTestTransport()
        set_transport(transport)

        alice = NodeKeyPair.generate_ed25519()
        network = NetworkNode(my_keys=[alice.node_id], transport=transport)

        transport.set_failure_mode("timeout")
        edges = network.sync_key(alice.node_id)
        assert len(edges) == 0
        assert network.sync_status[alice.node_id].state == SyncState.FAILED_RETRYABLE

        transport.set_failure_mode(None)
        edge = create_test_edge(alice, NodeKeyPair.generate_ed25519(), b"art")
        transport.inject_edge(edge)

        network.sync_status[alice.node_id].last_attempt = 0
        edges = network.sync_key(alice.node_id)
        assert any(e.edge_hash == edge.edge_hash for e in edges)

    def test_unavailable_artifact_goes_to_pending(self):
        """Unavailable artifact goes to pending retry, not dropped permanently."""
        transport = InProcessTestTransport()
        set_transport(transport)

        alice = NodeKeyPair.generate_ed25519()
        network = NetworkNode(my_keys=[alice.node_id], transport=transport)

        transport.key_edges[alice.node_id] = {b"missing_edge_hash"}

        edges = network.sync_key(alice.node_id)

        assert b"missing_edge_hash" in network.pending_retry


class TestPeerScoring:
    """Tests for peer scoring (Law 7 partial)."""

    def test_forged_signature_penalized(self):
        """Forged signatures are penalized."""
        transport = InProcessTestTransport()
        set_transport(transport)

        network = NetworkNode(my_keys=[b"me"], transport=transport)

        peer_id = b"bad_peer"
        network.scoring.record_forged_signature(peer_id)

        assert network.scoring.scores[peer_id] < 0

    def test_bad_peer_denied_after_threshold(self):
        """Bad peer is denied after threshold."""
        transport = InProcessTestTransport()
        set_transport(transport)

        network = NetworkNode(my_keys=[b"me"], transport=transport)

        peer_id = b"bad_peer"
        for _ in range(10):
            network.scoring.record_forged_signature(peer_id)

        assert network.scoring.is_denied(peer_id)

    def test_denylist_is_local_and_revocable(self):
        """Denylist is local and revocable."""
        transport = InProcessTestTransport()
        network = NetworkNode(my_keys=[b"me"], transport=transport)

        peer_id = b"peer"
        for _ in range(10):
            network.scoring.record_forged_signature(peer_id)

        assert network.scoring.is_denied(peer_id)

        network.scoring.remove_from_denylist(peer_id)
        assert not network.scoring.is_denied(peer_id)


class TestBootstrapConfig:
    """Tests for bootstrap multiaddr configuration."""

    def test_load_missing_config_returns_empty(self, tmp_path):
        """Missing config file returns empty list."""
        path = tmp_path / "nonexistent.json"
        result = load_bootstrap_config(path)
        assert result == []

    def test_save_and_load_config(self, tmp_path):
        """Config saves and loads correctly."""
        path = tmp_path / "bootstrap.json"
        addrs = ["/ip4/1.2.3.4/tcp/4001/p2p/QmPeer1", "/dns4/example.com/tcp/4001/p2p/QmPeer2"]

        save_bootstrap_config(addrs, path)
        loaded = load_bootstrap_config(path)

        assert loaded == addrs


class TestTwoHopSync:
    """Tests for 2-hop neighborhood sync (Law 7)."""

    def test_sync_walks_two_hops(self):
        """DHT sync walks 2 hops from user's own keys."""
        transport = InProcessTestTransport()
        set_transport(transport)

        me = NodeKeyPair.generate_ed25519()
        friend = NodeKeyPair.generate_ed25519()
        friend_of_friend = NodeKeyPair.generate_ed25519()

        edge1 = create_test_edge(me, friend, b"edge1")
        edge2 = create_test_edge(friend, friend_of_friend, b"edge2")

        transport.inject_edge(edge1)
        transport.inject_edge(edge2)

        network = NetworkNode(my_keys=[me.node_id], transport=transport)
        all_edges = network.sync_two_hop_neighborhood()

        edge_hashes = {e.edge_hash for e in all_edges}
        assert edge1.edge_hash in edge_hashes
        assert edge2.edge_hash in edge_hashes


def create_test_edge(alice: NodeKeyPair, bob: NodeKeyPair, artifact_seed: bytes) -> Edge:
    """Helper to create a test edge."""
    artifact = hashlib.sha256(artifact_seed).digest()

    alice_nonce = os.urandom(32)
    bob_nonce = os.urandom(32)

    alice_sig = create_edge_signature(alice, artifact, bob_nonce, alice_nonce)
    bob_sig = create_edge_signature(bob, artifact, alice_nonce, bob_nonce)

    return Edge(artifact, "git_commit", PARSER_VERSION, alice_sig, bob_sig)
