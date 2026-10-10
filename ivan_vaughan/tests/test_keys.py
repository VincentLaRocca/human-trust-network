"""Tests for node key management."""

import pytest
from ivan_vaughan.keys import (
    NodeKey,
    NodeKeyPair,
    verify_signature,
    Nickname,
)


class TestNodeKey:
    """Tests for NodeKey (Law 1: a node is a keypair)."""

    def test_ed25519_key_creation(self):
        """Ed25519 key must be 32 bytes."""
        key = NodeKey(bytes(32), "Ed25519")
        assert len(key.public_bytes) == 32
        assert key.algorithm == "Ed25519"

    def test_ed25519_invalid_length(self):
        """Ed25519 key with wrong length raises."""
        with pytest.raises(ValueError):
            NodeKey(bytes(31), "Ed25519")

    def test_es256_key_creation(self):
        """ES256 key must be 33 or 65 bytes."""
        key33 = NodeKey(bytes(33), "ES256")
        key65 = NodeKey(bytes(65), "ES256")
        assert len(key33.public_bytes) == 33
        assert len(key65.public_bytes) == 65

    def test_node_id_is_content_addressed(self):
        """Node ID is SHA-256 of algorithm || public_bytes."""
        key = NodeKey(bytes(32), "Ed25519")
        import hashlib
        expected = hashlib.sha256(b"Ed25519" + bytes(32)).digest()
        assert key.node_id == expected

    def test_different_keys_different_ids(self):
        """Different keys have different node IDs."""
        key1 = NodeKeyPair.generate_ed25519()
        key2 = NodeKeyPair.generate_ed25519()
        assert key1.node_id != key2.node_id

    def test_key_equality_by_node_id(self):
        """Keys are equal if their node IDs match."""
        key1 = NodeKeyPair.from_seed(b"test_seed")
        key2 = NodeKeyPair.from_seed(b"test_seed")
        assert key1.public == key2.public


class TestNodeKeyPair:
    """Tests for NodeKeyPair signing."""

    def test_generate_ed25519(self):
        """Generate Ed25519 keypair."""
        kp = NodeKeyPair.generate_ed25519()
        assert kp.public.algorithm == "Ed25519"
        assert len(kp.public.public_bytes) == 32

    def test_generate_es256(self):
        """Generate ES256 keypair."""
        kp = NodeKeyPair.generate_es256()
        assert kp.public.algorithm == "ES256"
        assert len(kp.public.public_bytes) in (33, 65)

    def test_from_seed_deterministic(self):
        """Same seed produces same key."""
        kp1 = NodeKeyPair.from_seed(b"deterministic_seed")
        kp2 = NodeKeyPair.from_seed(b"deterministic_seed")
        assert kp1.node_id == kp2.node_id

    def test_sign_and_verify_ed25519(self):
        """Sign and verify with Ed25519."""
        kp = NodeKeyPair.generate_ed25519()
        message = b"test message"
        signature = kp.sign(message)
        assert verify_signature(kp.public, message, signature)

    def test_sign_and_verify_es256(self):
        """Sign and verify with ES256."""
        kp = NodeKeyPair.generate_es256()
        message = b"test message"
        signature = kp.sign(message)
        assert verify_signature(kp.public, message, signature)

    def test_wrong_message_fails_verification(self):
        """Wrong message fails verification."""
        kp = NodeKeyPair.generate_ed25519()
        signature = kp.sign(b"original message")
        assert not verify_signature(kp.public, b"different message", signature)

    def test_wrong_key_fails_verification(self):
        """Wrong key fails verification."""
        kp1 = NodeKeyPair.generate_ed25519()
        kp2 = NodeKeyPair.generate_ed25519()
        signature = kp1.sign(b"message")
        assert not verify_signature(kp2.public, b"message", signature)

    def test_tampered_signature_fails(self):
        """Tampered signature fails verification."""
        kp = NodeKeyPair.generate_ed25519()
        signature = bytearray(kp.sign(b"message"))
        signature[0] ^= 0xFF  # Flip bits
        assert not verify_signature(kp.public, b"message", bytes(signature))


class TestNickname:
    """Tests for Nickname (UI cache with zero weight)."""

    def test_nickname_has_zero_protocol_weight(self):
        """Nicknames are UI-only, no protocol weight."""
        kp = NodeKeyPair.generate_ed25519()
        nick = Nickname(kp.node_id, "Alice")
        assert nick.label == "Alice"
        assert nick.node_id == kp.node_id
        # Nickname has no weight attribute - it's purely UI

    def test_nickname_repr(self):
        """Nickname repr is readable."""
        nick = Nickname(bytes(32), "Bob")
        assert "Bob" in repr(nick)
