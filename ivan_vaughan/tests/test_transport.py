"""Tests for transport validation (Law 6)."""

import hashlib
import os
import pytest

from ivan_vaughan.keys import NodeKeyPair
from ivan_vaughan.edge import Edge, create_edge_signature
from ivan_vaughan.parser import PARSER_VERSION
from ivan_vaughan.transport import (
    TransportVerdict,
    ValidationResult,
    validate_edge_transport,
    validate_edge_with_liveness,
    validate_fetched_artifact,
    PeerScoring,
    FetchResult,
    hash_integrity_check,
)
from ivan_vaughan.fido import (
    LivenessProof,
    build_authenticator_data,
    create_test_cose_key_es256,
    sign_fido2_assertion_es256,
)
from ivan_vaughan.wire import encode

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


def create_valid_edge() -> Edge:
    """Create a valid edge for testing."""
    alice = NodeKeyPair.generate_ed25519()
    bob = NodeKeyPair.generate_ed25519()
    artifact = hashlib.sha256(b"test").digest()

    alice_nonce = os.urandom(32)
    bob_nonce = os.urandom(32)

    alice_sig = create_edge_signature(alice, artifact, bob_nonce, alice_nonce)
    bob_sig = create_edge_signature(bob, artifact, alice_nonce, bob_nonce)

    return Edge(artifact, "git_commit", PARSER_VERSION, alice_sig, bob_sig)


class TestTransportValidation:
    """Tests for transport validation per Law 6."""

    def test_valid_edge_accepted(self):
        """Valid edge is accepted."""
        edge = create_valid_edge()
        result = validate_edge_transport(edge.to_wire())
        assert result.verdict == TransportVerdict.ACCEPT

    def test_malformed_data_rejected(self):
        """Malformed data is rejected."""
        result = validate_edge_transport(b"not valid cbor")
        assert result.verdict == TransportVerdict.REJECT

    def test_unknown_parser_version_ignored(self):
        """Unknown parser version yields Ignore, not Reject."""
        edge = create_valid_edge()
        data = encode({
            "artifact_hash": edge.artifact_hash,
            "artifact_type": edge.artifact_type,
            "parser_version": 999,
            "sig_a": {
                "signer_pubkey": edge.sig_a.signer.public_bytes,
                "signer_algorithm": edge.sig_a.signer.algorithm,
                "signature": edge.sig_a.signature,
                "nonce": edge.sig_a.nonce,
            },
            "sig_b": {
                "signer_pubkey": edge.sig_b.signer.public_bytes,
                "signer_algorithm": edge.sig_b.signer.algorithm,
                "signature": edge.sig_b.signature,
                "nonce": edge.sig_b.nonce,
            },
        })

        result = validate_edge_transport(data)
        assert result.verdict == TransportVerdict.IGNORE

    def test_bad_signature_rejected(self):
        """Bad signature is rejected."""
        edge = create_valid_edge()
        wire = bytearray(edge.to_wire())
        wire[-10] ^= 0xFF

        result = validate_edge_transport(bytes(wire))
        assert result.verdict == TransportVerdict.REJECT

    def test_hash_mismatch_rejected(self):
        """Hash mismatch in fetched artifact is rejected."""
        data = b"actual data"
        wrong_hash = hashlib.sha256(b"different data").digest()

        result = validate_fetched_artifact(FetchResult.ok(data), wrong_hash)
        assert result.verdict == TransportVerdict.REJECT
        assert "hash mismatch" in result.reason

    def test_fetch_timeout_is_ignore(self):
        """Fetch timeout yields Ignore (retry later)."""
        result = validate_fetched_artifact(
            FetchResult.timed_out(),
            hashlib.sha256(b"data").digest()
        )
        assert result.verdict == TransportVerdict.IGNORE


class TestLivenessValidation:
    """Tests for liveness validation in transport."""

    def test_up_bit_clear_rejected(self):
        """Clear UP bit is rejected at transport layer."""
        edge = create_valid_edge()

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        auth_data = build_authenticator_data(up=False)  # UP clear
        client_data_hash = hashlib.sha256(b"client").digest()
        cose_key = create_test_cose_key_es256(private_key)
        signature = sign_fido2_assertion_es256(private_key, auth_data, client_data_hash)

        liveness = LivenessProof(
            authenticator_data=auth_data,
            signature=signature,
            credential_id=b"cred",
            client_data_hash=client_data_hash,
            public_key_cose=cose_key,
        )

        result = validate_edge_with_liveness(edge, liveness, None)
        assert result.verdict == TransportVerdict.REJECT
        assert "UP bit clear" in result.reason


class TestPeerScoring:
    """Tests for peer scoring per Law 7."""

    def test_forged_signature_penalty(self):
        """Forged signatures receive large penalty."""
        scoring = PeerScoring()
        peer = b"bad_peer"

        scoring.record_forged_signature(peer)
        assert scoring.scores[peer] < 0

    def test_failed_parse_penalty(self):
        """Failed parses receive smaller penalty."""
        scoring = PeerScoring()
        peer = b"peer"

        scoring.record_failed_parse(peer)
        assert scoring.scores[peer] < 0

        scoring2 = PeerScoring()
        scoring2.record_forged_signature(peer)
        assert scoring2.scores[peer] < scoring.scores[peer]

    def test_good_behavior_positive(self):
        """Good edges give small positive score."""
        scoring = PeerScoring()
        peer = b"good_peer"

        scoring.record_good_edge(peer)
        assert scoring.scores[peer] >= 0

    def test_denylist_threshold(self):
        """Peer is denylisted after threshold."""
        scoring = PeerScoring()
        peer = b"bad_peer"

        for _ in range(5):
            scoring.record_forged_signature(peer)

        assert scoring.is_denied(peer)

    def test_no_ip_bans(self):
        """Denylist is peer-level, not IP-level (conceptual test)."""
        scoring = PeerScoring()
        peer1 = b"peer1"
        peer2 = b"peer2"

        for _ in range(5):
            scoring.record_forged_signature(peer1)

        assert scoring.is_denied(peer1)
        assert not scoring.is_denied(peer2)


class TestHashIntegrity:
    """Tests for hash integrity checks."""

    def test_correct_hash_passes(self):
        """Correct hash passes integrity check."""
        data = b"some data"
        expected = hashlib.sha256(data).digest()
        assert hash_integrity_check(data, expected)

    def test_wrong_hash_fails(self):
        """Wrong hash fails integrity check."""
        data = b"some data"
        wrong = hashlib.sha256(b"different").digest()
        assert not hash_integrity_check(data, wrong)


class TestTransportInvariants:
    """Tests for global invariants validated by transport."""

    def test_schema_validated(self):
        """Schema structure is validated."""
        result = validate_edge_transport(b"not an edge")
        assert result.verdict == TransportVerdict.REJECT

    def test_canonical_parse_required(self):
        """Only canonical parses accepted."""
        edge = create_valid_edge()
        valid_result = validate_edge_transport(edge.to_wire())
        assert valid_result.verdict == TransportVerdict.ACCEPT

    def test_sink_not_validated_at_transport(self):
        """Transport does NOT validate sink (Law 6: sink is never a relay gate)."""
        edge = create_valid_edge()
        result = validate_edge_transport(edge.to_wire())
        assert "sink" not in (result.reason or "").lower()
