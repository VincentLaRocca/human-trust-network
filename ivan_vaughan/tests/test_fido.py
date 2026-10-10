"""Tests for FIDO2/CTAP2 liveness (Law 5).

Uses real crypto fixtures with python-fido2.
Includes negative tests: UP clear, wrong challenge, wrong nonce owner,
tampered authData, bad signature.
"""

import hashlib
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.backends import default_backend

from ivan_vaughan.fido import (
    STATIC_RP_ID,
    RP_ID_HASH,
    UP_FLAG,
    LivenessChallenge,
    LivenessProof,
    generate_nonce,
    parse_authenticator_data,
    check_up_bit,
    check_rp_id_hash,
    verify_fido2_signature,
    verify_liveness,
    build_authenticator_data,
    create_test_cose_key_es256,
    create_test_cose_key_eddsa,
    sign_fido2_assertion_es256,
    sign_fido2_assertion_eddsa,
)


class TestLivenessChallenge:
    """Tests for challenge generation."""

    def test_challenge_format(self):
        """Challenge = SHA-256(peer_key || artifact_hash || peer_nonce)."""
        peer_key = bytes(32)
        artifact_hash = hashlib.sha256(b"artifact").digest()
        peer_nonce = generate_nonce()

        challenge = LivenessChallenge(peer_key, artifact_hash, peer_nonce)
        expected = hashlib.sha256(peer_key + artifact_hash + peer_nonce).digest()
        assert challenge.challenge_bytes == expected

    def test_nonce_must_be_32_bytes(self):
        """Nonce must be exactly 32 bytes."""
        with pytest.raises(ValueError, match="peer_nonce must be 32 bytes"):
            LivenessChallenge(bytes(32), bytes(32), bytes(16))

    def test_artifact_hash_must_be_32_bytes(self):
        """Artifact hash must be exactly 32 bytes."""
        with pytest.raises(ValueError, match="artifact_hash must be 32 bytes"):
            LivenessChallenge(bytes(32), bytes(16), bytes(32))


class TestAuthenticatorDataParsing:
    """Tests for REAL authenticatorData parsing."""

    def test_build_valid_auth_data(self):
        """Build valid authenticatorData with UP set."""
        auth_data = build_authenticator_data(up=True)
        assert len(auth_data) == 37
        assert check_up_bit(auth_data)
        assert check_rp_id_hash(auth_data)

    def test_rp_id_hash_correct(self):
        """RP ID hash is correct for static RP ID."""
        auth_data = build_authenticator_data()
        expected_rp_hash = hashlib.sha256(STATIC_RP_ID.encode()).digest()
        assert auth_data[:32] == expected_rp_hash

    def test_up_bit_set(self):
        """UP bit is set when requested."""
        auth_data = build_authenticator_data(up=True)
        flags = auth_data[32]
        assert flags & UP_FLAG

    def test_up_bit_clear(self):
        """UP bit is clear when not requested."""
        auth_data = build_authenticator_data(up=False)
        assert not check_up_bit(auth_data)

    def test_parse_with_python_fido2(self):
        """Real parsing with python-fido2 library."""
        auth_data = build_authenticator_data(up=True, sign_count=42)
        parsed = parse_authenticator_data(auth_data)
        assert parsed.rp_id_hash == RP_ID_HASH
        assert parsed.is_user_present()
        assert parsed.counter == 42


class TestES256Signatures:
    """Tests for FIDO2 ES256 (P-256 ECDSA) signatures."""

    @pytest.fixture
    def es256_key(self):
        """Generate ES256 test key."""
        return ec.generate_private_key(ec.SECP256R1(), default_backend())

    def test_valid_es256_signature(self, es256_key):
        """Valid ES256 signature passes verification."""
        auth_data = build_authenticator_data(up=True)
        client_data_hash = hashlib.sha256(b"client data").digest()
        cose_key = create_test_cose_key_es256(es256_key)
        signature = sign_fido2_assertion_es256(es256_key, auth_data, client_data_hash)

        assert verify_fido2_signature(cose_key, auth_data, client_data_hash, signature)

    def test_wrong_client_data_hash_fails(self, es256_key):
        """Wrong client data hash fails verification."""
        auth_data = build_authenticator_data(up=True)
        client_data_hash = hashlib.sha256(b"client data").digest()
        wrong_hash = hashlib.sha256(b"wrong data").digest()
        cose_key = create_test_cose_key_es256(es256_key)
        signature = sign_fido2_assertion_es256(es256_key, auth_data, client_data_hash)

        assert not verify_fido2_signature(cose_key, auth_data, wrong_hash, signature)

    def test_tampered_auth_data_fails(self, es256_key):
        """Tampered authenticatorData fails verification."""
        auth_data = build_authenticator_data(up=True)
        client_data_hash = hashlib.sha256(b"client data").digest()
        cose_key = create_test_cose_key_es256(es256_key)
        signature = sign_fido2_assertion_es256(es256_key, auth_data, client_data_hash)

        tampered = bytearray(auth_data)
        tampered[35] ^= 0xFF
        assert not verify_fido2_signature(cose_key, bytes(tampered), client_data_hash, signature)

    def test_bad_signature_fails(self, es256_key):
        """Corrupted signature fails verification."""
        auth_data = build_authenticator_data(up=True)
        client_data_hash = hashlib.sha256(b"client data").digest()
        cose_key = create_test_cose_key_es256(es256_key)
        signature = bytearray(sign_fido2_assertion_es256(es256_key, auth_data, client_data_hash))
        signature[0] ^= 0xFF

        assert not verify_fido2_signature(cose_key, auth_data, client_data_hash, bytes(signature))


class TestEdDSASignatures:
    """Tests for FIDO2 EdDSA (Ed25519) signatures."""

    @pytest.fixture
    def eddsa_key(self):
        """Generate EdDSA test key."""
        return ed25519.Ed25519PrivateKey.generate()

    def test_valid_eddsa_signature(self, eddsa_key):
        """Valid EdDSA signature passes verification."""
        auth_data = build_authenticator_data(up=True)
        client_data_hash = hashlib.sha256(b"client data").digest()
        cose_key = create_test_cose_key_eddsa(eddsa_key)
        signature = sign_fido2_assertion_eddsa(eddsa_key, auth_data, client_data_hash)

        assert verify_fido2_signature(cose_key, auth_data, client_data_hash, signature)

    def test_wrong_key_fails(self, eddsa_key):
        """Wrong key fails verification."""
        other_key = ed25519.Ed25519PrivateKey.generate()
        auth_data = build_authenticator_data(up=True)
        client_data_hash = hashlib.sha256(b"client data").digest()
        cose_key = create_test_cose_key_eddsa(other_key)  # Wrong key
        signature = sign_fido2_assertion_eddsa(eddsa_key, auth_data, client_data_hash)

        assert not verify_fido2_signature(cose_key, auth_data, client_data_hash, signature)


class TestLivenessVerification:
    """Full liveness verification tests including negative cases."""

    @pytest.fixture
    def valid_proof_es256(self):
        """Create a valid ES256 liveness proof."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        auth_data = build_authenticator_data(up=True)
        client_data_hash = hashlib.sha256(b"client data").digest()
        cose_key = create_test_cose_key_es256(private_key)
        signature = sign_fido2_assertion_es256(private_key, auth_data, client_data_hash)

        return LivenessProof(
            authenticator_data=auth_data,
            signature=signature,
            credential_id=b"cred_id",
            client_data_hash=client_data_hash,
            public_key_cose=cose_key,
        )

    def test_valid_liveness_proof(self, valid_proof_es256):
        """Valid proof passes all checks."""
        challenge = LivenessChallenge(bytes(32), bytes(32), bytes(32))
        result = verify_liveness(valid_proof_es256, challenge)

        assert result.valid
        assert result.up_set
        assert result.rp_id_valid
        assert result.signature_valid

    def test_up_bit_clear_rejected(self):
        """NEGATIVE: UP bit clear is rejected (Law 5 requirement)."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        auth_data = build_authenticator_data(up=False)  # UP clear
        client_data_hash = hashlib.sha256(b"client data").digest()
        cose_key = create_test_cose_key_es256(private_key)
        signature = sign_fido2_assertion_es256(private_key, auth_data, client_data_hash)

        proof = LivenessProof(
            authenticator_data=auth_data,
            signature=signature,
            credential_id=b"cred_id",
            client_data_hash=client_data_hash,
            public_key_cose=cose_key,
        )
        challenge = LivenessChallenge(bytes(32), bytes(32), bytes(32))
        result = verify_liveness(proof, challenge)

        assert not result.valid
        assert not result.up_set
        assert "UP bit not set" in result.error

    def test_wrong_rp_id_rejected(self):
        """NEGATIVE: Wrong RP ID is rejected."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        auth_data = build_authenticator_data(rp_id="wrong.example.com", up=True)
        client_data_hash = hashlib.sha256(b"client data").digest()
        cose_key = create_test_cose_key_es256(private_key)
        signature = sign_fido2_assertion_es256(private_key, auth_data, client_data_hash)

        proof = LivenessProof(
            authenticator_data=auth_data,
            signature=signature,
            credential_id=b"cred_id",
            client_data_hash=client_data_hash,
            public_key_cose=cose_key,
        )
        challenge = LivenessChallenge(bytes(32), bytes(32), bytes(32))
        result = verify_liveness(proof, challenge)

        assert not result.valid
        assert not result.rp_id_valid
        assert "RP ID hash mismatch" in result.error

    def test_tampered_auth_data_rejected(self):
        """NEGATIVE: Tampered authenticatorData is rejected."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        auth_data = build_authenticator_data(up=True)
        client_data_hash = hashlib.sha256(b"client data").digest()
        cose_key = create_test_cose_key_es256(private_key)
        signature = sign_fido2_assertion_es256(private_key, auth_data, client_data_hash)

        tampered = bytearray(auth_data)
        tampered[35] ^= 0xFF

        proof = LivenessProof(
            authenticator_data=bytes(tampered),
            signature=signature,
            credential_id=b"cred_id",
            client_data_hash=client_data_hash,
            public_key_cose=cose_key,
        )
        challenge = LivenessChallenge(bytes(32), bytes(32), bytes(32))
        result = verify_liveness(proof, challenge)

        assert not result.valid
        assert not result.signature_valid
        assert "Invalid signature" in result.error

    def test_bad_signature_rejected(self):
        """NEGATIVE: Bad signature is rejected."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        auth_data = build_authenticator_data(up=True)
        client_data_hash = hashlib.sha256(b"client data").digest()
        cose_key = create_test_cose_key_es256(private_key)
        signature = bytearray(sign_fido2_assertion_es256(private_key, auth_data, client_data_hash))
        signature[0] ^= 0xFF  # Corrupt signature

        proof = LivenessProof(
            authenticator_data=auth_data,
            signature=bytes(signature),
            credential_id=b"cred_id",
            client_data_hash=client_data_hash,
            public_key_cose=cose_key,
        )
        challenge = LivenessChallenge(bytes(32), bytes(32), bytes(32))
        result = verify_liveness(proof, challenge)

        assert not result.valid
        assert not result.signature_valid

    def test_wrong_nonce_owner_challenge(self):
        """NEGATIVE: Challenge with wrong nonce owner fails.

        The challenge must use the counterparty's nonce.
        """
        my_nonce = generate_nonce()
        peer_nonce = generate_nonce()
        artifact_hash = hashlib.sha256(b"artifact").digest()
        my_key = bytes(32)
        peer_key = bytes.fromhex("01" * 32)

        correct_challenge = LivenessChallenge(peer_key, artifact_hash, peer_nonce)
        wrong_owner_challenge = LivenessChallenge(peer_key, artifact_hash, my_nonce)

        assert correct_challenge.challenge_bytes != wrong_owner_challenge.challenge_bytes


class TestChallengeConstruction:
    """Tests for correct challenge construction per Law 5."""

    def test_challenge_uses_counterparty_nonce(self):
        """Challenge must use counterparty's nonce, not your own."""
        my_key = bytes(32)
        peer_key = bytes.fromhex("01" * 32)
        artifact = hashlib.sha256(b"artifact").digest()
        my_nonce = generate_nonce()
        peer_nonce = generate_nonce()

        my_challenge = LivenessChallenge(peer_key, artifact, peer_nonce)
        assert my_nonce not in my_challenge.challenge_bytes

    def test_challenge_binds_to_artifact(self):
        """Different artifacts produce different challenges."""
        key = bytes(32)
        nonce = bytes(32)
        artifact1 = hashlib.sha256(b"artifact1").digest()
        artifact2 = hashlib.sha256(b"artifact2").digest()

        c1 = LivenessChallenge(key, artifact1, nonce)
        c2 = LivenessChallenge(key, artifact2, nonce)

        assert c1.challenge_bytes != c2.challenge_bytes
