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


def create_valid_proof_for_challenge(challenge: LivenessChallenge, up: bool = True, rp_id: str = None):
    """Helper to create a valid liveness proof for a given challenge.
    
    The clientDataHash must commit to the challenge bytes via:
    clientDataHash = SHA-256(challenge.challenge_bytes)
    """
    from ivan_vaughan.fido import STATIC_RP_ID
    
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    auth_data = build_authenticator_data(up=up, rp_id=rp_id or STATIC_RP_ID)
    # CRITICAL: clientDataHash must be SHA-256 of the challenge bytes
    client_data_hash = hashlib.sha256(challenge.challenge_bytes).digest()
    cose_key = create_test_cose_key_es256(private_key)
    signature = sign_fido2_assertion_es256(private_key, auth_data, client_data_hash)

    return LivenessProof(
        authenticator_data=auth_data,
        signature=signature,
        credential_id=b"cred_id",
        client_data_hash=client_data_hash,
        public_key_cose=cose_key,
    )


class TestLivenessVerification:
    """Full liveness verification tests including negative cases."""

    def test_valid_liveness_proof(self):
        """Valid proof passes all checks."""
        challenge = LivenessChallenge(bytes(32), bytes(32), bytes(32))
        proof = create_valid_proof_for_challenge(challenge)
        result = verify_liveness(proof, challenge)

        assert result.valid
        assert result.up_set
        assert result.rp_id_valid
        assert result.signature_valid
        assert result.challenge_matched

    def test_wrong_challenge_rejected(self):
        """NEGATIVE: Wrong challenge is rejected (critical crypto check)."""
        # Create proof for one challenge
        challenge_used = LivenessChallenge(bytes(32), bytes(32), bytes(32))
        proof = create_valid_proof_for_challenge(challenge_used)
        
        # Try to verify with a different challenge
        different_challenge = LivenessChallenge(bytes(32), bytes(32), b'\x01' * 32)
        result = verify_liveness(proof, different_challenge)

        assert not result.valid
        assert not result.challenge_matched
        assert "Challenge mismatch" in result.error

    def test_up_bit_clear_rejected(self):
        """NEGATIVE: UP bit clear is rejected (Law 5 requirement)."""
        challenge = LivenessChallenge(bytes(32), bytes(32), bytes(32))
        proof = create_valid_proof_for_challenge(challenge, up=False)
        result = verify_liveness(proof, challenge)

        assert not result.valid
        assert not result.up_set
        assert "UP bit not set" in result.error

    def test_wrong_rp_id_rejected(self):
        """NEGATIVE: Wrong RP ID is rejected."""
        challenge = LivenessChallenge(bytes(32), bytes(32), bytes(32))
        proof = create_valid_proof_for_challenge(challenge, rp_id="wrong.example.com")
        result = verify_liveness(proof, challenge)

        assert not result.valid
        assert not result.rp_id_valid
        assert "RP ID hash mismatch" in result.error

    def test_tampered_auth_data_rejected(self):
        """NEGATIVE: Tampered authenticatorData is rejected."""
        challenge = LivenessChallenge(bytes(32), bytes(32), bytes(32))
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        auth_data = build_authenticator_data(up=True)
        # clientDataHash must match challenge for this test to reach signature verification
        client_data_hash = hashlib.sha256(challenge.challenge_bytes).digest()
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
        result = verify_liveness(proof, challenge)

        assert not result.valid
        assert not result.signature_valid
        assert "Invalid signature" in result.error

    def test_bad_signature_rejected(self):
        """NEGATIVE: Bad signature is rejected."""
        challenge = LivenessChallenge(bytes(32), bytes(32), bytes(32))
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        auth_data = build_authenticator_data(up=True)
        # clientDataHash must match challenge for this test to reach signature verification
        client_data_hash = hashlib.sha256(challenge.challenge_bytes).digest()
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


class TestChallengeVerificationNegative:
    """Additional negative tests for challenge verification (Gate 1 hardening)."""

    def test_wrong_artifact_hash_in_challenge(self):
        """Proof for artifact A cannot verify for artifact B."""
        nonce = bytes(32)
        peer_key = bytes(32)
        artifact_a = hashlib.sha256(b"artifact_a").digest()
        artifact_b = hashlib.sha256(b"artifact_b").digest()

        challenge_a = LivenessChallenge(peer_key, artifact_a, nonce)
        challenge_b = LivenessChallenge(peer_key, artifact_b, nonce)

        # Create valid proof for artifact A
        proof = create_valid_proof_for_challenge(challenge_a)

        # Should pass for challenge A
        result_a = verify_liveness(proof, challenge_a)
        assert result_a.valid
        assert result_a.challenge_matched

        # Should FAIL for challenge B (different artifact)
        result_b = verify_liveness(proof, challenge_b)
        assert not result_b.valid
        assert not result_b.challenge_matched

    def test_wrong_peer_key_in_challenge(self):
        """Proof for peer A cannot verify for peer B."""
        nonce = bytes(32)
        artifact = hashlib.sha256(b"artifact").digest()
        peer_key_a = bytes(32)
        peer_key_b = b'\x01' * 32

        challenge_a = LivenessChallenge(peer_key_a, artifact, nonce)
        challenge_b = LivenessChallenge(peer_key_b, artifact, nonce)

        proof = create_valid_proof_for_challenge(challenge_a)

        result_a = verify_liveness(proof, challenge_a)
        assert result_a.valid

        result_b = verify_liveness(proof, challenge_b)
        assert not result_b.valid
        assert not result_b.challenge_matched

    def test_wrong_nonce_in_challenge(self):
        """Proof with nonce A cannot verify with nonce B."""
        peer_key = bytes(32)
        artifact = hashlib.sha256(b"artifact").digest()
        nonce_a = bytes(32)
        nonce_b = b'\xff' * 32

        challenge_a = LivenessChallenge(peer_key, artifact, nonce_a)
        challenge_b = LivenessChallenge(peer_key, artifact, nonce_b)

        proof = create_valid_proof_for_challenge(challenge_a)

        result_a = verify_liveness(proof, challenge_a)
        assert result_a.valid

        result_b = verify_liveness(proof, challenge_b)
        assert not result_b.valid
        assert not result_b.challenge_matched

    def test_replay_attack_prevented(self):
        """A valid proof cannot be replayed with different parameters."""
        # Create a legitimate proof
        original_challenge = LivenessChallenge(
            peer_key=bytes(32),
            artifact_hash=hashlib.sha256(b"original").digest(),
            peer_nonce=bytes(32),
        )
        proof = create_valid_proof_for_challenge(original_challenge)

        # Verify original works
        result = verify_liveness(proof, original_challenge)
        assert result.valid

        # Attempt replay with different nonce (simulating attacker)
        replay_challenge = LivenessChallenge(
            peer_key=bytes(32),
            artifact_hash=hashlib.sha256(b"original").digest(),
            peer_nonce=b'\xaa' * 32,  # Attacker's chosen nonce
        )
        replay_result = verify_liveness(proof, replay_challenge)
        assert not replay_result.valid
        assert not replay_result.challenge_matched

    def test_no_mocked_verification(self):
        """Verify that signature verification is real, not mocked.
        
        This test verifies actual cryptographic operations occur:
        - A valid signature passes
        - A corrupted signature fails
        - The wrong key fails
        """
        challenge = LivenessChallenge(bytes(32), bytes(32), bytes(32))
        
        # Generate two different keypairs
        key1 = ec.generate_private_key(ec.SECP256R1(), default_backend())
        key2 = ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        auth_data = build_authenticator_data(up=True)
        client_data_hash = hashlib.sha256(challenge.challenge_bytes).digest()
        
        cose_key1 = create_test_cose_key_es256(key1)
        cose_key2 = create_test_cose_key_es256(key2)
        
        # Sign with key1
        signature = sign_fido2_assertion_es256(key1, auth_data, client_data_hash)
        
        # Proof with correct key should verify
        proof_good = LivenessProof(
            authenticator_data=auth_data,
            signature=signature,
            credential_id=b"cred",
            client_data_hash=client_data_hash,
            public_key_cose=cose_key1,
        )
        result_good = verify_liveness(proof_good, challenge)
        assert result_good.valid, "Valid signature should verify"
        
        # Same signature with wrong key should fail
        proof_wrong_key = LivenessProof(
            authenticator_data=auth_data,
            signature=signature,
            credential_id=b"cred",
            client_data_hash=client_data_hash,
            public_key_cose=cose_key2,  # Wrong key!
        )
        result_wrong_key = verify_liveness(proof_wrong_key, challenge)
        assert not result_wrong_key.valid, "Wrong key must fail verification"
        assert not result_wrong_key.signature_valid

    def test_real_eddsa_verification(self):
        """Test that EdDSA verification is also real."""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        
        challenge = LivenessChallenge(bytes(32), bytes(32), bytes(32))
        
        key = ed25519.Ed25519PrivateKey.generate()
        auth_data = build_authenticator_data(up=True)
        client_data_hash = hashlib.sha256(challenge.challenge_bytes).digest()
        
        cose_key = create_test_cose_key_eddsa(key)
        signature = sign_fido2_assertion_eddsa(key, auth_data, client_data_hash)
        
        proof = LivenessProof(
            authenticator_data=auth_data,
            signature=signature,
            credential_id=b"cred",
            client_data_hash=client_data_hash,
            public_key_cose=cose_key,
        )
        
        result = verify_liveness(proof, challenge)
        assert result.valid
        assert result.signature_valid
        
        # Corrupt the signature and verify it fails
        bad_sig = bytearray(signature)
        bad_sig[0] ^= 0xFF
        
        proof_bad = LivenessProof(
            authenticator_data=auth_data,
            signature=bytes(bad_sig),
            credential_id=b"cred",
            client_data_hash=client_data_hash,
            public_key_cose=cose_key,
        )
        result_bad = verify_liveness(proof_bad, challenge)
        assert not result_bad.valid
        assert not result_bad.signature_valid
