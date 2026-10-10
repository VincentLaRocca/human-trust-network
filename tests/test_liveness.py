#!/usr/bin/env python3
"""Tests for FIDO2/CTAP2 liveness verification.

Tests:
- Real FIDO2 assertion with software authenticator
- Clear-UP-bit REJECT
- Bad-signature REJECT
"""

import pytest
import os
import hashlib

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from ivan_vaughan.liveness import (
    LivenessVerifier,
    LivenessAssertion,
    LivenessCredential,
    LivenessResult,
    SoftwareAuthenticator,
    compute_challenge,
    check_up_bit,
    STATIC_RP_ID,
)


class TestSoftwareAuthenticator:
    """Test the software authenticator for FIDO2."""
    
    def test_generate_assertion(self):
        """Test generating a valid assertion."""
        auth = SoftwareAuthenticator()
        challenge = os.urandom(32)
        
        assertion = auth.assert_presence(challenge, user_present=True)
        
        assert assertion.credential_id == auth.credential_id
        assert len(assertion.authenticator_data) >= 37  # rpIdHash + flags + counter
        # DER signature length varies (typically 70-72 bytes for P-256)
        assert 68 <= len(assertion.signature) <= 73
        assert assertion.up_bit is True
    
    def test_up_bit_clear(self):
        """Test assertion with UP bit clear."""
        auth = SoftwareAuthenticator()
        challenge = os.urandom(32)
        
        assertion = auth.assert_presence(challenge, user_present=False)
        
        assert assertion.up_bit is False
    
    def test_bad_signature(self):
        """Test assertion with bad signature."""
        auth = SoftwareAuthenticator()
        challenge = os.urandom(32)
        
        assertion = auth.assert_with_bad_signature(challenge)
        
        # Signature is random bytes, should fail verification
        assert len(assertion.signature) == 64


class TestLivenessVerifier:
    """Test the liveness verifier with real crypto."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.verifier = LivenessVerifier()
        self.authenticator = SoftwareAuthenticator()
        self.credential = self.authenticator.get_credential()
        self.verifier.register_credential(self.credential)
    
    def test_valid_assertion(self):
        """Test verification of a valid FIDO2 assertion."""
        challenge = os.urandom(32)
        assertion = self.authenticator.assert_presence(challenge, user_present=True)
        
        result = self.verifier.verify(assertion, challenge)
        
        assert result == LivenessResult.VALID
    
    def test_reject_up_clear(self):
        """Test REJECT when UP bit is clear.
        
        Law 5: UP bit required.
        """
        challenge = os.urandom(32)
        assertion = self.authenticator.assert_presence(challenge, user_present=False)
        
        result = self.verifier.verify(assertion, challenge)
        
        assert result == LivenessResult.REJECT_UP_CLEAR
    
    def test_reject_bad_signature(self):
        """Test REJECT when signature is invalid."""
        challenge = os.urandom(32)
        assertion = self.authenticator.assert_with_bad_signature(challenge)
        
        result = self.verifier.verify(assertion, challenge)
        
        assert result == LivenessResult.REJECT_BAD_SIG
    
    def test_reject_unknown_credential(self):
        """Test REJECT when credential is not registered."""
        other_auth = SoftwareAuthenticator()
        challenge = os.urandom(32)
        assertion = other_auth.assert_presence(challenge, user_present=True)
        
        # Don't register this credential
        result = self.verifier.verify(assertion, challenge)
        
        assert result == LivenessResult.REJECT_INVALID


class TestChallengeComputation:
    """Test challenge computation per Law 5."""
    
    def test_challenge_format(self):
        """Test challenge = SHA-256(peer_key || artifact_hash || peer_nonce)."""
        peer_key = os.urandom(32)
        artifact_hash = os.urandom(32)
        peer_nonce = os.urandom(32)
        
        challenge = compute_challenge(peer_key, artifact_hash, peer_nonce)
        
        expected = hashlib.sha256(peer_key + artifact_hash + peer_nonce).digest()
        assert challenge == expected
        assert len(challenge) == 32
    
    def test_challenge_deterministic(self):
        """Test that same inputs produce same challenge."""
        peer_key = b'\x01' * 32
        artifact_hash = b'\x02' * 32
        peer_nonce = b'\x03' * 32
        
        c1 = compute_challenge(peer_key, artifact_hash, peer_nonce)
        c2 = compute_challenge(peer_key, artifact_hash, peer_nonce)
        
        assert c1 == c2
    
    def test_challenge_different_nonce(self):
        """Test that different nonces produce different challenges."""
        peer_key = b'\x01' * 32
        artifact_hash = b'\x02' * 32
        nonce1 = b'\x03' * 32
        nonce2 = b'\x04' * 32
        
        c1 = compute_challenge(peer_key, artifact_hash, nonce1)
        c2 = compute_challenge(peer_key, artifact_hash, nonce2)
        
        assert c1 != c2


class TestUpBitCheck:
    """Test UP bit checking."""
    
    def test_up_bit_set(self):
        """Test detecting UP bit when set."""
        # rpIdHash (32) + flags (1) + counter (4)
        rp_id_hash = hashlib.sha256(STATIC_RP_ID.encode()).digest()
        flags = 0x01  # UP bit set
        counter = b'\x00\x00\x00\x01'
        
        auth_data = rp_id_hash + bytes([flags]) + counter
        
        assert check_up_bit(auth_data) is True
    
    def test_up_bit_clear(self):
        """Test detecting UP bit when clear."""
        rp_id_hash = hashlib.sha256(STATIC_RP_ID.encode()).digest()
        flags = 0x00  # UP bit clear
        counter = b'\x00\x00\x00\x01'
        
        auth_data = rp_id_hash + bytes([flags]) + counter
        
        assert check_up_bit(auth_data) is False
    
    def test_up_bit_with_uv(self):
        """Test UP bit with UV also set (both allowed, only UP required)."""
        rp_id_hash = hashlib.sha256(STATIC_RP_ID.encode()).digest()
        flags = 0x05  # UP (0x01) + UV (0x04)
        counter = b'\x00\x00\x00\x01'
        
        auth_data = rp_id_hash + bytes([flags]) + counter
        
        assert check_up_bit(auth_data) is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
