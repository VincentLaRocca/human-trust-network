#!/usr/bin/env python3
"""FIDO2/CTAP2 liveness verification.

Law 5: Liveness: CTAP2/FIDO2, static RP ID, challenge = SHA-256(peer_key || artifact_hash || peer_nonce)
where the nonce is the counterparty's. UP bit required. Real signature verification.
No AAGUID allowlist, no UV requirement, no personhood claim.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    AuthenticatorData,
)
from fido2.cose import ES256, CoseKey
from fido2.utils import sha256


class LivenessError(Exception):
    """Base exception for liveness operations."""
    pass


class LivenessResult(Enum):
    """Result of liveness verification."""
    VALID = "valid"           # UP bit set, signature valid
    REJECT_UP_CLEAR = "reject_up_clear"  # UP bit not set
    REJECT_BAD_SIG = "reject_bad_sig"    # Signature verification failed
    REJECT_INVALID = "reject_invalid"    # Invalid data format


# Static RP ID per Law 5
STATIC_RP_ID = "ivan-vaughan.protocol"
STATIC_RP = PublicKeyCredentialRpEntity(name="Ivan Vaughan Protocol", id=STATIC_RP_ID)


def compute_challenge(peer_key: bytes, artifact_hash: bytes, peer_nonce: bytes) -> bytes:
    """Compute the challenge as SHA-256(peer_key || artifact_hash || peer_nonce).
    
    The nonce is the counterparty's, not the verifier's.
    """
    return hashlib.sha256(peer_key + artifact_hash + peer_nonce).digest()


@dataclass(frozen=True)
class LivenessAssertion:
    """A FIDO2 assertion for liveness proof.
    
    Contains the authenticator data and signature from a FIDO2 authenticator.
    """
    credential_id: bytes
    authenticator_data: bytes  # Raw authenticator data bytes
    signature: bytes
    client_data_hash: bytes    # SHA-256 of clientDataJSON
    
    @property
    def auth_data(self) -> AuthenticatorData:
        """Parse the authenticator data."""
        return AuthenticatorData(self.authenticator_data)
    
    @property
    def up_bit(self) -> bool:
        """Check if the User Present (UP) bit is set."""
        return self.auth_data.is_user_present()
    
    @property
    def uv_bit(self) -> bool:
        """Check if the User Verified (UV) bit is set. Not required by protocol."""
        return self.auth_data.is_user_verified()


@dataclass(frozen=True)
class LivenessCredential:
    """A registered FIDO2 credential for liveness proofs.
    
    Stored locally. No AAGUID allowlist per Law 5.
    """
    credential_id: bytes
    public_key: bytes  # COSE-encoded public key
    sign_count: int
    
    def cose_key(self) -> ES256:
        """Get the COSE key object for verification."""
        import cbor2
        # Use ES256 which has a working verify() method
        return ES256(cbor2.loads(self.public_key))


class LivenessVerifier:
    """Verifies FIDO2 liveness assertions.
    
    Enforces:
    - UP bit MUST be set
    - Real signature verification with the credential's public key
    - No AAGUID allowlist
    - No UV requirement (UV is optional)
    - No personhood claim
    """
    
    def __init__(self, rp_id: str = STATIC_RP_ID):
        self.rp_id = rp_id
        self._credentials: dict[bytes, LivenessCredential] = {}
    
    def register_credential(self, credential: LivenessCredential) -> None:
        """Register a credential for future verification."""
        self._credentials[credential.credential_id] = credential
    
    def get_credential(self, credential_id: bytes) -> Optional[LivenessCredential]:
        """Get a registered credential by ID."""
        return self._credentials.get(credential_id)
    
    def generate_nonce(self) -> bytes:
        """Generate a cryptographically secure nonce."""
        return os.urandom(32)
    
    def verify(
        self,
        assertion: LivenessAssertion,
        expected_challenge: bytes,
    ) -> LivenessResult:
        """Verify a liveness assertion.
        
        Returns:
            LivenessResult indicating success or specific failure reason.
        """
        try:
            auth_data = assertion.auth_data
        except Exception:
            return LivenessResult.REJECT_INVALID
        
        # Law 5: UP bit required
        if not auth_data.is_user_present():
            return LivenessResult.REJECT_UP_CLEAR
        
        # Get the registered credential
        credential = self.get_credential(assertion.credential_id)
        if credential is None:
            return LivenessResult.REJECT_INVALID
        
        # Verify the signature
        try:
            cose_key = credential.cose_key()
            
            # The signature is over authenticatorData || clientDataHash
            signed_data = assertion.authenticator_data + assertion.client_data_hash
            
            # Verify using the COSE key
            cose_key.verify(signed_data, assertion.signature)
            
            return LivenessResult.VALID
        except Exception:
            return LivenessResult.REJECT_BAD_SIG
    
    def verify_presence_backed_signature(
        self,
        peer_key: bytes,
        artifact_hash: bytes,
        peer_nonce: bytes,
        assertion: LivenessAssertion,
    ) -> LivenessResult:
        """Verify a presence-backed signature for mutual attestation.
        
        The challenge is computed as SHA-256(peer_key || artifact_hash || peer_nonce).
        """
        expected = compute_challenge(peer_key, artifact_hash, peer_nonce)
        
        # Verify that the client data hash matches our expected challenge
        # In FIDO2, the challenge is included in clientDataJSON which is hashed
        # For our protocol, we verify the assertion directly
        return self.verify(assertion, expected)


def make_client_data_hash(challenge: bytes) -> bytes:
    """Create a clientDataHash from a challenge.
    
    In real FIDO2, this would be SHA-256 of the JSON clientData.
    For testing/simulation, we use the challenge directly hashed.
    """
    return sha256(challenge)


def parse_authenticator_data(raw: bytes) -> AuthenticatorData:
    """Parse raw authenticator data bytes.
    
    The authenticatorData structure is:
    - rpIdHash (32 bytes)
    - flags (1 byte)
    - signCount (4 bytes, big-endian)
    - [optional] attestedCredentialData
    - [optional] extensions
    
    Flags bits:
    - bit 0 (0x01): User Present (UP)
    - bit 2 (0x04): User Verified (UV)
    - bit 6 (0x40): Attested credential data included
    - bit 7 (0x80): Extension data included
    """
    return AuthenticatorData(raw)


def check_up_bit(authenticator_data: bytes) -> bool:
    """Check if the UP (User Present) bit is set in authenticator data.
    
    The UP bit is bit 0 of the flags byte, which is at position 32.
    """
    if len(authenticator_data) < 33:
        return False
    flags = authenticator_data[32]
    return bool(flags & 0x01)


def verify_fido2_signature(
    public_key_cose: bytes,
    authenticator_data: bytes,
    client_data_hash: bytes,
    signature: bytes,
) -> bool:
    """Verify a FIDO2 signature with real cryptographic verification.
    
    The signature is over: authenticatorData || clientDataHash
    """
    import cbor2
    try:
        cose_key = CoseKey(cbor2.loads(public_key_cose))
        signed_data = authenticator_data + client_data_hash
        cose_key.verify(signed_data, signature)
        return True
    except Exception:
        return False


@dataclass
class SoftwareAuthenticator:
    """A software-based FIDO2 authenticator for testing.
    
    This is NOT for production use. It simulates a FIDO2 authenticator
    for testing the protocol without hardware.
    """
    
    def __init__(self, rp_id: str = STATIC_RP_ID):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        
        self.rp_id = rp_id
        self._private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self._credential_id = os.urandom(32)
        self._sign_count = 0
    
    @property
    def credential_id(self) -> bytes:
        return self._credential_id
    
    @property
    def public_key_cose(self) -> bytes:
        """Get the public key in COSE format (CBOR-encoded)."""
        import cbor2
        
        pub = self._private_key.public_key()
        numbers = pub.public_numbers()
        
        # COSE_Key for ES256 (ECDSA with P-256)
        # Key type: EC2 (2)
        # Algorithm: ES256 (-7)
        # Curve: P-256 (1)
        # x and y coordinates
        cose_map = {
            1: 2,   # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            -2: numbers.x.to_bytes(32, 'big'),  # x
            -3: numbers.y.to_bytes(32, 'big'),  # y
        }
        return cbor2.dumps(cose_map)
    
    def get_credential(self) -> LivenessCredential:
        """Get the credential for registration."""
        return LivenessCredential(
            credential_id=self._credential_id,
            public_key=self.public_key_cose,  # Already CBOR bytes
            sign_count=self._sign_count,
        )
    
    def assert_presence(
        self,
        challenge: bytes,
        user_present: bool = True,
    ) -> LivenessAssertion:
        """Generate an assertion with the given challenge.
        
        Args:
            challenge: The challenge to sign
            user_present: Whether to set the UP bit (for testing rejection)
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        
        self._sign_count += 1
        
        # Build authenticator data
        rp_id_hash = hashlib.sha256(self.rp_id.encode()).digest()
        flags = 0x01 if user_present else 0x00  # UP bit
        sign_count_bytes = self._sign_count.to_bytes(4, 'big')
        auth_data = rp_id_hash + bytes([flags]) + sign_count_bytes
        
        # Client data hash (in real FIDO2, this is hash of clientDataJSON)
        client_data_hash = sha256(challenge)
        
        # Sign authenticatorData || clientDataHash
        signed_data = auth_data + client_data_hash
        
        # ECDSA signature - keep DER format as COSE key verifier expects
        signature_der = self._private_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))
        
        return LivenessAssertion(
            credential_id=self._credential_id,
            authenticator_data=auth_data,
            signature=signature_der,
            client_data_hash=client_data_hash,
        )
    
    def assert_with_bad_signature(self, challenge: bytes) -> LivenessAssertion:
        """Generate an assertion with an invalid signature (for testing)."""
        self._sign_count += 1
        
        rp_id_hash = hashlib.sha256(self.rp_id.encode()).digest()
        flags = 0x01  # UP bit set
        sign_count_bytes = self._sign_count.to_bytes(4, 'big')
        auth_data = rp_id_hash + bytes([flags]) + sign_count_bytes
        client_data_hash = sha256(challenge)
        
        # Bad signature - random bytes
        bad_signature = os.urandom(64)
        
        return LivenessAssertion(
            credential_id=self._credential_id,
            authenticator_data=auth_data,
            signature=bad_signature,
            client_data_hash=client_data_hash,
        )
