"""Node identity: a keypair. (Law 1)

A node is a keypair. Nicknames are UI caches with zero weight.
Unlinked aliases are hermetic - no relationship unless an edge exists.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend


@dataclass(frozen=True)
class NodeKey:
    """A node identity backed by an EdDSA or ECDSA key."""

    public_bytes: bytes
    algorithm: str  # "Ed25519" or "ES256"

    def __post_init__(self) -> None:
        if self.algorithm == "Ed25519" and len(self.public_bytes) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
        if self.algorithm == "ES256" and len(self.public_bytes) not in (33, 65):
            raise ValueError("ES256 public key must be 33 or 65 bytes")

    @property
    def node_id(self) -> bytes:
        """Content-addressed identity: SHA-256 of algorithm || public key."""
        return hashlib.sha256(self.algorithm.encode() + self.public_bytes).digest()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NodeKey):
            return False
        return self.node_id == other.node_id

    def __hash__(self) -> int:
        return hash(self.node_id)


@dataclass
class NodeKeyPair:
    """A node with its private key for signing."""

    public: NodeKey
    _private: bytes

    @classmethod
    def generate_ed25519(cls) -> "NodeKeyPair":
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        private_bytes = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        return cls(NodeKey(public_bytes, "Ed25519"), private_bytes)

    @classmethod
    def generate_es256(cls) -> "NodeKeyPair":
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )
        private_bytes = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return cls(NodeKey(public_bytes, "ES256"), private_bytes)

    @classmethod
    def from_seed(cls, seed: bytes, algorithm: str = "Ed25519") -> "NodeKeyPair":
        """Deterministic key from seed (for testing)."""
        if algorithm == "Ed25519":
            if len(seed) != 32:
                seed = hashlib.sha256(seed).digest()
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
            public_bytes = private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            return cls(NodeKey(public_bytes, "Ed25519"), seed)
        else:
            raise ValueError(f"Unsupported algorithm for seed generation: {algorithm}")

    def sign(self, message: bytes) -> bytes:
        """Sign a message."""
        if self.public.algorithm == "Ed25519":
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(self._private)
            return private_key.sign(message)
        elif self.public.algorithm == "ES256":
            private_key = serialization.load_der_private_key(
                self._private, password=None, backend=default_backend()
            )
            return private_key.sign(message, ec.ECDSA(SHA256()))
        else:
            raise ValueError(f"Unknown algorithm: {self.public.algorithm}")

    @property
    def node_id(self) -> bytes:
        return self.public.node_id


def verify_signature(key: NodeKey, message: bytes, signature: bytes) -> bool:
    """Verify a signature. Returns True if valid, False otherwise."""
    try:
        if key.algorithm == "Ed25519":
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(key.public_bytes)
            public_key.verify(signature, message)
            return True
        elif key.algorithm == "ES256":
            if len(key.public_bytes) == 33:
                public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), key.public_bytes
                )
            else:
                public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), key.public_bytes
                )
            public_key.verify(signature, message, ec.ECDSA(SHA256()))
            return True
        else:
            return False
    except Exception:
        return False


class Nickname:
    """UI-only label for a node. Zero protocol weight."""

    def __init__(self, node_id: bytes, label: str) -> None:
        self.node_id = node_id
        self.label = label
        self._cache_time: Optional[float] = None

    def __repr__(self) -> str:
        return f"Nickname({self.node_id.hex()[:8]}..., {self.label!r})"
