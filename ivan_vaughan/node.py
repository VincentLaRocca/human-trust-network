#!/usr/bin/env python3
"""Node identity as a keypair.

Law 1: Node is a keypair. Nicknames are UI caches with zero weight.
Unlinked aliases are hermetic.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.backends import default_backend


class NodeError(Exception):
    """Base exception for node operations."""
    pass


@dataclass(frozen=True)
class NodeID:
    """A node identifier derived from its public key.
    
    The ID is the SHA-256 of the public key bytes (x-only for secp256k1,
    raw bytes for Ed25519). IDs are deterministic from the key material.
    """
    key_bytes: bytes
    algorithm: str  # "secp256k1" or "ed25519"
    
    def __post_init__(self) -> None:
        if self.algorithm == "secp256k1":
            if len(self.key_bytes) not in (32, 33):
                raise NodeError("secp256k1 key must be 32 (x-only) or 33 (compressed) bytes")
        elif self.algorithm == "ed25519":
            if len(self.key_bytes) != 32:
                raise NodeError("ed25519 key must be 32 bytes")
        else:
            raise NodeError(f"unknown algorithm: {self.algorithm}")
    
    @property
    def node_id(self) -> bytes:
        """SHA-256 hash of the key bytes."""
        return hashlib.sha256(self.xonly).digest()
    
    @property
    def xonly(self) -> bytes:
        """X-only form of the public key (32 bytes)."""
        if self.algorithm == "secp256k1" and len(self.key_bytes) == 33:
            return self.key_bytes[1:]
        return self.key_bytes
    
    @property
    def did(self) -> str:
        """DID representation: did:key:<multibase-encoded-key>."""
        # multicodec prefix: 0xe7 for secp256k1, 0xed for ed25519
        if self.algorithm == "secp256k1":
            prefix = b'\xe7\x01'
        else:
            prefix = b'\xed\x01'
        import base64
        encoded = base64.urlsafe_b64encode(prefix + self.xonly).rstrip(b'=').decode()
        return f"did:key:z{encoded}"
    
    def __hash__(self) -> int:
        return hash((self.xonly, self.algorithm))
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NodeID):
            return False
        return self.xonly == other.xonly and self.algorithm == other.algorithm


@dataclass
class Node:
    """A node in the network, identified by its keypair.
    
    Nicknames are UI-level caches and carry zero protocol weight.
    """
    private_key: bytes
    algorithm: str = "ed25519"
    _nickname: Optional[str] = field(default=None, repr=False)
    
    def __post_init__(self) -> None:
        if self.algorithm not in ("secp256k1", "ed25519"):
            raise NodeError(f"unsupported algorithm: {self.algorithm}")
        if self.algorithm == "ed25519":
            if len(self.private_key) != 32:
                raise NodeError("ed25519 private key must be 32 bytes")
        elif self.algorithm == "secp256k1":
            if len(self.private_key) != 32:
                raise NodeError("secp256k1 private key must be 32 bytes")
    
    @classmethod
    def generate(cls, algorithm: str = "ed25519") -> "Node":
        """Generate a new random node keypair."""
        secret = os.urandom(32)
        return cls(private_key=secret, algorithm=algorithm)
    
    @classmethod
    def from_seed(cls, seed: bytes, algorithm: str = "ed25519") -> "Node":
        """Derive a node from a seed (deterministic)."""
        secret = hashlib.sha256(seed).digest()
        return cls(private_key=secret, algorithm=algorithm)
    
    @property
    def public_key(self) -> bytes:
        """Get the public key bytes."""
        if self.algorithm == "ed25519":
            key = ed25519.Ed25519PrivateKey.from_private_bytes(self.private_key)
            return key.public_key().public_bytes_raw()
        else:
            key = ec.derive_private_key(
                int.from_bytes(self.private_key, "big"),
                ec.SECP256K1(),
                default_backend()
            )
            pub = key.public_key()
            numbers = pub.public_numbers()
            prefix = b'\x02' if numbers.y % 2 == 0 else b'\x03'
            return prefix + numbers.x.to_bytes(32, "big")
    
    @property
    def node_id(self) -> NodeID:
        """Get the node identifier."""
        return NodeID(self.public_key, self.algorithm)
    
    def sign(self, message: bytes) -> bytes:
        """Sign a message with this node's private key."""
        if self.algorithm == "ed25519":
            key = ed25519.Ed25519PrivateKey.from_private_bytes(self.private_key)
            return key.sign(message)
        else:
            from embit.ec import PrivateKey
            key = PrivateKey(self.private_key)
            return key.schnorr_sign(message).serialize()
    
    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes, algorithm: str = "ed25519") -> bool:
        """Verify a signature against a public key."""
        try:
            if algorithm == "ed25519":
                if len(public_key) != 32:
                    return False
                key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
                key.verify(signature, message)
                return True
            else:
                from embit.ec import PublicKey, SchnorrSig
                xonly = public_key[1:] if len(public_key) == 33 else public_key
                if len(xonly) != 32 or len(signature) != 64:
                    return False
                pk = PublicKey.from_xonly(xonly)
                return pk.schnorr_verify(SchnorrSig(signature), message)
        except Exception:
            return False
    
    @property
    def nickname(self) -> Optional[str]:
        """UI-level nickname. Carries zero protocol weight."""
        return self._nickname
    
    @nickname.setter
    def nickname(self, value: Optional[str]) -> None:
        """Set the nickname. This is a UI cache only."""
        self._nickname = value


@dataclass(frozen=True)
class Alias:
    """An unlinked alias. Hermetic by design.
    
    Aliases are separate keypairs that cannot be linked to the primary node
    at the protocol level. Any linkage is UI-level only and carries zero weight.
    """
    node: NodeID
    alias: NodeID
    
    def __post_init__(self) -> None:
        if self.node == self.alias:
            raise NodeError("alias cannot be the node itself")


class SignerDID:
    """Canonical DID for a signer key."""
    
    def __init__(self, key_bytes: bytes, algorithm: str = "ed25519"):
        self.node_id = NodeID(key_bytes, algorithm)
    
    @property
    def did(self) -> str:
        return self.node_id.did
    
    def __str__(self) -> str:
        return self.did
    
    def __hash__(self) -> int:
        return hash(self.node_id)
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SignerDID):
            return False
        return self.node_id == other.node_id
