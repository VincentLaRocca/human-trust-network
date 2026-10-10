"""Dual-signed, content-addressed edge. (Law 2)

An edge is a dual-signed, content-addressed artifact hash.
Roles come only from a canonical parser on the raw bytes, version-pinned on the edge.
Upgrades do not reclassify old edges. No free-text roles.

Canonical edge hash: sort the two signatures (or keys), then compute
SHA-256(artifact_hash || sig_a || sig_b). Order-independence must be tested.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from .keys import NodeKey, NodeKeyPair, verify_signature
from .parser import ParsedRole, PARSER_VERSION
from .wire import encode, decode


@dataclass(frozen=True)
class EdgeSignature:
    """One party's signature on an edge."""

    signer: NodeKey
    signature: bytes
    nonce: bytes  # 32-byte nonce for liveness challenge

    def __post_init__(self) -> None:
        if len(self.nonce) != 32:
            raise ValueError("nonce must be 32 bytes")


@dataclass(frozen=True)
class Edge:
    """A dual-signed edge linking two nodes via an artifact.

    Both parties must sign. The edge is content-addressed.
    Roles are derived from the canonical parser, version-pinned.
    """

    artifact_hash: bytes  # SHA-256 of the artifact
    artifact_type: str  # e.g., "git_commit"
    parser_version: int
    sig_a: EdgeSignature
    sig_b: EdgeSignature

    def __post_init__(self) -> None:
        if len(self.artifact_hash) != 32:
            raise ValueError("artifact_hash must be 32 bytes (SHA-256)")
        if self.sig_a.signer == self.sig_b.signer:
            raise ValueError("Edge must link two different nodes")

    @property
    def edge_hash(self) -> bytes:
        """Canonical content-addressed hash.

        Sort signatures by signer node_id, then:
        SHA-256(artifact_hash || sig_a_bytes || sig_b_bytes)
        """
        sigs = sorted(
            [(self.sig_a.signer.node_id, self.sig_a.signature),
             (self.sig_b.signer.node_id, self.sig_b.signature)],
            key=lambda x: x[0]
        )
        return hashlib.sha256(
            self.artifact_hash + sigs[0][1] + sigs[1][1]
        ).digest()

    @property
    def nodes(self) -> tuple[NodeKey, NodeKey]:
        """The two nodes linked by this edge, in canonical order."""
        if self.sig_a.signer.node_id < self.sig_b.signer.node_id:
            return (self.sig_a.signer, self.sig_b.signer)
        return (self.sig_b.signer, self.sig_a.signer)

    def to_wire(self) -> bytes:
        """Serialize to CBOR (binary-safe)."""
        return encode({
            "artifact_hash": self.artifact_hash,
            "artifact_type": self.artifact_type,
            "parser_version": self.parser_version,
            "sig_a": {
                "signer_pubkey": self.sig_a.signer.public_bytes,
                "signer_algorithm": self.sig_a.signer.algorithm,
                "signature": self.sig_a.signature,
                "nonce": self.sig_a.nonce,
            },
            "sig_b": {
                "signer_pubkey": self.sig_b.signer.public_bytes,
                "signer_algorithm": self.sig_b.signer.algorithm,
                "signature": self.sig_b.signature,
                "nonce": self.sig_b.nonce,
            },
        })

    @classmethod
    def from_wire(cls, data: bytes) -> "Edge":
        """Deserialize from CBOR."""
        obj = decode(data)
        sig_a = EdgeSignature(
            signer=NodeKey(obj["sig_a"]["signer_pubkey"], obj["sig_a"]["signer_algorithm"]),
            signature=obj["sig_a"]["signature"],
            nonce=obj["sig_a"]["nonce"],
        )
        sig_b = EdgeSignature(
            signer=NodeKey(obj["sig_b"]["signer_pubkey"], obj["sig_b"]["signer_algorithm"]),
            signature=obj["sig_b"]["signature"],
            nonce=obj["sig_b"]["nonce"],
        )
        return cls(
            artifact_hash=obj["artifact_hash"],
            artifact_type=obj["artifact_type"],
            parser_version=obj["parser_version"],
            sig_a=sig_a,
            sig_b=sig_b,
        )


def edge_signing_payload(artifact_hash: bytes, counterparty_nonce: bytes) -> bytes:
    """The payload each party signs to create an edge.

    Includes the counterparty's nonce to bind the signatures.
    """
    return b"IVAN_VAUGHAN_EDGE_V1:" + artifact_hash + counterparty_nonce


def create_edge_signature(
    keypair: NodeKeyPair,
    artifact_hash: bytes,
    counterparty_nonce: bytes,
    my_nonce: bytes,
) -> EdgeSignature:
    """Create one party's signature for an edge."""
    payload = edge_signing_payload(artifact_hash, counterparty_nonce)
    signature = keypair.sign(payload)
    return EdgeSignature(
        signer=keypair.public,
        signature=signature,
        nonce=my_nonce,
    )


def verify_edge_signature(sig: EdgeSignature, artifact_hash: bytes, counterparty_nonce: bytes) -> bool:
    """Verify one party's signature on an edge."""
    payload = edge_signing_payload(artifact_hash, counterparty_nonce)
    return verify_signature(sig.signer, payload, sig.signature)


def verify_edge(edge: Edge) -> tuple[bool, Optional[str]]:
    """Verify both signatures on an edge.

    Returns (valid, error_message).
    """
    if not verify_edge_signature(edge.sig_a, edge.artifact_hash, edge.sig_b.nonce):
        return False, "sig_a invalid"
    if not verify_edge_signature(edge.sig_b, edge.artifact_hash, edge.sig_a.nonce):
        return False, "sig_b invalid"
    return True, None


@dataclass
class PendingEdge:
    """An edge under construction, before both parties have signed."""

    artifact_hash: bytes
    artifact_type: str
    parser_version: int
    initiator_sig: Optional[EdgeSignature] = None
    responder_sig: Optional[EdgeSignature] = None

    def add_initiator(self, sig: EdgeSignature) -> None:
        if self.initiator_sig is not None:
            raise ValueError("Initiator already signed")
        self.initiator_sig = sig

    def add_responder(self, sig: EdgeSignature) -> None:
        if self.responder_sig is not None:
            raise ValueError("Responder already signed")
        self.responder_sig = sig

    def is_complete(self) -> bool:
        return self.initiator_sig is not None and self.responder_sig is not None

    def finalize(self) -> Edge:
        if not self.is_complete():
            raise ValueError("Edge not complete")
        return Edge(
            artifact_hash=self.artifact_hash,
            artifact_type=self.artifact_type,
            parser_version=self.parser_version,
            sig_a=self.initiator_sig,
            sig_b=self.responder_sig,
        )
