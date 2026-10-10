"""Sandbox and mutual attestation. (Law 8)

A failed sandbox writes nothing.
Mutual attestation happens only after commit-reveal of presence-backed signatures.
The artifact is pinned before broadcast.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict

from .edge import Edge, EdgeSignature, PendingEdge, create_edge_signature, verify_edge
from .fido import (
    LivenessProof,
    LivenessChallenge,
    verify_liveness,
    generate_nonce,
)
from .keys import NodeKeyPair, NodeKey
from .wire import encode, decode


class AttestationPhase(Enum):
    """Phases of mutual attestation."""

    INIT = "init"
    COMMIT_SENT = "commit_sent"
    COMMIT_RECEIVED = "commit_received"
    REVEAL_SENT = "reveal_sent"
    REVEAL_RECEIVED = "reveal_received"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass(frozen=True)
class Commitment:
    """Commitment to a signature (commit phase)."""

    commit_hash: bytes  # SHA-256(signature || nonce || blinding)
    public_key: NodeKey

    @classmethod
    def create(cls, signature: bytes, nonce: bytes, blinding: bytes) -> "Commitment":
        commit_hash = hashlib.sha256(signature + nonce + blinding).digest()
        return cls(commit_hash=commit_hash, public_key=None)


@dataclass(frozen=True)
class Reveal:
    """Revealed signature (reveal phase)."""

    signature: bytes
    nonce: bytes
    blinding: bytes

    def verify_against_commit(self, commit: Commitment) -> bool:
        """Verify this reveal matches the commitment."""
        expected = hashlib.sha256(self.signature + self.nonce + self.blinding).digest()
        return expected == commit.commit_hash


@dataclass
class SandboxState:
    """State of a sandbox attestation session.

    A failed sandbox writes nothing - no edge is stored.
    """

    artifact_hash: bytes
    artifact_type: str
    parser_version: int
    initiator_key: NodeKeyPair
    responder_key: Optional[NodeKey] = None
    phase: AttestationPhase = AttestationPhase.INIT
    my_nonce: bytes = field(default_factory=generate_nonce)
    my_blinding: bytes = field(default_factory=lambda: os.urandom(32))
    peer_nonce: Optional[bytes] = None
    my_signature: Optional[bytes] = None
    my_commit: Optional[bytes] = None
    peer_commit: Optional[bytes] = None
    peer_reveal: Optional[Reveal] = None
    my_liveness: Optional[LivenessProof] = None
    peer_liveness: Optional[LivenessProof] = None
    pinned: bool = False
    error: Optional[str] = None

    def fail(self, reason: str) -> None:
        """Mark sandbox as failed. Nothing will be written."""
        self.phase = AttestationPhase.FAILED
        self.error = reason


@dataclass
class AttestationProtocol:
    """Mutual attestation with commit-reveal.

    Flow:
    1. Both parties pin the artifact locally
    2. Both parties generate nonces and signatures
    3. Both parties send commitments (hash of signature)
    4. Both parties send reveals (actual signature)
    5. Both parties verify reveals match commitments
    6. Edge is created only if all steps succeed
    """

    state: SandboxState

    def generate_commitment(self) -> bytes:
        """Generate and store commitment for our signature."""
        if self.state.phase != AttestationPhase.INIT:
            self.state.fail("wrong phase for commitment")
            return b""

        if self.state.peer_nonce is None:
            self.state.fail("need peer nonce before signing")
            return b""

        from .edge import edge_signing_payload
        payload = edge_signing_payload(self.state.artifact_hash, self.state.peer_nonce)
        self.state.my_signature = self.state.initiator_key.sign(payload)

        self.state.my_commit = hashlib.sha256(
            self.state.my_signature + self.state.my_nonce + self.state.my_blinding
        ).digest()

        self.state.phase = AttestationPhase.COMMIT_SENT
        return encode({
            "commit": self.state.my_commit,
            "nonce": self.state.my_nonce,
            "public_key": self.state.initiator_key.public.public_bytes,
            "algorithm": self.state.initiator_key.public.algorithm,
        })

    def receive_commitment(self, data: bytes) -> bool:
        """Receive and store peer's commitment."""
        if self.state.phase not in (AttestationPhase.INIT, AttestationPhase.COMMIT_SENT):
            self.state.fail("wrong phase for receiving commitment")
            return False

        try:
            obj = decode(data)
            self.state.peer_commit = obj["commit"]
            self.state.peer_nonce = obj["nonce"]
            self.state.responder_key = NodeKey(obj["public_key"], obj["algorithm"])

            if self.state.phase == AttestationPhase.INIT:
                self.state.phase = AttestationPhase.COMMIT_RECEIVED
            else:
                pass

            return True
        except Exception as e:
            self.state.fail(f"invalid commitment: {e}")
            return False

    def generate_reveal(self) -> bytes:
        """Generate reveal after both commitments received."""
        if self.state.my_signature is None:
            self.state.fail("no signature to reveal")
            return b""

        self.state.phase = AttestationPhase.REVEAL_SENT
        return encode({
            "signature": self.state.my_signature,
            "nonce": self.state.my_nonce,
            "blinding": self.state.my_blinding,
        })

    def receive_reveal(self, data: bytes) -> bool:
        """Receive and verify peer's reveal."""
        try:
            obj = decode(data)
            reveal = Reveal(
                signature=obj["signature"],
                nonce=obj["nonce"],
                blinding=obj["blinding"],
            )

            expected_commit = hashlib.sha256(
                reveal.signature + reveal.nonce + reveal.blinding
            ).digest()

            if expected_commit != self.state.peer_commit:
                self.state.fail("reveal does not match commitment")
                return False

            self.state.peer_reveal = reveal
            self.state.phase = AttestationPhase.REVEAL_RECEIVED
            return True
        except Exception as e:
            self.state.fail(f"invalid reveal: {e}")
            return False

    def set_liveness_proofs(
        self,
        my_liveness: LivenessProof,
        peer_liveness: LivenessProof,
    ) -> bool:
        """Set liveness proofs for both parties."""
        challenge_me = LivenessChallenge(
            peer_key=self.state.responder_key.public_bytes,
            artifact_hash=self.state.artifact_hash,
            peer_nonce=self.state.peer_nonce,
        )
        result_me = verify_liveness(my_liveness, challenge_me)
        if not result_me.valid:
            self.state.fail(f"my liveness invalid: {result_me.error}")
            return False

        challenge_peer = LivenessChallenge(
            peer_key=self.state.initiator_key.public.public_bytes,
            artifact_hash=self.state.artifact_hash,
            peer_nonce=self.state.my_nonce,
        )
        result_peer = verify_liveness(peer_liveness, challenge_peer)
        if not result_peer.valid:
            self.state.fail(f"peer liveness invalid: {result_peer.error}")
            return False

        self.state.my_liveness = my_liveness
        self.state.peer_liveness = peer_liveness
        return True

    def finalize(self) -> Optional[Edge]:
        """Create final edge if all attestation succeeded.

        Returns None if sandbox failed - nothing is written.
        """
        if self.state.phase == AttestationPhase.FAILED:
            return None

        if self.state.peer_reveal is None:
            self.state.fail("peer reveal not received")
            return None

        if not self.state.pinned:
            self.state.fail("artifact not pinned")
            return None

        from .edge import EdgeSignature, verify_edge_signature

        my_sig = EdgeSignature(
            signer=self.state.initiator_key.public,
            signature=self.state.my_signature,
            nonce=self.state.my_nonce,
        )

        peer_sig = EdgeSignature(
            signer=self.state.responder_key,
            signature=self.state.peer_reveal.signature,
            nonce=self.state.peer_reveal.nonce,
        )

        if not verify_edge_signature(my_sig, self.state.artifact_hash, self.state.peer_nonce):
            self.state.fail("my signature invalid")
            return None

        if not verify_edge_signature(peer_sig, self.state.artifact_hash, self.state.my_nonce):
            self.state.fail("peer signature invalid")
            return None

        try:
            edge = Edge(
                artifact_hash=self.state.artifact_hash,
                artifact_type=self.state.artifact_type,
                parser_version=self.state.parser_version,
                sig_a=my_sig,
                sig_b=peer_sig,
            )
            valid, error = verify_edge(edge)
            if not valid:
                self.state.fail(f"edge invalid: {error}")
                return None

            self.state.phase = AttestationPhase.COMPLETE
            return edge
        except Exception as e:
            self.state.fail(f"edge creation failed: {e}")
            return None

    def pin_artifact(self) -> None:
        """Mark artifact as pinned. Must be called before finalize."""
        self.state.pinned = True


def create_sandbox(
    artifact_hash: bytes,
    artifact_type: str,
    parser_version: int,
    initiator: NodeKeyPair,
) -> AttestationProtocol:
    """Create a new attestation sandbox."""
    state = SandboxState(
        artifact_hash=artifact_hash,
        artifact_type=artifact_type,
        parser_version=parser_version,
        initiator_key=initiator,
    )
    return AttestationProtocol(state=state)
