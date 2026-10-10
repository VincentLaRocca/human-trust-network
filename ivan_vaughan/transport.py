"""Transport validation. (Law 6)

Transport validates only global invariants:
- Schema
- Known parser version
- Hash integrity
- Canonical parse
- Presence-backed signatures

Unknown parser version or fetch timeout = Ignore (no penalty, no forward).
Reject only on:
- Known-version parse failure
- Hash mismatch
- Clear UP bit
- Bad signature

The sink is never a relay gate.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

from .edge import Edge, verify_edge
from .parser import validate_parser_version, PARSER_VERSION
from .fido import LivenessProof, verify_liveness, LivenessChallenge, check_up_bit


class TransportVerdict(Enum):
    """Verdict from transport validation."""

    ACCEPT = "accept"  # Valid, forward to local storage
    IGNORE = "ignore"  # Unknown version or timeout, no penalty, no forward, retry later
    REJECT = "reject"  # Invalid, penalty applies


@dataclass(frozen=True)
class ValidationResult:
    """Result of transport validation."""

    verdict: TransportVerdict
    reason: Optional[str] = None


def validate_edge_transport(edge_data: bytes) -> ValidationResult:
    """Validate an edge at the transport layer.

    Only global invariants. Does NOT check sink (that's lens-only).
    """
    try:
        edge = Edge.from_wire(edge_data)
    except Exception as e:
        return ValidationResult(TransportVerdict.REJECT, f"deserialize failed: {e}")

    if not validate_parser_version(edge.parser_version):
        return ValidationResult(
            TransportVerdict.IGNORE,
            f"unknown parser version {edge.parser_version}"
        )

    computed_hash = edge.edge_hash
    if len(edge.artifact_hash) != 32:
        return ValidationResult(TransportVerdict.REJECT, "artifact_hash wrong length")

    valid, error = verify_edge(edge)
    if not valid:
        return ValidationResult(TransportVerdict.REJECT, f"signature: {error}")

    return ValidationResult(TransportVerdict.ACCEPT)


def validate_edge_with_liveness(
    edge: Edge,
    liveness_a: Optional[LivenessProof],
    liveness_b: Optional[LivenessProof],
) -> ValidationResult:
    """Validate edge including liveness proofs.

    Both parties must provide presence-backed signatures (UP bit set).
    """
    valid, error = verify_edge(edge)
    if not valid:
        return ValidationResult(TransportVerdict.REJECT, f"edge signature: {error}")

    if liveness_a is not None:
        if not check_up_bit(liveness_a.authenticator_data):
            return ValidationResult(TransportVerdict.REJECT, "liveness_a: UP bit clear")

    if liveness_b is not None:
        if not check_up_bit(liveness_b.authenticator_data):
            return ValidationResult(TransportVerdict.REJECT, "liveness_b: UP bit clear")

    return ValidationResult(TransportVerdict.ACCEPT)


@dataclass
class PeerScoring:
    """Peer scoring for transport. (Law 7 partial)

    Peer scoring only for:
    - Forged signatures
    - Failed parses

    Local temporary PeerID denylist. No IP bans.
    """

    scores: dict[bytes, float]  # peer_id -> score (lower is worse)
    denylist: set[bytes]  # temporary local denylist
    denylist_threshold: float = -10.0

    def __init__(self) -> None:
        self.scores = {}
        self.denylist = set()

    def record_forged_signature(self, peer_id: bytes) -> None:
        """Penalize for forged signature."""
        self.scores[peer_id] = self.scores.get(peer_id, 0.0) - 5.0
        self._check_denylist(peer_id)

    def record_failed_parse(self, peer_id: bytes) -> None:
        """Penalize for failed parse on known version."""
        self.scores[peer_id] = self.scores.get(peer_id, 0.0) - 2.0
        self._check_denylist(peer_id)

    def record_good_edge(self, peer_id: bytes) -> None:
        """Small positive score for good behavior."""
        self.scores[peer_id] = min(0.0, self.scores.get(peer_id, 0.0) + 0.1)

    def _check_denylist(self, peer_id: bytes) -> None:
        if self.scores.get(peer_id, 0.0) <= self.denylist_threshold:
            self.denylist.add(peer_id)

    def is_denied(self, peer_id: bytes) -> bool:
        return peer_id in self.denylist

    def remove_from_denylist(self, peer_id: bytes) -> None:
        """Manual removal from denylist (local, revocable)."""
        self.denylist.discard(peer_id)
        self.scores[peer_id] = 0.0


def hash_integrity_check(data: bytes, expected_hash: bytes) -> bool:
    """Verify SHA-256 hash matches."""
    return hashlib.sha256(data).digest() == expected_hash


@dataclass
class FetchResult:
    """Result of fetching data from network."""

    success: bool
    data: Optional[bytes] = None
    timeout: bool = False
    error: Optional[str] = None

    @classmethod
    def ok(cls, data: bytes) -> "FetchResult":
        return cls(success=True, data=data)

    @classmethod
    def timed_out(cls) -> "FetchResult":
        return cls(success=False, timeout=True, error="timeout")

    @classmethod
    def failed(cls, error: str) -> "FetchResult":
        return cls(success=False, error=error)


def validate_fetched_artifact(
    fetch_result: FetchResult,
    expected_hash: bytes,
) -> ValidationResult:
    """Validate a fetched artifact.

    Timeout = Ignore (retry later).
    Hash mismatch = Reject.
    """
    if fetch_result.timeout:
        return ValidationResult(TransportVerdict.IGNORE, "fetch timeout")

    if not fetch_result.success:
        return ValidationResult(TransportVerdict.IGNORE, f"fetch failed: {fetch_result.error}")

    if not hash_integrity_check(fetch_result.data, expected_hash):
        return ValidationResult(TransportVerdict.REJECT, "hash mismatch")

    return ValidationResult(TransportVerdict.ACCEPT)
