"""Weight and sink verification via lens. (Law 3)

Weight is zero until the user's own lens verifies a structural external
dependency (a build or call that breaks without the artifact).

A fee, an OP_RETURN, or a payload flag is not a sink.
The cascade stops at that artifact.

Sink verification goes through a light client or user-configured endpoints
with a Merkle proof, not set membership. Used only by the lens, never by transport.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Callable

from .edge import Edge
from .parser import ParsedRole, roles_from_artifact


class SinkType(Enum):
    """Types of structural sinks. NOT transport gates."""

    BUILD_DEPENDENCY = "build_dependency"
    RUNTIME_CALL = "runtime_call"
    IMPORT_CHAIN = "import_chain"


@dataclass(frozen=True)
class MerkleProof:
    """A Merkle proof for sink verification.

    REAL structure, but proof verification depends on the sink type
    and external light client.
    """

    root: bytes
    leaf: bytes
    path: List[tuple[bytes, bool]]  # (sibling_hash, is_left)
    proof_type: str  # identifies which tree/chain

    def verify(self) -> bool:
        """Verify the Merkle proof."""
        current = self.leaf
        for sibling, is_left in self.path:
            if is_left:
                current = hashlib.sha256(sibling + current).digest()
            else:
                current = hashlib.sha256(current + sibling).digest()
        return current == self.root


@dataclass(frozen=True)
class SinkVerification:
    """Result of verifying a structural sink."""

    verified: bool
    sink_type: Optional[SinkType]
    proof: Optional[MerkleProof]
    artifact_hash: bytes
    error: Optional[str] = None

    @property
    def is_structural(self) -> bool:
        """A structural dependency that breaks without the artifact."""
        return self.verified and self.sink_type is not None


class SinkVerifier(ABC):
    """Abstract interface for sink verification.

    STUB: Implement with light client for specific chain/system.
    REAL: Interface and proof verification logic.
    """

    @abstractmethod
    def verify_build_dependency(
        self,
        artifact_hash: bytes,
        dependent_build: bytes,
    ) -> SinkVerification:
        """Verify artifact is a build dependency."""
        pass

    @abstractmethod
    def verify_runtime_call(
        self,
        artifact_hash: bytes,
        call_site: bytes,
    ) -> SinkVerification:
        """Verify artifact is called at runtime."""
        pass


class LocalBuildVerifier(SinkVerifier):
    """Local build system verifier.

    Checks if removing the artifact would break a build.
    """

    def __init__(self, build_graph: Dict[bytes, List[bytes]]) -> None:
        self.build_graph = build_graph

    def verify_build_dependency(
        self,
        artifact_hash: bytes,
        dependent_build: bytes,
    ) -> SinkVerification:
        deps = self.build_graph.get(dependent_build, [])
        if artifact_hash in deps:
            leaf = hashlib.sha256(artifact_hash + dependent_build).digest()
            root = self._compute_merkle_root(deps, dependent_build)
            proof = MerkleProof(
                root=root,
                leaf=leaf,
                path=self._compute_path(deps, artifact_hash),
                proof_type="build_dependency",
            )
            return SinkVerification(
                verified=proof.verify(),
                sink_type=SinkType.BUILD_DEPENDENCY,
                proof=proof,
                artifact_hash=artifact_hash,
            )
        return SinkVerification(
            verified=False,
            sink_type=None,
            proof=None,
            artifact_hash=artifact_hash,
            error="not a dependency",
        )

    def _compute_merkle_root(self, deps: List[bytes], build_id: bytes) -> bytes:
        """Compute Merkle root of dependencies."""
        if not deps:
            return hashlib.sha256(build_id).digest()
        leaves = [hashlib.sha256(d + build_id).digest() for d in sorted(deps)]
        while len(leaves) > 1:
            next_level = []
            for i in range(0, len(leaves), 2):
                if i + 1 < len(leaves):
                    next_level.append(hashlib.sha256(leaves[i] + leaves[i + 1]).digest())
                else:
                    next_level.append(leaves[i])
            leaves = next_level
        return leaves[0]

    def _compute_path(
        self, deps: List[bytes], artifact: bytes
    ) -> List[tuple[bytes, bool]]:
        """Compute Merkle path for a dependency."""
        return []

    def verify_runtime_call(
        self,
        artifact_hash: bytes,
        call_site: bytes,
    ) -> SinkVerification:
        return SinkVerification(
            verified=False,
            sink_type=None,
            proof=None,
            artifact_hash=artifact_hash,
            error="runtime verification not implemented",
        )


@dataclass(frozen=True)
class WeightedEdge:
    """An edge with its lens-computed weight."""

    edge: Edge
    weight: float
    roles: List[ParsedRole]
    sink_verified: bool

    @classmethod
    def zero(cls, edge: Edge) -> "WeightedEdge":
        """Create an edge with zero weight (not yet verified)."""
        return cls(edge=edge, weight=0.0, roles=[], sink_verified=False)


@dataclass
class Lens:
    """User's lens for scoring edges.

    Weight is zero until a structural external dependency is verified.
    The lens runs asynchronously and does not block transport.
    """

    sink_verifier: Optional[SinkVerifier]
    artifact_fetcher: Callable[[bytes], Optional[bytes]]
    scored_edges: Dict[bytes, WeightedEdge] = field(default_factory=dict)
    pending_verification: List[bytes] = field(default_factory=list)

    def add_edge(self, edge: Edge) -> None:
        """Add an edge at weight 0. Will be scored asynchronously."""
        if edge.edge_hash not in self.scored_edges:
            self.scored_edges[edge.edge_hash] = WeightedEdge.zero(edge)
            self.pending_verification.append(edge.edge_hash)

    def score_edge(self, edge_hash: bytes, build_context: Optional[bytes] = None) -> WeightedEdge:
        """Score an edge by verifying structural dependency.

        Weight remains 0 until sink is verified.
        """
        if edge_hash not in self.scored_edges:
            return None

        weighted = self.scored_edges[edge_hash]
        edge = weighted.edge

        artifact = self.artifact_fetcher(edge.artifact_hash)
        if artifact is None:
            return weighted

        roles = roles_from_artifact(artifact, edge.artifact_type)

        weight = 0.0
        sink_verified = False

        if self.sink_verifier and build_context:
            verification = self.sink_verifier.verify_build_dependency(
                edge.artifact_hash, build_context
            )
            if verification.is_structural:
                weight = 1.0
                sink_verified = True

        self.scored_edges[edge_hash] = WeightedEdge(
            edge=edge,
            weight=weight,
            roles=roles,
            sink_verified=sink_verified,
        )
        return self.scored_edges[edge_hash]

    def process_pending(self, build_context: Optional[bytes] = None) -> int:
        """Process pending edge verifications. Returns count scored."""
        scored = 0
        still_pending = []

        for edge_hash in self.pending_verification:
            result = self.score_edge(edge_hash, build_context)
            if result and result.weight > 0:
                scored += 1
            elif result and result.weight == 0:
                still_pending.append(edge_hash)

        self.pending_verification = still_pending
        return scored

    def get_weight(self, edge_hash: bytes) -> float:
        """Get current weight for an edge. 0 if not scored or not verified."""
        weighted = self.scored_edges.get(edge_hash)
        return weighted.weight if weighted else 0.0

    def filter_by_weight(self, min_weight: float = 0.0) -> List[WeightedEdge]:
        """Get edges with weight >= threshold."""
        return [w for w in self.scored_edges.values() if w.weight >= min_weight]
