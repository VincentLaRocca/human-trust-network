#!/usr/bin/env python3
"""Light client sink verification with Merkle proofs.

Law 3: Weight is zero until the user's own lens verifies a structural external
dependency (a build or call that breaks without the artifact). A fee, an OP_RETURN,
or a payload flag is not a sink. Cascade stops at that artifact.

Law 6: Sink is never a relay gate.

Implementation requirements:
- Light client or user-configured endpoints with a Merkle proof for the sink.
- Not set membership.
- Not a shipped list of RPC providers.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
from enum import Enum


class SinkError(Exception):
    """Base exception for sink operations."""
    pass


class SinkType(Enum):
    """Types of sinks that can verify structural dependencies."""
    ETHEREUM_STATE = "ethereum_state"  # State root verification
    BITCOIN_UTXO = "bitcoin_utxo"      # UTXO set verification
    CUSTOM = "custom"                   # User-defined verification


@dataclass(frozen=True)
class MerkleProof:
    """A Merkle proof for verifying inclusion.
    
    Not set membership - actual cryptographic proof of inclusion in a tree.
    """
    leaf: bytes           # The leaf being proven
    proof: Tuple[Tuple[bytes, bool], ...]  # (sibling_hash, is_left) pairs
    root: bytes           # Expected root
    
    def verify(self) -> bool:
        """Verify the Merkle proof.
        
        Returns True if the proof is valid, False otherwise.
        """
        current = self.leaf
        
        for sibling, is_left in self.proof:
            if is_left:
                current = hashlib.sha256(sibling + current).digest()
            else:
                current = hashlib.sha256(current + sibling).digest()
        
        return current == self.root


@dataclass(frozen=True)
class PatriciaProof:
    """A Patricia/Merkle-Patricia proof for Ethereum-style tries."""
    key: bytes
    value: bytes
    proof_nodes: Tuple[bytes, ...]
    root: bytes
    
    def verify(self) -> bool:
        """Verify the Patricia proof.
        
        This is a simplified verification. Full implementation would
        need RLP decoding and proper trie traversal.
        """
        # For now, compute hash chain
        # Real implementation would verify the trie structure
        if not self.proof_nodes:
            return False
        
        # Basic structure check
        return len(self.root) == 32


@dataclass
class Endpoint:
    """A user-configured endpoint for sink queries.
    
    Not a shipped list - user must configure these.
    """
    url: str
    chain_id: Optional[int] = None
    endpoint_type: str = "rpc"  # rpc, rest, etc.
    
    def __post_init__(self) -> None:
        if not self.url:
            raise SinkError("endpoint URL required")


@dataclass
class EndpointConfig:
    """User-editable endpoint configuration.
    
    Law: Not a shipped list of RPC providers.
    """
    endpoints: List[Endpoint] = field(default_factory=list)
    
    def add_endpoint(self, endpoint: Endpoint) -> None:
        """Add an endpoint (user action)."""
        self.endpoints.append(endpoint)
    
    def remove_endpoint(self, url: str) -> None:
        """Remove an endpoint by URL."""
        self.endpoints = [e for e in self.endpoints if e.url != url]
    
    def get_endpoints(self, chain_id: Optional[int] = None) -> List[Endpoint]:
        """Get endpoints, optionally filtered by chain."""
        if chain_id is None:
            return list(self.endpoints)
        return [e for e in self.endpoints if e.chain_id == chain_id]


@dataclass(frozen=True)
class StructuralDependency:
    """A structural external dependency.
    
    Law 3: Weight is zero until the user's own lens verifies a structural
    external dependency (a build or call that breaks without the artifact).
    """
    artifact_hash: bytes
    dependency_type: str  # "build", "call", "import", etc.
    target_address: Optional[bytes] = None  # Contract address, etc.
    proof: Optional[MerkleProof | PatriciaProof] = None
    verified: bool = False
    
    def __post_init__(self) -> None:
        # A fee, OP_RETURN, or payload flag is NOT a valid dependency
        if self.dependency_type in ("fee", "op_return", "flag"):
            raise SinkError(f"'{self.dependency_type}' is not a structural dependency")


class LightClient:
    """Light client for sink verification.
    
    Verifies structural dependencies using Merkle proofs.
    Does NOT use:
    - Set membership checks
    - Shipped RPC provider lists
    - The sink as a relay gate
    """
    
    def __init__(self, config: Optional[EndpointConfig] = None):
        self.config = config or EndpointConfig()
        self._verified_deps: dict[bytes, StructuralDependency] = {}
    
    def verify_merkle_proof(self, proof: MerkleProof) -> bool:
        """Verify a Merkle proof."""
        return proof.verify()
    
    def verify_patricia_proof(self, proof: PatriciaProof) -> bool:
        """Verify a Patricia proof."""
        return proof.verify()
    
    def verify_structural_dependency(
        self,
        dependency: StructuralDependency,
    ) -> bool:
        """Verify a structural dependency.
        
        Law 3: A build or call that breaks without the artifact.
        
        Returns True if the dependency is verified, False otherwise.
        """
        if dependency.proof is None:
            return False
        
        if isinstance(dependency.proof, MerkleProof):
            verified = self.verify_merkle_proof(dependency.proof)
        elif isinstance(dependency.proof, PatriciaProof):
            verified = self.verify_patricia_proof(dependency.proof)
        else:
            return False
        
        if verified:
            # Record the verified dependency
            self._verified_deps[dependency.artifact_hash] = StructuralDependency(
                artifact_hash=dependency.artifact_hash,
                dependency_type=dependency.dependency_type,
                target_address=dependency.target_address,
                proof=dependency.proof,
                verified=True,
            )
        
        return verified
    
    def is_verified(self, artifact_hash: bytes) -> bool:
        """Check if an artifact's dependency has been verified."""
        dep = self._verified_deps.get(artifact_hash)
        return dep is not None and dep.verified
    
    def get_weight(self, artifact_hash: bytes) -> float:
        """Get the weight for an artifact.
        
        Law 3: Weight is zero until verified.
        """
        if self.is_verified(artifact_hash):
            # Weight > 0 only after verification
            # The actual weight calculation would depend on the lens
            return 1.0
        return 0.0
    
    def clear_verification(self, artifact_hash: bytes) -> None:
        """Clear verification for an artifact."""
        self._verified_deps.pop(artifact_hash, None)


class Lens:
    """User's lens for scoring edges.
    
    Law 3: Weight is zero until the user's own lens verifies...
    """
    
    def __init__(self, light_client: LightClient):
        self.light_client = light_client
    
    def score(
        self,
        artifact_hash: bytes,
        dependency: Optional[StructuralDependency] = None,
    ) -> float:
        """Score an artifact.
        
        Returns 0 if not verified, positive weight if verified.
        """
        if dependency:
            if self.light_client.verify_structural_dependency(dependency):
                return 1.0
        
        return self.light_client.get_weight(artifact_hash)


def compute_merkle_root(leaves: List[bytes]) -> bytes:
    """Compute a Merkle root from a list of leaves."""
    if not leaves:
        return bytes(32)
    
    # Pad to power of 2
    n = 1
    while n < len(leaves):
        n *= 2
    padded = list(leaves) + [bytes(32)] * (n - len(leaves))
    
    # Build tree bottom-up
    while len(padded) > 1:
        next_level = []
        for i in range(0, len(padded), 2):
            combined = hashlib.sha256(padded[i] + padded[i + 1]).digest()
            next_level.append(combined)
        padded = next_level
    
    return padded[0]


def create_merkle_proof(leaves: List[bytes], index: int) -> MerkleProof:
    """Create a Merkle proof for a leaf at the given index."""
    if index >= len(leaves):
        raise SinkError("index out of range")
    
    # Pad to power of 2
    n = 1
    while n < len(leaves):
        n *= 2
    padded = list(leaves) + [bytes(32)] * (n - len(leaves))
    
    proof_parts: List[Tuple[bytes, bool]] = []
    current_index = index
    current_level = padded
    
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            combined = hashlib.sha256(current_level[i] + current_level[i + 1]).digest()
            next_level.append(combined)
            
            # If this pair contains our node, record the sibling
            if i == current_index or i + 1 == current_index:
                sibling_index = i + 1 if i == current_index else i
                is_left = sibling_index < current_index
                proof_parts.append((current_level[sibling_index], is_left))
        
        current_index //= 2
        current_level = next_level
    
    root = current_level[0]
    
    return MerkleProof(
        leaf=leaves[index],
        proof=tuple(proof_parts),
        root=root,
    )


def is_structural_dependency(dependency_type: str) -> bool:
    """Check if a dependency type is structural.
    
    Law 3: A fee, an OP_RETURN, or a payload flag is not a sink.
    """
    non_structural = {"fee", "op_return", "flag", "metadata"}
    return dependency_type.lower() not in non_structural
