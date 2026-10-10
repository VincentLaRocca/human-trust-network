#!/usr/bin/env python3
"""Edge storage with canonical hash computation.

Law 2: Edge is a dual-signed, content-addressed artifact hash.
Law 3: Weight is zero until the user's own lens verifies a structural external dependency.

Canonical edge hash: sort the two signatures (or keys) before SHA-256(artifact_hash || sig_a || sig_b).
Edge lands in local SQLite at weight 0. The user's lens scores it asynchronously.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Iterator


class EdgeError(Exception):
    """Base exception for edge operations."""
    pass


class EdgeStatus(Enum):
    """Edge validation status."""
    PENDING = "pending"  # Not yet validated
    VALID = "valid"      # Passed validation, weight still 0
    INVALID = "invalid"  # Failed validation


@dataclass(frozen=True)
class Edge:
    """A dual-signed edge between two nodes.
    
    The edge is content-addressed by its canonical hash, computed as:
    SHA-256(artifact_hash || sorted_sig_a || sorted_sig_b)
    
    Weight is ALWAYS 0 on landing. The user's lens scores asynchronously.
    """
    artifact_hash: bytes  # SHA-256 of the artifact
    signer_a: bytes       # Public key of first signer (32 bytes x-only)
    signer_b: bytes       # Public key of second signer (32 bytes x-only)
    signature_a: bytes    # Signature from signer_a
    signature_b: bytes    # Signature from signer_b
    parser_version: str   # Version-pinned parser that derived roles
    roles: tuple[str, ...] = field(default_factory=tuple)  # Roles from canonical parser
    
    def __post_init__(self) -> None:
        if len(self.artifact_hash) != 32:
            raise EdgeError("artifact_hash must be 32 bytes")
        if len(self.signer_a) != 32 or len(self.signer_b) != 32:
            raise EdgeError("signers must be 32-byte x-only keys")
        if self.signer_a == self.signer_b:
            raise EdgeError("edge cannot be self-referential")
    
    @property
    def canonical_hash(self) -> bytes:
        """Compute the canonical edge hash.
        
        Sorts signatures by the signer keys to ensure order-independence.
        """
        if self.signer_a < self.signer_b:
            sig_first, sig_second = self.signature_a, self.signature_b
        else:
            sig_first, sig_second = self.signature_b, self.signature_a
        return hashlib.sha256(
            self.artifact_hash + sig_first + sig_second
        ).digest()
    
    @property
    def signers(self) -> frozenset[bytes]:
        """The set of signer keys on this edge."""
        return frozenset([self.signer_a, self.signer_b])
    
    def to_bytes(self) -> bytes:
        """Serialize edge to bytes for transport."""
        parser_bytes = self.parser_version.encode('utf-8')
        roles_bytes = b'\x00'.join(r.encode('utf-8') for r in self.roles)
        return (
            self.artifact_hash +
            self.signer_a +
            self.signer_b +
            len(self.signature_a).to_bytes(2, 'big') + self.signature_a +
            len(self.signature_b).to_bytes(2, 'big') + self.signature_b +
            len(parser_bytes).to_bytes(2, 'big') + parser_bytes +
            len(roles_bytes).to_bytes(2, 'big') + roles_bytes
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "Edge":
        """Deserialize edge from bytes."""
        if len(data) < 32 + 32 + 32 + 2:
            raise EdgeError("data too short")
        pos = 0
        artifact_hash = data[pos:pos+32]; pos += 32
        signer_a = data[pos:pos+32]; pos += 32
        signer_b = data[pos:pos+32]; pos += 32
        sig_a_len = int.from_bytes(data[pos:pos+2], 'big'); pos += 2
        signature_a = data[pos:pos+sig_a_len]; pos += sig_a_len
        sig_b_len = int.from_bytes(data[pos:pos+2], 'big'); pos += 2
        signature_b = data[pos:pos+sig_b_len]; pos += sig_b_len
        parser_len = int.from_bytes(data[pos:pos+2], 'big'); pos += 2
        parser_version = data[pos:pos+parser_len].decode('utf-8'); pos += parser_len
        roles_len = int.from_bytes(data[pos:pos+2], 'big'); pos += 2
        roles_bytes = data[pos:pos+roles_len]
        roles = tuple(r.decode('utf-8') for r in roles_bytes.split(b'\x00') if r)
        return cls(
            artifact_hash=artifact_hash,
            signer_a=signer_a,
            signer_b=signer_b,
            signature_a=signature_a,
            signature_b=signature_b,
            parser_version=parser_version,
            roles=roles,
        )


@dataclass
class StoredEdge:
    """An edge stored in the local database."""
    edge: Edge
    weight: float = 0.0  # Always 0 on landing
    status: EdgeStatus = EdgeStatus.PENDING
    created_at: float = field(default_factory=time.time)
    scored_at: Optional[float] = None


class EdgeStore:
    """Local SQLite store for edges.
    
    All edges land at weight 0. The user's lens scores asynchronously.
    """
    
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS edges (
        canonical_hash BLOB PRIMARY KEY,
        artifact_hash BLOB NOT NULL,
        signer_a BLOB NOT NULL,
        signer_b BLOB NOT NULL,
        signature_a BLOB NOT NULL,
        signature_b BLOB NOT NULL,
        parser_version TEXT NOT NULL,
        roles TEXT NOT NULL,
        weight REAL DEFAULT 0.0,
        status TEXT DEFAULT 'pending',
        created_at REAL NOT NULL,
        scored_at REAL
    );
    
    CREATE INDEX IF NOT EXISTS idx_signer_a ON edges(signer_a);
    CREATE INDEX IF NOT EXISTS idx_signer_b ON edges(signer_b);
    CREATE INDEX IF NOT EXISTS idx_artifact ON edges(artifact_hash);
    CREATE INDEX IF NOT EXISTS idx_status ON edges(status);
    """
    
    def __init__(self, db_path: Path | str = ":memory:"):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()
    
    def _init_db(self) -> None:
        self._conn = sqlite3.connect(self.db_path)
        self._conn.executescript(self.SCHEMA)
        self._conn.commit()
    
    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
    
    def store(self, edge: Edge) -> StoredEdge:
        """Store an edge at weight 0. Returns the stored edge."""
        if self._conn is None:
            raise EdgeError("store is closed")
        
        canonical = edge.canonical_hash
        created_at = time.time()
        roles_str = '\x00'.join(edge.roles)
        
        try:
            self._conn.execute(
                """INSERT INTO edges 
                   (canonical_hash, artifact_hash, signer_a, signer_b, 
                    signature_a, signature_b, parser_version, roles,
                    weight, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0.0, 'pending', ?)""",
                (canonical, edge.artifact_hash, edge.signer_a, edge.signer_b,
                 edge.signature_a, edge.signature_b, edge.parser_version, roles_str,
                 created_at)
            )
            self._conn.commit()
        except sqlite3.IntegrityError:
            pass  # Already exists
        
        return StoredEdge(edge=edge, weight=0.0, created_at=created_at)
    
    def get(self, canonical_hash: bytes) -> Optional[StoredEdge]:
        """Retrieve an edge by its canonical hash."""
        if self._conn is None:
            raise EdgeError("store is closed")
        
        cursor = self._conn.execute(
            """SELECT artifact_hash, signer_a, signer_b, signature_a, signature_b,
                      parser_version, roles, weight, status, created_at, scored_at
               FROM edges WHERE canonical_hash = ?""",
            (canonical_hash,)
        )
        row = cursor.fetchone()
        if row is None:
            return None
        
        (artifact_hash, signer_a, signer_b, signature_a, signature_b,
         parser_version, roles_str, weight, status, created_at, scored_at) = row
        
        roles = tuple(r for r in roles_str.split('\x00') if r)
        edge = Edge(
            artifact_hash=artifact_hash,
            signer_a=signer_a,
            signer_b=signer_b,
            signature_a=signature_a,
            signature_b=signature_b,
            parser_version=parser_version,
            roles=roles,
        )
        return StoredEdge(
            edge=edge,
            weight=weight,
            status=EdgeStatus(status),
            created_at=created_at,
            scored_at=scored_at,
        )
    
    def edges_for_signer(self, signer: bytes) -> Iterator[StoredEdge]:
        """Get all edges involving a specific signer."""
        if self._conn is None:
            raise EdgeError("store is closed")
        
        cursor = self._conn.execute(
            """SELECT canonical_hash FROM edges 
               WHERE signer_a = ? OR signer_b = ?""",
            (signer, signer)
        )
        for (canonical_hash,) in cursor:
            stored = self.get(canonical_hash)
            if stored:
                yield stored
    
    def update_weight(self, canonical_hash: bytes, weight: float, status: EdgeStatus) -> None:
        """Update the weight of an edge after lens scoring."""
        if self._conn is None:
            raise EdgeError("store is closed")
        
        self._conn.execute(
            """UPDATE edges SET weight = ?, status = ?, scored_at = ?
               WHERE canonical_hash = ?""",
            (weight, status.value, time.time(), canonical_hash)
        )
        self._conn.commit()
    
    def pending_edges(self) -> Iterator[StoredEdge]:
        """Get all edges pending scoring."""
        if self._conn is None:
            raise EdgeError("store is closed")
        
        cursor = self._conn.execute(
            "SELECT canonical_hash FROM edges WHERE status = 'pending'"
        )
        for (canonical_hash,) in cursor:
            stored = self.get(canonical_hash)
            if stored:
                yield stored
    
    def has_edge(self, canonical_hash: bytes) -> bool:
        """Check if an edge exists in the store."""
        if self._conn is None:
            raise EdgeError("store is closed")
        
        cursor = self._conn.execute(
            "SELECT 1 FROM edges WHERE canonical_hash = ?",
            (canonical_hash,)
        )
        return cursor.fetchone() is not None


def canonical_edge_hash(artifact_hash: bytes, signer_a: bytes, signer_b: bytes,
                        signature_a: bytes, signature_b: bytes) -> bytes:
    """Compute canonical edge hash with order-independent sorting.
    
    Sort the two signatures by their signer keys before hashing.
    """
    if signer_a < signer_b:
        sig_first, sig_second = signature_a, signature_b
    else:
        sig_first, sig_second = signature_b, signature_a
    return hashlib.sha256(artifact_hash + sig_first + sig_second).digest()
