"""SQLite storage for edges.

Edges land at weight 0, lens scores asynchronously before pathfinding.
Uses CBOR for binary-safe storage.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List

from .edge import Edge
from .wire import encode, decode


@dataclass
class StoredEdge:
    """An edge as stored in SQLite."""

    edge_hash: bytes
    edge_data: bytes  # CBOR-encoded
    weight: float
    sink_verified: bool
    parser_version: int
    created_at: float
    scored_at: Optional[float]


class EdgeStore:
    """SQLite storage for edges.

    Edges are stored at weight 0 until lens scores them.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path))
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS edges (
                edge_hash BLOB PRIMARY KEY,
                edge_data BLOB NOT NULL,
                weight REAL DEFAULT 0.0,
                sink_verified INTEGER DEFAULT 0,
                parser_version INTEGER NOT NULL,
                created_at REAL NOT NULL,
                scored_at REAL
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_edges_weight ON edges(weight)
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS node_edges (
                node_id BLOB NOT NULL,
                edge_hash BLOB NOT NULL,
                PRIMARY KEY (node_id, edge_hash),
                FOREIGN KEY (edge_hash) REFERENCES edges(edge_hash)
            )
        """)
        self.conn.commit()

    def store_edge(self, edge: Edge) -> bool:
        """Store an edge at weight 0. Returns True if newly stored."""
        edge_hash = edge.edge_hash
        edge_data = edge.to_wire()
        now = time.time()

        try:
            self.conn.execute(
                """INSERT OR IGNORE INTO edges 
                   (edge_hash, edge_data, weight, sink_verified, parser_version, created_at)
                   VALUES (?, ?, 0.0, 0, ?, ?)""",
                (edge_hash, edge_data, edge.parser_version, now)
            )
            for node in edge.nodes:
                self.conn.execute(
                    "INSERT OR IGNORE INTO node_edges (node_id, edge_hash) VALUES (?, ?)",
                    (node.node_id, edge_hash)
                )
            self.conn.commit()
            return self.conn.total_changes > 0
        except sqlite3.Error:
            return False

    def get_edge(self, edge_hash: bytes) -> Optional[StoredEdge]:
        """Get a stored edge by hash."""
        cursor = self.conn.execute(
            "SELECT * FROM edges WHERE edge_hash = ?", (edge_hash,)
        )
        row = cursor.fetchone()
        if row:
            return StoredEdge(
                edge_hash=row[0],
                edge_data=row[1],
                weight=row[2],
                sink_verified=bool(row[3]),
                parser_version=row[4],
                created_at=row[5],
                scored_at=row[6],
            )
        return None

    def update_weight(
        self,
        edge_hash: bytes,
        weight: float,
        sink_verified: bool,
    ) -> bool:
        """Update edge weight after lens scoring."""
        now = time.time()
        try:
            self.conn.execute(
                """UPDATE edges SET weight = ?, sink_verified = ?, scored_at = ?
                   WHERE edge_hash = ?""",
                (weight, int(sink_verified), now, edge_hash)
            )
            self.conn.commit()
            return self.conn.total_changes > 0
        except sqlite3.Error:
            return False

    def get_edges_for_node(self, node_id: bytes) -> List[StoredEdge]:
        """Get all edges for a node."""
        cursor = self.conn.execute(
            """SELECT e.* FROM edges e
               JOIN node_edges ne ON e.edge_hash = ne.edge_hash
               WHERE ne.node_id = ?""",
            (node_id,)
        )
        return [
            StoredEdge(
                edge_hash=row[0],
                edge_data=row[1],
                weight=row[2],
                sink_verified=bool(row[3]),
                parser_version=row[4],
                created_at=row[5],
                scored_at=row[6],
            )
            for row in cursor.fetchall()
        ]

    def get_unscored_edges(self) -> List[StoredEdge]:
        """Get edges that haven't been scored yet."""
        cursor = self.conn.execute(
            "SELECT * FROM edges WHERE scored_at IS NULL"
        )
        return [
            StoredEdge(
                edge_hash=row[0],
                edge_data=row[1],
                weight=row[2],
                sink_verified=bool(row[3]),
                parser_version=row[4],
                created_at=row[5],
                scored_at=row[6],
            )
            for row in cursor.fetchall()
        ]

    def get_all_edges(self, min_weight: float = 0.0) -> List[Edge]:
        """Get all edges with weight >= threshold."""
        cursor = self.conn.execute(
            "SELECT edge_data FROM edges WHERE weight >= ?", (min_weight,)
        )
        edges = []
        for row in cursor.fetchall():
            try:
                edges.append(Edge.from_wire(row[0]))
            except Exception:
                continue
        return edges

    def close(self) -> None:
        self.conn.close()
