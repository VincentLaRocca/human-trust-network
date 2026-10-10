"""GossipSub/DHT network layer. (Law 7)

GossipSub for new edges. DHT for history, walked 2 hops from user's own keys.
Bootstrap multiaddrs live in a user-editable config.

This module provides an INTERFACE with an in-process test transport.
The validation, Ignore/Reject, re-provide and retry logic is REAL.

To bind a real libp2p implementation:
1. Implement NetworkTransport with py-libp2p
2. Load bootstrap multiaddrs from config file (default: ~/.ivan-vaughan/bootstrap.json)
3. Call set_transport() with the implementation

STUB: The actual libp2p networking is stubbed.
REAL: Validation, retry logic, re-provide logic, peer scoring.
"""

from __future__ import annotations

import json
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Callable, List, Dict, Set

from .edge import Edge
from .transport import (
    TransportVerdict,
    ValidationResult,
    validate_edge_transport,
    PeerScoring,
)


DEFAULT_CONFIG_PATH = Path.home() / ".ivan-vaughan" / "bootstrap.json"


class SyncState(Enum):
    """State of DHT sync for a key."""

    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED_RETRYABLE = "failed_retryable"  # Ignore - will retry


@dataclass
class KeySyncStatus:
    """Tracks sync status for a key. Does NOT mark synced until success."""

    key_id: bytes
    state: SyncState = SyncState.NOT_STARTED
    last_attempt: float = 0.0
    attempt_count: int = 0
    edges_found: List[bytes] = field(default_factory=list)  # edge hashes

    def mark_in_progress(self) -> None:
        self.state = SyncState.IN_PROGRESS
        self.last_attempt = time.time()
        self.attempt_count += 1

    def mark_completed(self, edges: List[bytes]) -> None:
        """Only mark completed on actual success."""
        self.state = SyncState.COMPLETED
        self.edges_found = edges

    def mark_failed_retryable(self) -> None:
        """DHT lookup failed - will retry. NOT marked as synced."""
        self.state = SyncState.FAILED_RETRYABLE

    def should_retry(self, min_interval: float = 60.0) -> bool:
        """Check if we should retry this key."""
        if self.state == SyncState.COMPLETED:
            return False
        if self.state == SyncState.NOT_STARTED:
            return True
        if self.state == SyncState.FAILED_RETRYABLE:
            return time.time() - self.last_attempt >= min_interval
        return False


class NetworkTransport(ABC):
    """Abstract interface for network transport.

    STUB: Implement with py-libp2p for real networking.
    """

    @abstractmethod
    def publish_edge(self, edge_data: bytes) -> bool:
        """Publish edge via GossipSub."""
        pass

    @abstractmethod
    def subscribe_edges(self, callback: Callable[[bytes, bytes], None]) -> None:
        """Subscribe to new edges. callback(peer_id, edge_data)."""
        pass

    @abstractmethod
    def dht_get(self, key: bytes) -> Optional[List[bytes]]:
        """Get edge hashes for a key from DHT. Returns None on failure."""
        pass

    @abstractmethod
    def dht_provide(self, key: bytes, edge_hash: bytes) -> bool:
        """Provide an edge hash for a key. Any holder must re-provide."""
        pass

    @abstractmethod
    def fetch_edge(self, edge_hash: bytes) -> Optional[bytes]:
        """Fetch edge data by hash. Returns None on failure/timeout."""
        pass

    @abstractmethod
    def get_peer_id(self) -> bytes:
        """Get our peer ID."""
        pass


class InProcessTestTransport(NetworkTransport):
    """In-process test transport for unit testing.

    STUB: Not real networking.
    REAL: All validation logic is exercised.
    """

    def __init__(self) -> None:
        self.peer_id = os.urandom(32)
        self.edges: Dict[bytes, bytes] = {}  # edge_hash -> edge_data
        self.key_edges: Dict[bytes, Set[bytes]] = {}  # key_id -> edge_hashes
        self.subscribers: List[Callable[[bytes, bytes], None]] = []
        self.failure_mode: Optional[str] = None  # For testing failures

    def set_failure_mode(self, mode: Optional[str]) -> None:
        """Set failure mode for testing. None = normal, 'timeout', 'error'."""
        self.failure_mode = mode

    def publish_edge(self, edge_data: bytes) -> bool:
        if self.failure_mode:
            return False
        try:
            edge = Edge.from_wire(edge_data)
            edge_hash = edge.edge_hash
            self.edges[edge_hash] = edge_data
            for node in edge.nodes:
                self.key_edges.setdefault(node.node_id, set()).add(edge_hash)
            for callback in self.subscribers:
                callback(self.peer_id, edge_data)
            return True
        except Exception:
            return False

    def subscribe_edges(self, callback: Callable[[bytes, bytes], None]) -> None:
        self.subscribers.append(callback)

    def dht_get(self, key: bytes) -> Optional[List[bytes]]:
        if self.failure_mode == "timeout":
            return None
        if self.failure_mode == "error":
            return None
        edges = self.key_edges.get(key, set())
        return list(edges) if edges else []

    def dht_provide(self, key: bytes, edge_hash: bytes) -> bool:
        if self.failure_mode:
            return False
        self.key_edges.setdefault(key, set()).add(edge_hash)
        return True

    def fetch_edge(self, edge_hash: bytes) -> Optional[bytes]:
        if self.failure_mode == "timeout":
            return None
        return self.edges.get(edge_hash)

    def get_peer_id(self) -> bytes:
        return self.peer_id

    def inject_edge(self, edge: Edge) -> None:
        """Inject an edge directly for testing."""
        edge_data = edge.to_wire()
        edge_hash = edge.edge_hash
        self.edges[edge_hash] = edge_data
        for node in edge.nodes:
            self.key_edges.setdefault(node.node_id, set()).add(edge_hash)


_transport: Optional[NetworkTransport] = None


def set_transport(transport: NetworkTransport) -> None:
    """Set the network transport implementation."""
    global _transport
    _transport = transport


def get_transport() -> NetworkTransport:
    """Get the current transport. Creates test transport if none set."""
    global _transport
    if _transport is None:
        _transport = InProcessTestTransport()
    return _transport


def load_bootstrap_config(path: Path = DEFAULT_CONFIG_PATH) -> List[str]:
    """Load bootstrap multiaddrs from user config.

    Returns empty list if file doesn't exist (first run).
    """
    if not path.exists():
        return []
    try:
        with open(path) as f:
            config = json.load(f)
            return config.get("bootstrap_multiaddrs", [])
    except (json.JSONDecodeError, IOError):
        return []


def save_bootstrap_config(multiaddrs: List[str], path: Path = DEFAULT_CONFIG_PATH) -> None:
    """Save bootstrap multiaddrs to user config."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump({"bootstrap_multiaddrs": multiaddrs}, f, indent=2)


@dataclass
class NetworkNode:
    """A node's view of the network.

    Implements Law 7:
    - GossipSub for new edges
    - DHT for history, walked 2 hops from own keys
    - Peer scoring only for forged signatures and failed parses
    - Local temporary PeerID denylist, no IP bans
    """

    my_keys: List[bytes]  # node_ids of our keys
    transport: NetworkTransport = field(default_factory=get_transport)
    scoring: PeerScoring = field(default_factory=PeerScoring)
    sync_status: Dict[bytes, KeySyncStatus] = field(default_factory=dict)
    local_edges: Dict[bytes, Edge] = field(default_factory=dict)  # edge_hash -> Edge
    pending_retry: List[bytes] = field(default_factory=list)  # edge_hashes to retry

    def __post_init__(self) -> None:
        self.transport.subscribe_edges(self._on_edge_received)

    def _on_edge_received(self, peer_id: bytes, edge_data: bytes) -> None:
        """Handle incoming edge from GossipSub."""
        if self.scoring.is_denied(peer_id):
            return  # Ignore from denied peers

        result = validate_edge_transport(edge_data)

        if result.verdict == TransportVerdict.REJECT:
            if "signature" in (result.reason or ""):
                self.scoring.record_forged_signature(peer_id)
            else:
                self.scoring.record_failed_parse(peer_id)
            return

        if result.verdict == TransportVerdict.IGNORE:
            return

        try:
            edge = Edge.from_wire(edge_data)
            self.local_edges[edge.edge_hash] = edge
            self.scoring.record_good_edge(peer_id)
            self._re_provide_edge(edge)
        except Exception:
            self.scoring.record_failed_parse(peer_id)

    def _re_provide_edge(self, edge: Edge) -> None:
        """Re-provide edge for both keys. Any holder must re-provide."""
        for node in edge.nodes:
            self.transport.dht_provide(node.node_id, edge.edge_hash)

    def publish_edge(self, edge: Edge) -> bool:
        """Publish a new edge via GossipSub."""
        edge_data = edge.to_wire()
        success = self.transport.publish_edge(edge_data)
        if success:
            self.local_edges[edge.edge_hash] = edge
            self._re_provide_edge(edge)
        return success

    def sync_key(self, key_id: bytes) -> List[Edge]:
        """Sync edges for a key from DHT.

        Does NOT mark synced on failure - will retry.
        Providers may omit edges - we can't invent missing ones.
        """
        status = self.sync_status.setdefault(key_id, KeySyncStatus(key_id))

        if not status.should_retry():
            return [self.local_edges[h] for h in status.edges_found if h in self.local_edges]

        status.mark_in_progress()

        edge_hashes = self.transport.dht_get(key_id)
        if edge_hashes is None:
            status.mark_failed_retryable()
            return []

        valid_edges: List[Edge] = []
        valid_hashes: List[bytes] = []

        for edge_hash in edge_hashes:
            if edge_hash in self.local_edges:
                valid_edges.append(self.local_edges[edge_hash])
                valid_hashes.append(edge_hash)
                continue

            edge_data = self.transport.fetch_edge(edge_hash)
            if edge_data is None:
                self.pending_retry.append(edge_hash)
                continue

            result = validate_edge_transport(edge_data)
            if result.verdict == TransportVerdict.REJECT:
                continue
            if result.verdict == TransportVerdict.IGNORE:
                self.pending_retry.append(edge_hash)
                continue

            try:
                edge = Edge.from_wire(edge_data)
                self.local_edges[edge.edge_hash] = edge
                self._re_provide_edge(edge)
                valid_edges.append(edge)
                valid_hashes.append(edge.edge_hash)
            except Exception:
                continue

        status.mark_completed(valid_hashes)
        return valid_edges

    def sync_two_hop_neighborhood(self) -> List[Edge]:
        """Sync all edges within 2 hops of our keys.

        DHT for history, walked 2 hops from user's own keys.
        """
        all_edges: List[Edge] = []
        hop1_keys: Set[bytes] = set()

        for key_id in self.my_keys:
            edges = self.sync_key(key_id)
            all_edges.extend(edges)
            for edge in edges:
                for node in edge.nodes:
                    if node.node_id != key_id:
                        hop1_keys.add(node.node_id)

        for key_id in hop1_keys:
            edges = self.sync_key(key_id)
            all_edges.extend(edges)

        return list({e.edge_hash: e for e in all_edges}.values())

    def retry_pending(self) -> int:
        """Retry fetching edges that previously failed (Ignore)."""
        retried = 0
        still_pending = []

        for edge_hash in self.pending_retry:
            edge_data = self.transport.fetch_edge(edge_hash)
            if edge_data is None:
                still_pending.append(edge_hash)
                continue

            result = validate_edge_transport(edge_data)
            if result.verdict == TransportVerdict.ACCEPT:
                try:
                    edge = Edge.from_wire(edge_data)
                    self.local_edges[edge.edge_hash] = edge
                    self._re_provide_edge(edge)
                    retried += 1
                except Exception:
                    pass
            elif result.verdict == TransportVerdict.IGNORE:
                still_pending.append(edge_hash)

        self.pending_retry = still_pending
        return retried
