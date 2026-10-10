#!/usr/bin/env python3
"""P2P daemon integration with libp2p.

Law 7: GossipSub for new edges. DHT for history. Bootstrap multiaddrs in a 
user-editable config. Peer scoring only for forged signatures and failed parses.
Local temporary PeerID denylist. No IP bans.

This module provides integration with libp2p for:
- GossipSub pubsub for broadcasting new edges
- Kademlia DHT for edge history lookup
- Peer management with scoring and denylist
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable, Awaitable, List, Set, Dict, Any

try:
    from .dht_sync import ValidationResult, GossipValidator, DHTSyncer
    from .edge_store import Edge, EdgeStore
    from .node import Node
except ImportError:
    from ivan_vaughan.dht_sync import ValidationResult, GossipValidator, DHTSyncer
    from ivan_vaughan.edge_store import Edge, EdgeStore
    from ivan_vaughan.node import Node


class P2PError(Exception):
    """Base exception for P2P operations."""
    pass


# Default topic for edge broadcasts
EDGE_TOPIC = "/ivan-vaughan/edges/1.0.0"

# Default DHT namespace
DHT_NAMESPACE = "/ivan-vaughan/edges/"


@dataclass
class BootstrapConfig:
    """Bootstrap configuration for P2P network.
    
    Law 7: Bootstrap multiaddrs in a user-editable config.
    """
    multiaddrs: List[str] = field(default_factory=list)
    config_path: Optional[Path] = None
    
    @classmethod
    def from_file(cls, path: Path) -> "BootstrapConfig":
        """Load bootstrap config from a JSON file."""
        if not path.exists():
            return cls(config_path=path)
        
        try:
            with open(path) as f:
                data = json.load(f)
            return cls(
                multiaddrs=data.get("bootstrap_multiaddrs", []),
                config_path=path,
            )
        except Exception as e:
            raise P2PError(f"failed to load bootstrap config: {e}")
    
    def save(self) -> None:
        """Save config to file."""
        if self.config_path is None:
            raise P2PError("no config path set")
        
        with open(self.config_path, 'w') as f:
            json.dump({"bootstrap_multiaddrs": self.multiaddrs}, f, indent=2)
    
    def add_multiaddr(self, addr: str) -> None:
        """Add a bootstrap multiaddr."""
        if addr not in self.multiaddrs:
            self.multiaddrs.append(addr)
    
    def remove_multiaddr(self, addr: str) -> None:
        """Remove a bootstrap multiaddr."""
        if addr in self.multiaddrs:
            self.multiaddrs.remove(addr)


@dataclass
class PeerInfo:
    """Information about a connected peer."""
    peer_id: bytes
    multiaddrs: List[str] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    connected: bool = False


class P2PDaemon:
    """Interface to libp2p for GossipSub and DHT operations.
    
    This class provides a high-level interface that can work with:
    1. The libp2p Python library directly
    2. A go-libp2p daemon via RPC
    3. A mock implementation for testing
    """
    
    def __init__(
        self,
        store: EdgeStore,
        local_node: Node,
        bootstrap_config: Optional[BootstrapConfig] = None,
        validator: Optional[GossipValidator] = None,
    ):
        self.store = store
        self.local_node = local_node
        self.bootstrap_config = bootstrap_config or BootstrapConfig()
        self.validator = validator or GossipValidator(store)
        self.syncer = DHTSyncer(store, local_node, self.validator)
        
        self._running = False
        self._connected_peers: Dict[bytes, PeerInfo] = {}
        self._subscriptions: Set[str] = set()
        self._message_handlers: Dict[str, List[Callable[[bytes, bytes], Awaitable[None]]]] = {}
    
    async def start(self) -> None:
        """Start the P2P daemon."""
        if self._running:
            return
        
        self._running = True
        
        # Subscribe to edge topic
        await self.subscribe(EDGE_TOPIC, self._handle_edge_message)
        
        # Bootstrap
        await self._bootstrap()
    
    async def stop(self) -> None:
        """Stop the P2P daemon."""
        self._running = False
        self._subscriptions.clear()
        self._connected_peers.clear()
    
    async def _bootstrap(self) -> None:
        """Connect to bootstrap nodes."""
        for addr in self.bootstrap_config.multiaddrs:
            try:
                await self.connect(addr)
            except Exception:
                pass  # Best effort
    
    async def connect(self, multiaddr: str) -> PeerInfo:
        """Connect to a peer by multiaddr."""
        # This would use libp2p to connect
        # For now, this is a placeholder
        raise NotImplementedError("connect to peer")
    
    async def disconnect(self, peer_id: bytes) -> None:
        """Disconnect from a peer."""
        if peer_id in self._connected_peers:
            del self._connected_peers[peer_id]
    
    async def subscribe(
        self,
        topic: str,
        handler: Callable[[bytes, bytes], Awaitable[None]],
    ) -> None:
        """Subscribe to a GossipSub topic."""
        self._subscriptions.add(topic)
        if topic not in self._message_handlers:
            self._message_handlers[topic] = []
        self._message_handlers[topic].append(handler)
    
    async def unsubscribe(self, topic: str) -> None:
        """Unsubscribe from a topic."""
        self._subscriptions.discard(topic)
        self._message_handlers.pop(topic, None)
    
    async def publish(self, topic: str, data: bytes) -> None:
        """Publish a message to a GossipSub topic."""
        if not self._running:
            raise P2PError("daemon not running")
        
        # This would use libp2p's GossipSub
        # For now, this is a placeholder
        raise NotImplementedError("publish to gossipsub")
    
    async def broadcast_edge(self, edge: Edge) -> None:
        """Broadcast a new edge to the network.
        
        Law 7: GossipSub for new edges.
        Law 8: Artifact pinned before broadcast.
        """
        if not self._running:
            raise P2PError("daemon not running")
        
        # Ensure edge is stored locally first (Law 8)
        self.store.store(edge)
        
        # Broadcast via GossipSub
        await self.publish(EDGE_TOPIC, edge.to_bytes())
    
    async def _handle_edge_message(self, peer_id: bytes, data: bytes) -> None:
        """Handle an incoming edge message from GossipSub."""
        # Validate with tripartite firewall
        def verify_sig(key: bytes, msg: bytes, sig: bytes) -> bool:
            return Node.verify(key, msg, sig, "ed25519")
        
        outcome = self.validator.validate_edge(
            raw_payload=data,
            peer_id=peer_id,
            verify_signature=verify_sig,
        )
        
        if outcome.result == ValidationResult.ACCEPT:
            # Forward to other peers (GossipSub handles this)
            pass
        elif outcome.result == ValidationResult.REJECT:
            # Message dropped, peer scored down
            pass
        # IGNORE: silently drop, no forwarding, no penalty
    
    async def dht_put(self, key: bytes, value: bytes) -> None:
        """Put a value in the DHT."""
        raise NotImplementedError("DHT put")
    
    async def dht_get(self, key: bytes) -> List[bytes]:
        """Get values from the DHT.
        
        PART 4.4: Returns raw bytes, no JSON encoding.
        """
        raise NotImplementedError("DHT get")
    
    async def dht_provide(self, key: bytes) -> None:
        """Announce that we can provide a key.
        
        PART 4.3: Provide for own keys and validated edge hashes.
        """
        raise NotImplementedError("DHT provide")
    
    async def dht_find_providers(self, key: bytes) -> List[PeerInfo]:
        """Find providers for a key in the DHT."""
        raise NotImplementedError("DHT find providers")
    
    async def request_edges_from_peer(
        self,
        peer_id: bytes,
        key: bytes,
    ) -> List[bytes]:
        """Request edges for a key from a specific peer.
        
        PART 4.4: Returns raw byte streams, no JSON encoding.
        """
        raise NotImplementedError("request edges from peer")
    
    async def sync_from_dht(self) -> int:
        """Sync edges from DHT, walking 2 hops.
        
        Law 7: DHT for history, walked 2 hops from the user's own keys.
        """
        async def fetch(key: bytes) -> List[bytes]:
            return await self.dht_get(key)
        
        def verify(key: bytes, msg: bytes, sig: bytes) -> bool:
            return Node.verify(key, msg, sig, "ed25519")
        
        return await self.syncer.walk_two_hops(fetch, verify)
    
    async def provide_keys(self) -> None:
        """Provide() for our keys in the DHT.
        
        PART 4.3: Provide for own root keys, validated edge hashes, and signer DIDs.
        """
        for key in self.syncer.get_keys_to_provide():
            try:
                await self.dht_provide(key)
            except Exception:
                pass  # Best effort
    
    @property
    def peer_count(self) -> int:
        """Number of connected peers."""
        return len(self._connected_peers)
    
    def is_peer_denied(self, peer_id: bytes) -> bool:
        """Check if a peer is in the local denylist.
        
        Law 7: Local temporary PeerID denylist. No IP bans.
        """
        return self.validator.is_in_denylist(peer_id)


class MockP2PDaemon(P2PDaemon):
    """Mock P2P daemon for testing."""
    
    def __init__(
        self,
        store: EdgeStore,
        local_node: Node,
        bootstrap_config: Optional[BootstrapConfig] = None,
        validator: Optional[GossipValidator] = None,
    ):
        super().__init__(store, local_node, bootstrap_config, validator)
        self._dht_store: Dict[bytes, List[bytes]] = {}
        self._published_messages: List[tuple[str, bytes]] = []
    
    async def connect(self, multiaddr: str) -> PeerInfo:
        """Mock connect - just creates a peer entry."""
        import hashlib
        peer_id = hashlib.sha256(multiaddr.encode()).digest()
        info = PeerInfo(peer_id=peer_id, multiaddrs=[multiaddr], connected=True)
        self._connected_peers[peer_id] = info
        return info
    
    async def publish(self, topic: str, data: bytes) -> None:
        """Mock publish - stores message for inspection."""
        self._published_messages.append((topic, data))
    
    async def dht_put(self, key: bytes, value: bytes) -> None:
        """Mock DHT put."""
        if key not in self._dht_store:
            self._dht_store[key] = []
        if value not in self._dht_store[key]:
            self._dht_store[key].append(value)
    
    async def dht_get(self, key: bytes) -> List[bytes]:
        """Mock DHT get."""
        return self._dht_store.get(key, [])
    
    async def dht_provide(self, key: bytes) -> None:
        """Mock DHT provide - no-op for testing."""
        pass
    
    async def dht_find_providers(self, key: bytes) -> List[PeerInfo]:
        """Mock find providers."""
        return []
    
    async def request_edges_from_peer(
        self,
        peer_id: bytes,
        key: bytes,
    ) -> List[bytes]:
        """Mock request - returns empty list."""
        return []
    
    def inject_dht_value(self, key: bytes, value: bytes) -> None:
        """Inject a value into the mock DHT for testing."""
        if key not in self._dht_store:
            self._dht_store[key] = []
        self._dht_store[key].append(value)
    
    def get_published_messages(self) -> List[tuple[str, bytes]]:
        """Get all published messages for testing."""
        return list(self._published_messages)
    
    def clear_published_messages(self) -> None:
        """Clear published messages."""
        self._published_messages.clear()
