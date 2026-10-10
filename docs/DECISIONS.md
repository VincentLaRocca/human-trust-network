# Ivan Vaughan Primitive - Implementation Decisions

This document records the library choices and design decisions for the Ivan Vaughan Primitive implementation.

## Library Choices

### Cryptography

| Component | Library | Why |
|-----------|---------|-----|
| **FIDO2/CTAP2** | `fido2` (python-fido2) | Maintained Yubico library with real authenticatorData parsing, UP/UV bit extraction, and COSE key verification. Preferred over custom parsing because FIDO2 is complex and security-critical. |
| **Ed25519 signatures** | `cryptography` | Standard library for Python cryptography, well-maintained, audited. Used for node keypairs and edge signing. |
| **Schnorr/secp256k1** | `embit` | Already used in the existing codebase for BIP-340 Schnorr signatures. Maintains consistency with `btc-root/` and `personal-chains/`. |
| **SHA-256** | `hashlib` (stdlib) | Standard library, no external dependency needed. |

### Networking

| Component | Library | Why |
|-----------|---------|-----|
| **libp2p** | `libp2p` | Python implementation of libp2p for GossipSub and Kademlia DHT. Provides peer discovery, pubsub, and DHT in one package. |
| **HTTP client** | `urllib.request` (stdlib) | Matches existing codebase pattern in `btc-root/builder.py`. No need for additional dependencies. |

### Storage

| Component | Library | Why |
|-----------|---------|-----|
| **Edge store** | `sqlite3` (stdlib) | Lightweight, embedded, zero-config. Edges land locally with weight 0; no need for distributed database. |

### Alternatives Considered

1. **FIDO2 parsing**: Considered manual authenticatorData parsing but rejected due to:
   - Complex binary format with optional extensions
   - Security implications of incorrect parsing
   - `fido2` library is well-tested and maintained

2. **libp2p alternatives**:
   - `go-libp2p` daemon with RPC: More mature but requires running a separate process
   - Custom P2P: Rejected - reinventing GossipSub and DHT is error-prone
   - Chose `libp2p` Python library for native integration

3. **Merkle proof library**:
   - Considered using `py-merkle-tree` or similar
   - Implemented custom for simplicity - Merkle proofs are straightforward
   - Custom allows exact control over hash function and proof format

## Protocol Laws Enforcement

### Fully Enforced

| Law | Implementation |
|-----|----------------|
| 1. Node is a keypair | `node.py`: `Node` class wraps a private key, `NodeID` is deterministic from public key |
| 2. Edge is dual-signed | `edge_store.py`: `Edge` requires two signers and two signatures |
| 3. Weight zero until verified | `edge_store.py`: All edges land with `weight=0.0` |
| 4. Max 2 hops | `routing.py`: `RouteProposal` raises error if `len(path) > 2` |
| 5. UP bit required | `liveness.py`: `LivenessVerifier.verify()` returns `REJECT_UP_CLEAR` if UP not set |
| 6. Tripartite validation | `dht_sync.py`: `ValidationResult` enum with `ACCEPT`, `REJECT`, `IGNORE` |
| 7. No IP bans | `dht_sync.py`: Only PeerID denylist, no IP-based blocking |
| 8. Artifact pinned before broadcast | `p2p_daemon.py`: `broadcast_edge()` stores locally before publish |

### Partially Enforced (Requires Integration)

| Law | Status | Notes |
|-----|--------|-------|
| Sink verification | Implemented | `light_client.py` provides Merkle proof verification; actual sink chain integration requires user-configured endpoints |
| DHT 2-hop walk | Implemented | `DHTSyncer.walk_two_hops()` exists but requires actual libp2p DHT connection |
| GossipSub forwarding | Implemented | Validation returns correct result but actual forwarding depends on libp2p integration |

## Hard Prohibitions Compliance

| Prohibition | Enforcement |
|-------------|-------------|
| No central tracker | DHT is decentralized, bootstrap addrs are user-configurable |
| No oracle allowlist | No hardcoded oracles; user configures endpoints |
| No sink check in relay path | `dht_sync.py` validates without sink lookup; sink is asynchronous via Lens |
| No shipped RPC providers | `EndpointConfig` starts empty; user adds endpoints |
| No AAGUID allowlist | `liveness.py` never checks AAGUID |
| No UV requirement | Only UP bit checked, UV is optional |
| No personhood claim | Liveness proves presence, not personhood |
| No free-text roles | `canonical_parser.py` only allows `repo:` namespace roles |
| No IP bans | `PeerScore` tracks peer_id only, no IP logging |

## File Structure

```
ivan-vaughan/
├── __init__.py         # Package metadata and protocol law summary
├── node.py             # Law 1: Node as keypair
├── edge_store.py       # Laws 2,3: Dual-signed edges, weight 0 landing
├── liveness.py         # Law 5: FIDO2 with UP bit
├── canonical_parser.py # Law 2: Version-pinned role derivation
├── routing.py          # Law 4: 2-hop Jaccard routing, hollow-route
├── dht_sync.py         # Laws 6,7: Tripartite validation, peer scoring
├── p2p_daemon.py       # Law 7: GossipSub/DHT integration
└── light_client.py     # Law 3: Merkle proof sink verification

tests/
├── test_liveness.py       # FIDO2 tests with software authenticator
├── test_edge_store.py     # Canonical hash, weight 0, serialization
├── test_dht_sync.py       # Validation results, IGNORE on unknown version
├── test_canonical_parser.py # Git commit parsing, role derivation
├── test_routing.py        # Jaccard cost, hollow-route
└── test_light_client.py   # Merkle proofs, structural dependencies
```

## Test Coverage

Tests use real cryptographic operations:

1. **FIDO2**: Software authenticator generates real ECDSA signatures over authenticator data
2. **Signatures**: Ed25519 signing and verification for edges
3. **Merkle proofs**: Real SHA-256 proof generation and verification
4. **Canonical hash**: Verified order-independence with different signer orderings

## Future Work

1. **Full libp2p integration**: The P2P daemon has placeholder methods; full integration requires connecting to the libp2p network
2. **Ethereum light client**: PatriciaProof verification needs full RLP decoding
3. **Bitcoin UTXO verification**: Requires SPV proof support
4. **Parser upgrades**: Add new parser versions without reclassifying old edges
