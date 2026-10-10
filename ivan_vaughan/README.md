# Ivan Vaughan Primitive

Zero-trust collaborator-introduction protocol.

## Protocol Laws (Locked)

### Law 1: Node is a Keypair
**Code:** `keys.py` | **Tests:** `test_keys.py`

A node is a keypair. Nicknames are UI caches with zero weight. Unlinked aliases are hermetic.

- `NodeKey`: Content-addressed node identity (SHA-256 of algorithm || public_bytes)
- `NodeKeyPair`: Node with signing capability (Ed25519 or ES256)
- `Nickname`: UI-only label, zero protocol weight

### Law 2: Edge is Dual-Signed Artifact Hash
**Code:** `edge.py`, `parser.py` | **Tests:** `test_edge.py`, `test_parser.py`

An edge is a dual-signed, content-addressed artifact hash. Roles come only from a canonical parser on the raw bytes, version-pinned on the edge. Upgrades do not reclassify old edges. No free-text roles.

- **Canonical edge hash:** `SHA-256(artifact_hash || sig_a || sig_b)` with signatures sorted by `node_id`
- **Parser version:** Pinned at creation, stored with edge
- **Roles:** `repo:commit_author` (author header key), `repo:reviewer` (second key signing review payload)
- **No substring matching, no default roles for unknown signers**

### Law 3: Weight is Zero Until Structural Dependency Verified
**Code:** `lens.py` | **Tests:** `test_lens.py`

Weight is zero until the user's own lens verifies a structural external dependency (a build or call that breaks without the artifact). A fee, an OP_RETURN, or a payload flag is not a sink. The cascade stops at that artifact.

- `Lens`: Async scoring, doesn't block transport
- `SinkVerifier`: Interface for Merkle-proof-based verification
- `LocalBuildVerifier`: Verifies build dependencies
- Edges land at weight 0, lens scores asynchronously before pathfinding

### Law 4: Routing with Jaccard Cost
**Code:** `routing.py` | **Tests:** `test_routing.py`

One proposal, max 2 hops, Jaccard cost on 2-hop neighborhoods. The complement is the set-difference of derived roles. Hollow-route is a local, revocable mask, never a graph write.

- `find_route()`: Returns single best proposal
- `build_neighborhood()`: Builds 2-hop neighborhood
- `jaccard_cost()`: 1 - Jaccard similarity
- `HollowRoute`: Local mask, revocable, never modifies graph

### Law 5: CTAP2/FIDO2 Liveness
**Code:** `fido.py` | **Tests:** `test_fido.py`

CTAP2/FIDO2 with a static RP ID. Challenge = SHA-256(peer_key || artifact_hash || peer_nonce), where the nonce is the counterparty's. UP bit required. Real signature verification. No AAGUID allowlist, no UV requirement, no personhood claim.

- **Uses python-fido2 for REAL authenticatorData parsing**
- `LivenessChallenge`: Challenge construction with counterparty's nonce
- `verify_liveness()`: Full verification including UP bit check
- Test fixtures with real ES256/EdDSA signatures

**Negative tests:** UP clear, wrong challenge, wrong nonce owner, tampered authData, bad signature

### Law 6: Transport Validates Global Invariants Only
**Code:** `transport.py` | **Tests:** `test_transport.py`

Transport validates only global invariants: schema, known parser version, hash integrity, canonical parse, and presence-backed signatures. Unknown parser version or fetch timeout = Ignore (no penalty, no forward). Reject only on a known-version parse failure, hash mismatch, clear UP bit, or bad signature. The sink is never a relay gate.

- `TransportVerdict`: ACCEPT, IGNORE, REJECT
- `validate_edge_transport()`: Full transport-layer validation
- Unknown parser version → Ignore
- Timeout → Ignore (retry later)
- Bad signature → Reject

### Law 7: GossipSub for Edges, DHT for History
**Code:** `network.py` | **Tests:** `test_network.py`

GossipSub for new edges. DHT for history, walked 2 hops from the user's own keys. Bootstrap multiaddrs live in a user-editable config. Peer scoring only for forged signatures and failed parses. Local temporary PeerID denylist. No IP bans.

- `NetworkTransport`: Interface for network operations (STUB)
- `InProcessTestTransport`: Test implementation with real validation
- `NetworkNode`: Full sync and publish logic
- `PeerScoring`: Forged signatures, failed parses; local denylist
- **Any holder re-provides edges, not just owner**
- **Failed DHT lookup → retry, NOT marked synced**

### Law 8: Failed Sandbox Writes Nothing
**Code:** `sandbox.py` | **Tests:** `test_sandbox.py`

A failed sandbox writes nothing. Mutual attestation happens only after commit-reveal of presence-backed signatures. The artifact is pinned before broadcast.

- `SandboxState`: Tracks attestation progress
- `AttestationProtocol`: Commit-reveal flow
- `Commitment`/`Reveal`: Cryptographic commit-reveal
- Artifact must be pinned before finalize

## Implementation Requirements

### FIDO2 with Real Crypto
**Files:** `fido.py`, `test_fido.py`

Uses python-fido2 for:
- Real authenticatorData parsing via `AuthenticatorData` class
- UP-bit check on actual flag byte
- Real COSE key parsing and signature verification

Test vectors generated with real ES256/EdDSA keys include negative tests for:
- UP clear
- Wrong challenge
- Wrong nonce owner
- Tampered authData
- Bad signature

### Canonical Parser for Git Commits
**Files:** `parser.py`, `test_parser.py`

- `repo:commit_author`: Key in `author-key` header
- `repo:reviewer`: Second key signing `ReviewPayload` over commit hash
- No substring matching
- No default role for leftover signers
- Version-pinned at `PARSER_VERSION = 1`

### Sink Verification via Merkle Proof
**Files:** `lens.py`, `test_lens.py`

- Light client interface via `SinkVerifier` ABC
- `MerkleProof` with real verification
- Used only by lens, never by transport
- Fee/OP_RETURN/flag NOT a sink

### Canonical Edge Hash (Order-Independent)
**Files:** `edge.py`, `test_edge.py`

```python
sigs = sorted([(sig_a.node_id, sig_a.signature), (sig_b.node_id, sig_b.signature)])
edge_hash = SHA-256(artifact_hash || sigs[0][1] || sigs[1][1])
```

Order-independence tested explicitly in `test_edge.py::TestCanonicalEdgeHash`.

### Historical Sync Robustness
**Files:** `network.py`, `test_network.py`

Regression tests for prior dht_sync.py flaws:
1. Key NOT marked synced until DHT lookup succeeds
2. Any holder re-provides, not just owner
3. Ignore and Reject are distinct verdicts
4. Provider not trusted for edge validity
5. CBOR preserves signature bytes (no JSON)

### Binary-Safe Wire Format (CBOR)
**Files:** `wire.py`, `test_wire.py`

- Uses `cbor2` library
- No JSON round-trip of signature bytes
- Canonical encoding for determinism

### SQLite Storage at Weight 0
**Files:** `store.py`, `test_store.py`

- Edges land at weight 0
- Lens scores asynchronously
- Index by both node IDs

## Stubs vs Real Code

### REAL (Cryptographic Reality)
- All signature verification (Ed25519, ES256)
- FIDO2 authenticatorData parsing and UP-bit check
- Challenge construction and verification
- Edge hash computation
- Parser version pinning
- Transport validation (Ignore vs Reject)
- Peer scoring logic
- Retry/re-provide logic
- Commit-reveal protocol
- CBOR serialization
- SQLite storage
- Routing algorithms

### STUB (Interface with Test Transport)
- **`NetworkTransport`**: Abstract interface for libp2p
  - `InProcessTestTransport`: In-process test implementation
  - Validation logic is REAL, only network I/O is stubbed
- **`SinkVerifier`**: Abstract interface for light clients
  - `LocalBuildVerifier`: Local build graph verifier

### Binding Real libp2p

To bind a real libp2p implementation:

1. Implement `NetworkTransport` interface with py-libp2p
2. Load bootstrap multiaddrs from `~/.ivan-vaughan/bootstrap.json`:
   ```json
   {
     "bootstrap_multiaddrs": [
       "/ip4/1.2.3.4/tcp/4001/p2p/QmPeerId..."
     ]
   }
   ```
3. Call `set_transport(your_implementation)`

## Running Tests

```bash
cd ivan-vaughan
pip install pytest
python -m pytest tests/ -v
```

## Module Summary

| Module | Purpose | Law |
|--------|---------|-----|
| `keys.py` | Node keypair identity | 1 |
| `edge.py` | Dual-signed edges | 2 |
| `parser.py` | Git commit parser | 2 |
| `fido.py` | CTAP2/FIDO2 liveness | 5 |
| `routing.py` | Jaccard cost routing | 4 |
| `transport.py` | Transport validation | 6 |
| `network.py` | GossipSub/DHT layer | 7 |
| `lens.py` | Weight/sink verification | 3 |
| `store.py` | SQLite storage | - |
| `sandbox.py` | Commit-reveal attestation | 8 |
| `wire.py` | CBOR wire format | - |
