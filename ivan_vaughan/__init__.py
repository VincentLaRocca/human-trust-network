"""Ivan Vaughan Primitive: Zero-trust collaborator-introduction protocol.

Protocol Laws:
1. A node is a keypair. Nicknames are UI caches with zero weight.
2. An edge is a dual-signed, content-addressed artifact hash with version-pinned roles.
3. Weight is zero until lens verifies a structural external dependency.
4. Routing: one proposal, max 2 hops, Jaccard cost.
5. Liveness: CTAP2/FIDO2 with static RP ID, UP bit required.
6. Transport validates only global invariants.
7. GossipSub for edges, DHT for history, bootstrap from config.
8. Failed sandbox writes nothing; mutual attestation after commit-reveal.
"""

__version__ = "0.1.0"
