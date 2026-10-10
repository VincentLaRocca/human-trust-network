"""Ivan Vaughan Primitive - Decentralized trust network protocol.

Protocol Laws:
1. Node is a keypair. Nicknames are UI caches with zero weight.
2. Edge is dual-signed, content-addressed artifact hash.
3. Weight is zero until lens verifies structural external dependency.
4. Routing: one proposal, max 2 hops, Jaccard cost.
5. Liveness: CTAP2/FIDO2 with UP bit required.
6. Transport validates only global invariants.
7. GossipSub for new edges, DHT for history.
8. Failed sandbox writes nothing.
"""

__version__ = "0.1.0"
