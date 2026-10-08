# Personal chains

One contract, one history, held by the parties who receive the consignment.

Encoded in `schema_encoder.py`:

- HardwareTitleDeed_v1 — one title right, no mint
- CopyrightMaster_v1 — master right plus a license cap
- SovereignAgent_v1 — control right plus an instance cap

A transition cannot update a seal in place. Issuing a license or an instance closes the parent seal and reopens it. The encoder rejects a second close of the same seal, a mint past the cap, and a witnessed transition without a BIP-340 threshold.
