# Personal chains

One custody handoff, one history, held by the parties who receive the consignment.

The first schema is that handoff. Copyright and agent identity are out of scope here.

`schema_encoder.py` on main does not enforce the handoff. Witness material is a hash of the public key. A seal can be closed twice. `issue()` does not require witnesses. Treat it as a sketch until it is replaced.
