# Personal chains

One custody handoff, one history, held by the parties who receive the consignment.

Copyright and agent identity are not in this directory.

`schema_encoder.py` records a handoff only when the spent seal is current and a BIP-340 witness threshold signs the operation id. It does not mint. It does not connect to the Taproot cold leaf in `btc-root/`.
