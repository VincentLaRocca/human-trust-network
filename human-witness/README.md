# Human witness

Threshold signatures from the genesis witness set.

Required on genesis, deed transfer, license issuance, agent upgrade, and instance mint.
Not required on a pure agent key rotation.
Not the cold key. The cold key is a Taproot script path on the control output.

No identity directory lives here. A key is not a person.

`max_path.py` is the client-side score for witness keys already in a local neighborhood. It keeps the strongest chain only, hop limit 1 or 2, default threshold 0.45. It does not sum paths, penalize degree, or run a global max-flow.

`client_observer.py` runs the gates in order. Signature and seal checks are shared. The anchor proof is supplied, not fetched. `max_path` is local. A failed score marks the seal spent and does not move the title pointer.
