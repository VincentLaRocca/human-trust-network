# Human Trust Network

A root-and-branch profile. Bitcoin is the root. Each handoff has its own consignment. Named witnesses sign the transitions that are allowed to anchor.

This is not a validator network, a global ledger, or a Solidity contract. There is no chain here except Bitcoin. A personal chain is the off-chain history of one custody record, held by the parties who need it, anchored by a single-use seal.

This is not [The Gem](https://github.com/VincentLaRocca/The-Gem). The Gem is a design record and says it is not a chain. This repository stays out of it.

The first schema is a custody handoff. Copyright and agent identity are not in the encoder.

## What is on main

`personal-chains/schema_encoder.py` at `029f51b` is a custody handoff, not the earlier sketch.

- Witness checks are BIP-340 Schnorr over the operation id. A hash of the public key does not pass.
- `transfer()` spends only the current seal. A second close of the genesis seal is rejected.
- The witness threshold runs inside `transfer()`. An unsigned handoff is not recorded.
- There is one title. The encoder does not mint extra rights, and it does not accept an arbitrary kind string.
- Seal blinding must be 32 nonzero bytes.

`btc-root/operator_cold_leaf.py` is separate. A rotation must still commit to the genesis cold leaf. The cold key can spend the control output at any time. There is no delay and no CSV window. The confirmed spend wins. The encoder does not check that Taproot leaf.

`human-witness/max_path.py` scores witness keys from the observer's neighborhood. The score is the strongest chain, hop limit at most 2, default threshold 0.45. It does not sum paths and it does not apply a degree penalty. A client does not need the global graph.

A confirmed seal close is global. `transfer()` either has the signatures or it does not. `weigh()` may then refuse to move this client's title pointer. Disagreement across clients is the policy, not a consensus failure. `human-witness/bifurcation.py` measures only that third step, and only for the hub's own key. The tally is `consider()`: `ADVANCED` against `SPENT_UNADVANCED`.

A failed `weigh()` does not drop the edge. Stress test: after `SPENT_UNADVANCED`, this client should delete its edge to every signer that missed the threshold. That cut is not implemented. The closed seal stays closed.

A key is not a person. A close proves that a seal was spent and that the consignment commits to that spend. It does not prove the item is genuine.

## Three layers

```text
human-trust-network/
├── btc-root/            Bitcoin L1 anchor. Seal close is the only global fact.
├── personal-chains/     One consignment history per handoff.
└── human-witness/       Who must sign before a transition may anchor.
```

## License

MIT
