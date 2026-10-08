# Human Trust Network

A root-and-branch profile. Bitcoin is the root. Each handoff has its own consignment. Named witnesses sign the transitions that are allowed to anchor.

This is not a validator network, a global ledger, or a Solidity contract. There is no chain here except Bitcoin. A personal chain is the off-chain history of one custody record, held by the parties who need it, anchored by a single-use seal.

This is not [The Gem](https://github.com/VincentLaRocca/The-Gem). The Gem is a design record and says it is not a chain. This repository stays out of it.

The first schema is a custody handoff. Copyright and agent identity are not part of that schema.

## What is on main

`personal-chains/schema_encoder.py` on this branch is a sketch. It does not do what a custody record needs.

- Witness checks compare `SHA-256(key || op_id)`. Anyone who knows the public key can produce a passing signature. They are not BIP-340 Schnorr.
- `issue()` does not track the current seal. The genesis seal can be closed twice, and an unknown seal is accepted.
- `issue()` does not call the witness check. A transfer is recorded whether or not anyone signed.
- A deed can mint extra rights. The kind string is not restricted. A cap stored on the schema is not the cap `issue()` enforces.

Do not build on that file. A local replacement exists and is not this commit.

`btc-root/operator_cold_leaf.py` is the part that matches its claim. A rotation must still commit to the genesis cold leaf. The cold key can spend the control output at any time. There is no delay and no CSV window. The confirmed spend wins.

## Three layers

```text
human-trust-network/
├── btc-root/            Bitcoin L1 anchor. Seal close is the only global fact.
├── personal-chains/     One consignment history per handoff.
└── human-witness/       Who must sign before a transition may anchor.
```

Bitcoin supplies order and a one-time spend. It does not store the pouch, the deed, or the identity of the signer. A key is not a person. A close proves that a seal was spent and that the consignment commits to that spend. It does not prove the item is genuine.

## License

MIT
