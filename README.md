# Human Trust Network

A root-and-branch profile. Bitcoin is the root. Each asset has its own consignment history. Humans sign the transitions that are allowed to anchor.

This is not a validator network, a global ledger, or a Solidity contract. There is no chain here except Bitcoin. A "personal blockchain" is the off-chain history of one contract, held by the parties who need it, anchored by a single-use seal.

This is not [The Gem](https://github.com/VincentLaRocca/The-Gem). The Gem is a design record. This repository is the profile that record does not contain.

## Three layers

```text
human-trust-network/
├── btc-root/            Bitcoin L1 anchor. Seal close is the only global fact.
├── personal-chains/     One consignment history per asset. Not a shared ledger.
└── human-witness/       Who must sign before a transition may anchor.
```

### 1. BTC root

Bitcoin supplies order and a one-time spend. It does not store the deed, the media file, or the model.

- The contract id is the asset. It is the genesis commitment. It does not change when the seal moves.
- The unspent seal is the current controller. Pinning an agent to an outpoint is wrong. Key rotation closes the seal and opens another. The contract id stays.
- A right moves only when its seal closes. A recovery spend is a close of that same outpoint, script-path, and it must anchor a bundle. A sweep with no bundle burns the right.
- The confirmed spend wins. A later consignment cannot rewrite it.
- The cold key can spend the control output at any time. There is no delay and no CSV window. Recovery is a race: whoever confirms first wins.

`btc-root/operator_cold_leaf.py` is the operator check that a rotation still commits to the genesis cold leaf. The in-process deed ledger, the agent ledger, and the Core regtest builder are not in this tree yet.

### 2. Personal chains

Each hardware deed, copyright master, or agent is its own contract. `personal-chains/schema_encoder.py` encodes the three schemas, requires a BIP-340 witness threshold on witnessed transitions, rejects a second close of the current seal, and enforces the license and instance caps.

- Global state is fixed at genesis: serial hash, master-file hash, or genesis weights.
- Owned rights are assigned to seals. A hardware deed has one title. A copyright has a master right plus capped license rights. An agent has one control right and capped instance rights.
- Transition metadata is not inherited. An inspection root, a license scope, or a version hash is attached to the close. It is not a field the next holder can edit in place.
- The consignment is the history. Parties who were not given it cannot see the current controller. That is the publication limit, not a missing consensus layer.

### 3. Human witness

The witness layer is a threshold over a genesis key set. It is not an identity directory.

- Genesis names the keys and the threshold `m`.
- A deed transfer, a copyright issuance, and an agent upgrade or instance mint need `k >= m` signatures from that set.
- A pure agent key rotation does not. That act is the controller, not the human layer.
- The cold key is not a witness. It is a script path on the control output, and it can spend at any time. Public verifiers learn that leaf only when recovery spends it. The operator's wallet checks it on every rotation and stores the opening locally.

Nothing here enrolls a notary, routes a decentralized identifier, or ties a key to a person. A signature says the key signed. Who held the key is a record this repository does not keep.

## What a close proves

A confirmed Bitcoin spend of the sealed outpoint, whose anchor commits to the bundle id, with a consignment that meets the schema. It does not prove the document is true, the file is the work, or the process loaded the weights.

## License

MIT
