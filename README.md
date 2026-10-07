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

Scripts in `btc-root/` are the seal profile. They are demonstrations, not a wallet.

| Script | Status |
| --- | --- |
| `hwdeed_regtest.py` | In-process deed. Tagged hashes, witness threshold, one close. Signatures are stand-ins. |
| `agent_seal_regtest.py` | Rotation, mint, cold-path race. No Taproot. |
| `operator_cold_leaf.py` | Operator-only check that a rotation still commits to the genesis cold leaf. |
| `agent_regtest_rpc.py` | Raw Taproot genesis, key-path rotation, script-path recovery. Dry-run builds transactions. A node has not accepted the script-path spend. |

`seal-profile` was the first landing place for this layer. This directory is the copy that belongs to the whole.

### 2. Personal chains

Each hardware deed, copyright master, or agent is its own contract.

- Global state is fixed at genesis: serial hash, master-file hash, or genesis weights.
- Owned rights are assigned to seals. A hardware deed has one title. A copyright has a master right plus capped license rights. An agent has one control right and capped instance rights.
- Transition metadata is not inherited. An inspection root, a license scope, or a version hash is attached to the close. It is not a field the next holder can edit in place.
- The consignment is the history. Parties who were not given it cannot see the current controller. That is the publication limit, not a missing consensus layer.

No consignment encoder is in this repository yet. The schemas below are the contract. The scripts do not emit them.

```text
HardwareTitleDeed_v1
  global: asset_type, issuer_pk, serial_hash, genesis doc roots, witness set
  owned:  title<1>
  transition: inspection_root?, witnesses

CopyrightMaster_v1
  global: master_file_hash, authorship claim, license_cap
  owned:  master<1>, license<license_cap>
  transition: issuing a license closes master and reopens it

SovereignAgent_v1
  global: genesis_weights, training_root, instance_cap, cold_leaf
  owned:  control<1>, instance<instance_cap>
  transition: pure rotation omits witnesses; upgrade or mint requires them
```

### 3. Human witness

The witness layer is a threshold over a genesis key set. It is not an identity directory.

- Genesis names the keys and the threshold `m`.
- A deed transfer, a copyright issuance, and an agent upgrade or instance mint need `k >= m` signatures from that set.
- A pure agent key rotation does not. That act is the controller, not the human layer.
- The cold key is not a witness. It is a script path on the control output. Public verifiers learn that leaf only when recovery spends it. The operator's wallet checks it on every rotation and stores the opening locally.

Nothing here enrolls a notary, routes a decentralized identifier, or ties a key to a person. A signature says the key signed. Who held the key is a record this repository does not keep.

## What a close proves

A confirmed Bitcoin spend of the sealed outpoint, whose anchor commits to the bundle id, with a consignment that meets the schema. It does not prove the document is true, the file is the work, or the process loaded the weights.

## License

MIT
