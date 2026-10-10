# Human Trust Network

A root-and-branch profile. Bitcoin is the root. Each handoff has its own consignment. Named witnesses sign the transitions that are allowed to anchor.

This is not a validator network, a global ledger, or a Solidity contract. There is no chain here except Bitcoin. A personal chain is the off-chain history of one custody record, held by the parties who need it, anchored by a single-use seal.

This is not [The Gem](https://github.com/VincentLaRocca/The-Gem). The Gem is a design record and says it is not a chain. This repository stays out of it.

The first schema is a custody handoff. Copyright and agent identity are not in the encoder.

## Reference client (Android-first)

The practical path that binds a human, their agent, and the economic layer lives on the phone. How the phone performs and what its private protocols are remains the owner’s business; the public network only sees the signed events that leave the device.

- Day 1 the human registers (operational key + recovery-key commitment) and, on the same Android phone, registers their AI agent by signing a scoped delegation.
- The agent process and the economic layer (Lightning hold invoices, settlements, any bonds) co-locate on the same device. The agent acts on the human’s behalf.
- Human keys are secured on the phone (Android Keystore / StrongBox). Holding them cryptographically on a remote node is possible but makes less sense for this design.
- Any spend still requires the human’s signature, gated by the keystore + biometric path. The agent never holds raw spending authority or the recovery key.
- Autonomous control can be granted inside limits. The agent can never control the whole wallet stack. Stop-loss: at most 5 % of the relevant balance in any one given sequence. Anything above that requires explicit human signature.
- A phone’s unique internal ID is used only as a local uniqueness check so the same physical device is not registered twice. It is not part of the public identity, not published, and not used for authorization or recovery.
- Scoped agent keys are delegated locally; revocation stays on-device. The human can always tighten, pause, or cut the agent off without rotating their own identity.
- Public events published to the network contain only the signed records the phone chooses to emit.

The protocol and public record stay open and chain-agnostic. The reference client that makes human–agent cohabitation useful is opinionated and Android-first (keystore, BiometricPrompt, local intents/services). Supporting both platforms would split the secure path; Android gives one coherent stack.

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

A failed `weigh()` cuts this client's edge to every signer that missed the threshold. If `sponsor.py` paired that signer with an introducer, the edge to the sponsor and the introduction edge are cut too. The cut is local. The closed seal stays closed. A bond is not an identity and it does not raise the score.

Next step is a local regtest node, not another case. `live_bifurcation.py` has not been run. It needs `HTN_ANCHOR_SECRET` and a reachable bitcoind. No script-path spend is signed here.

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
