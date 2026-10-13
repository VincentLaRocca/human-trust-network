# Human Trust Network

Protocol Document  
Relationship to the Courier Chain of Trust  
October 2026

## 1. Purpose

The Human Trust Network is a root-and-branch system for custody, attestation, and paid work. Bitcoin is the only chain. Each asset or job carries its own off-chain personal consignment history, anchored by a single-use Bitcoin seal. Named human witnesses must sign before a transition is allowed to anchor. There is no native token.

It is a general protocol. It can be seeded by a concrete application such as the Courier Chain of Trust, but it does not depend on any single application remaining active.

## 2. The Seed

The seed is the first Bitcoin seal close.

When a Courier Chain of Trust handoff closes its first seal, that confirmed Bitcoin transaction is the seed. The Human Trust Network treats it as the initial global fact and the starting point for the local witness neighborhood. Keys that signed or witnessed that close become the earliest entries available for strongest-path scoring (hop limit ≤ 2).

No other coupling is required. The Courier Chain of Trust may continue, pause, or cease; the seed remains a valid Bitcoin fact that any later participant can reference.

## 3. Core Properties (unchanged)

- **btc-root**: Confirmed seal close is the only global fact.
- **personal-chains**: One ordered history per handoff or job, held by the parties who need it.
- **human-witness**: Local scoring; disagreement across clients is policy, not consensus failure.
- Human operational keys stay on the device (Android Keystore / StrongBox + biometric). Offline recovery-key commitment can override. Agents receive scoped, limited delegation only.
- Public events contain only hashes, job identifiers, and public keys.
- Offline signing is first-class; the seal and OpenTimestamps proof are obtained later and do not rewrite local history.

## 4. Bootstrap Path

1. A Courier Chain of Trust pilot executes a real handoff and closes the first Bitcoin seal.
2. That seal close is published as the seed.
3. The participating keys form the initial neighborhood.
4. Additional users (target: 22 real participants who each complete a verifiable registration and at least one transition or witness signature) may join by referencing the seed or subsequent closes.
5. Once the 22-user gate is cleared and sustained cycles have been run, the network can be shown as a working artifact.

The courier system supplies the seed; it does not operate the network.

## 5. What This System Does Not Do

- It does not require the Courier Chain of Trust to remain the sole or primary user.
- It does not mint extra rights or maintain a global asset registry.
- A seal close proves a consignment was anchored; it does not prove the item is genuine.
- A key is not a person.

## 6. Status

Custody encoder, witness scoring, incentives prototype, and voucher-pool specification exist. The seed relationship is now explicit. Production use, the first real seed close, and the 22-user threshold remain ahead.
