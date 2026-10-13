# Courier Chain of Trust

Business and Operating Document  
October 2026

## 1. Purpose

The Courier Chain of Trust is a concrete logistics and handoff system for physical or digital assets. It produces durable, offline-verifiable proof that a specific item left a sender, passed through one or more couriers, and was accepted by an authorized recipient.

It is not a general-purpose network. It is a focused application that generates Bitcoin seal closes. The first such seal close it produces is the seed that the Human Trust Network can recognize.

## 2. Parties and Roles

- **Sender**: Originates the asset and the initial consignment record. Holds an operational key on device.
- **Courier**: Takes physical or logical possession and is responsible for the next handoff. May be a person or a bounded agent under human authorization.
- **Recipient**: Accepts the asset and closes the current leg. Must be able to verify the consignment offline.
- **Witnesses** (optional per leg): Named keys that must sign before a seal may close. Threshold is set per market or per job.

All human keys remain on the participant’s device (keystore + biometric). No party holds another party’s spending authority.

## 3. Core Flow

1. Sender creates a consignment record (hash of item description, parties, terms) and an unspent seal.
2. Courier accepts possession and signs the handoff. Signatures and the personal chain can be completed offline.
3. Recipient verifies the chain locally, accepts, and co-signs.
4. When connectivity is available, the required witness threshold is checked and the Bitcoin seal is closed. The confirmed seal close is the only global fact for that leg.
5. The next leg (if any) begins with a new seal that commits to the prior close.

A failed or incomplete leg does not rewrite prior history. The closed seal stays closed.

## 4. The Seed

The seed is the first Bitcoin seal close produced by a Courier Chain of Trust handoff.

That single confirmed transaction is the bootstrap event recognized by the Human Trust Network. It establishes the initial global fact and the starting neighborhood of keys that participated in or witnessed the close. Subsequent courier handoffs may continue independently; the Human Trust Network may use the seed as its genesis anchor without requiring ongoing operational coupling.

## 5. Business Model

- Direct fees for handoff services (Lightning or on-chain).
- Enterprise contracts for repeated high-value routes (studios, rights holders, construction milestones, specialized logistics).
- Optional bonded performance by couriers; bonds are released or forfeited according to the personal-chain record and any dispute event published by the recipient.
- No native token. Revenue is payment for verifiable service.

The system can operate profitably on courier fees alone. Participation in the broader Human Trust Network is not required for a courier business to function.

## 6. What This System Does Not Do

- It does not maintain a global ledger of all assets.
- It does not prove the underlying item is genuine; it proves the consignment record was accepted and anchored.
- It does not require every observer to store every history.
- It does not replace the Human Trust Network; it can seed it.

## 7. Status

Design complete enough for a minimal pilot (one sender, one courier, one recipient, one seal close). Production hardening, real-money cycles, and the first seed close remain ahead.
