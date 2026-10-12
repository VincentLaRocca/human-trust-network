# Human Trust Network

White Paper — Draft 0.4  
October 2026

### Abstract

The Human Trust Network is a root-and-branch system for custody, attestation, and paid work. Bitcoin is the only chain. Each asset or job carries its own off-chain consignment history, anchored by a single-use Bitcoin seal. Named human witnesses must sign before a transition is allowed to anchor. Paid work is recorded as signed public events; optional bonded vouching and a shared voucher pool supply skin in the game. There is no native token.

### 1. Problem

A master recording leaves a studio in the hands of a courier. Three days later the rights holder needs to prove, to a counterparty or a court, that the same file arrived unaltered and that the person who accepted it was authorized to do so. The courier company can produce a delivery scan. The studio can produce an email. Neither artifact is bound to the other, neither is offline-verifiable, and neither survives the disappearance of the company that issued it. The same gap appears when a sample clearance is granted by email and later disputed, or when a physical asset changes hands in a location without reliable connectivity.

A commercial contractor finishes a designated milestone on a government site. The site manager’s local, offline signature on the transition event is the proof of completion. That signature is sufficient to release escrow or settle a Lightning hold invoice. Neither party needs a central SaaS platform or a paper sign-off sheet that can be lost or altered after the fact.

Existing systems either centralize the record (so the record disappears with the intermediary) or force every observer to store the full history of every asset. What is required is a durable, portable proof that a particular transition occurred and that designated parties accepted it—proof that can be checked offline, that does not require a global ledger of every item, and that can later be presented as evidence of the chain of custody. The Human Trust Network supplies that proof by anchoring only the transitions that named witnesses have signed, using Bitcoin as the single global root.

### 2. Design

Bitcoin is the root. A single-use seal close is the only global fact. Everything else is a personal chain—the ordered history of one custody record or job—held by the parties who need it and anchored by that seal.

Three layers:

- **btc-root**: the Bitcoin L1 anchor. The confirmed seal close is global.
- **personal-chains**: one consignment history per handoff or job. The encoder records only the transitions that meet the witness threshold.
- **human-witness**: the set of named keys that must sign before a transition may anchor. Scoring is local (strongest path, hop limit 2); disagreement across clients is policy, not a consensus failure.

Public events contain only hashes, job identifiers, and public keys. Names, addresses, and packet contents never appear. OpenTimestamps anchors the events. Nostr-style signatures and event format are used for the public record.

### 3. Human and Agent Keys

An operator publishes a timestamped commitment to an offline recovery key. The recovery key can override any later rotation. Agent keys are delegated with explicit scope and optional expiry; they can be revoked by the operational key or the recovery key without rotating the human’s identity. The agent never holds the recovery key or unrestricted spending authority. Reference client is Android-first so that human keys remain in the device keystore and biometric path.

A handoff can be signed and locally verified while offline. The personal chain and the witness threshold are evaluated on the devices present; the Bitcoin seal and the OpenTimestamps proof are obtained later when connectivity returns. The eventual anchor does not rewrite the local history; it only confirms that the already-signed transition was allowed to close.

### 4. Paid Work and Incentives

Operators (or their scoped agents) perform jobs: handoffs, sealings, verifications, attestations. The counterparty—client or recipient—publishes the completion event and any dispute event. The worker cannot sign either.  

A job may be accepted and completed offline. The local signatures and the personal-chain history are sufficient for the parties present. When connectivity returns, the same events are published to the public record and timestamped. The public deterministic score is computed only from the published event set. Offline history that is never published does not affect the score; published events that later fall inside a compromised-key window are excluded.  

Payment is Lightning hold invoice for short jobs or on-chain escrow for longer ones. The score aggregates completed jobs, clean vouches, and lost disputes. Anyone holding the public events can recompute it.

### 5. Specialized Markets

Jobs carry an optional market tag. Per-market rules (scoring weights, bond floor, evaluation requirement, hold-invoice limit) live in configuration. Absence of the tag means the general market. This supplies specialization without new chains or tokens.

In the general market a milestone completion may clear with a single counterparty signature and a standard hold-invoice window. In a heavy-construction market the same job type can require a higher minimum bond, three named witnesses instead of one, and a fourteen-day hold before the Lightning invoice may settle, giving time for structural inspection. The market tag selects the rule set; the underlying event format, seal, and scoring machinery remain unchanged.

### 6. Voucher Pool

A single Bitcoin multisig output holds the pool. Two scoped AI agents hold the keys; neither signs alone.  

The AI keys are used for the pool because the pool must respond to penalty and reclaim requests without requiring a human to be online for every routine action, and because the agents have no residual claim on the funds once their signatures are spent. Neutrality and reduced human attack surface on the shared capital are the design reasons; execution speed is a consequence. Each AI remains under a human operator who receives the alert if the agents are unreachable.  

Each vouch requires a contribution that is credited to the voucher’s share. Shares are recorded solely by signed public events; anyone can recompute balances from the event set. A proven bad vouch reduces the share and pays the harmed client (both AI signatures plus the acting arbiter). Reclaim of unused share after the timelock requires both AI signatures and a signed reclaim event. AIs have a 10-minute signing window; if both are unreachable an 8-hour clock starts and the human operators are alerted. The Bitcoin script remains the enforcement boundary.

The acting arbiter is the founder unless the founder is a party to the job, in which case a designated backup acts. Recusal is mandatory and is written into the spend path. The arbiter does not hold the AI pool keys and cannot spend the pool alone. The role is early and narrow; once multiple operators exist, the same recusal rule can be applied to any designated arbiter per market.

### 7. Failure Modes

**Lost operational key.** The recovery key rotates or revokes. Earlier history remains.

**Stolen operational key.** The recovery key names a “compromised since” time. Subsequent events are disputable and excluded from scoring.

**Arbiter silence.** The voucher reclaims via the timelock path.

**Founder is a party.** The backup arbiter decides.

**AI pool keys offline.** The action waits or is refused after the stated clocks. The share stays locked.

**Timestamp calendars unreachable.** Local signatures and the personal chain remain valid. The OpenTimestamps proof is obtained when a calendar is again reachable. The eventual anchor does not alter the already-signed history.

### 8. What This Is Not

It is not a validator network, a global ledger of all assets, a token, or a smart-contract platform. A seal close proves that a particular consignment was anchored; it does not prove the underlying item is genuine. A key is not a person.

### 9. Status

The custody encoder, witness scoring, incentives prototype (events, keys, scoring, Lightning sandbox, Taproot bond), and voucher-pool specification exist. Production use and repeated real cycles remain ahead. Numeric parameters (bond sizes, windows, fee splits, scoring weights) are placeholders until timestamped with the Nucleus.
