# Satoshi Mode

Operating Profile  
October 2026

Satoshi mode is a minimal operating profile for the Human Trust Network and any system that seeds it (including the Courier Chain of Trust). It prioritizes the same constraints visible in the original Bitcoin design: the only global fact is a confirmed Bitcoin transaction, everything else stays local or optional, and public records contain the least information required for verification.

## Rules

1. **Root fact only**  
   The sole global, timestamped fact is a confirmed single-use Bitcoin seal close. No other chain, token, or consensus system is introduced.

2. **Minimal public record**  
   Events published to the network contain only:
   - hashes of consignments or jobs,
   - job or seal identifiers,
   - public keys of required signers.  
   Names, addresses, item descriptions, and packet contents never appear.

3. **Local history**  
   Each personal chain (the ordered consignment history of one handoff or job) is held only by the parties who need it. Observers who do not hold the chain cannot reconstruct it from public data.

4. **Human keys on device**  
   Operational keys remain in the participant’s device keystore, gated by biometric or equivalent local factor. An offline recovery-key commitment can override. No remote party holds raw spending authority.

5. **Witness threshold before anchor**  
   A seal may close only after the required named keys have signed. Scoring of those keys is local (strongest path, hop limit ≤ 2). Disagreement across clients is policy, not a failure of the seal.

6. **Offline first**  
   Signatures and personal-chain updates can be completed and verified with no network. The Bitcoin seal and any OpenTimestamps proof are obtained later and do not rewrite the already-signed local history.

7. **No residual claims**  
   There is no native token. Optional bonds or voucher-pool shares are recorded solely by signed public events that anyone can recompute. Protocol maintainers hold no special residual right to user funds.

8. **Seed is just a seal**  
   The first Bitcoin seal close (produced, for example, by a Courier Chain of Trust handoff) is a valid seed. It requires no additional ceremony, identity registry, or coordination channel beyond the confirmed transaction itself.

## What Satoshi mode excludes

- Any requirement that every participant store every history.
- Global identity directories or name-to-key bindings in the public record.
- Trusted third parties for the root fact.
- Automatic or unrestricted agent spending authority.
- Token issuance or protocol-level extraction.

## Status

This profile is compatible with the existing custody encoder, witness scoring, and seal logic. It can be used by the Courier Chain of Trust for its handoffs and by any later participant who references the seed. Implementation remains the same code paths already present; Satoshi mode is the set of operational constraints applied on top.
