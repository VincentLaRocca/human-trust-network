# Voucher Pool

Specification for the shared vouch pool. Design complete; implementation remains.

## Pool

One Bitcoin output.  
Multisig.  
Registered by one timestamped event containing the script hash and the two AI public keys.  
Any change of keys or script starts a new pool. Old shares remain under the prior rules.

## Keys

Two AI agents.  
Each is scoped under a human operator.  
Neither signs alone.  
Ordinary spends: both AI signatures.  
Penalty spends: both AI signatures plus the acting arbiter.  
Founder recusal applies.

## Share

Voucher sends stake to the pool address.  
Signed event records: voucher, amount, job id, funding txid.  
Event set is the complete public ledger of shares.  
Any party recomputes every balance from the events alone.

## Penalty

Upheld dispute.  
Spend reduces the voucher’s recorded share and pays the client.  
Requires both AI signatures and the arbiter.  
AIs do not hold the arbiter key.

## Reclaim

After T blocks and no upheld dispute against the share.  
Voucher publishes a signed reclaim event.  
Both AIs sign the spend.  
Earlier spend is invalid under the script.

## Timeouts

AIs have 10 minutes to return signatures.  
Failure refuses the attempt. Share unchanged.  
If both AIs are unreachable, an 8-hour clock starts.  
Alert (job id, action, deadline) is sent to each human operator.  
Clock expiry refuses the action.  
Bitcoin script requires the signatures; the timers are checked by the operators before broadcast.

## Enforcement

Only the paths above can spend.  
Events record ownership.  
Script enforces the signatures and the timelock.  
No other spend is possible.
