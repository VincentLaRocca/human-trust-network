# Scoring formula (v1)

Anyone holding the same public events, the same as-of time and the same view of
the chain gets exactly the same scores. No private data, no randomness.
Run `python -m htn score --check-bonds`.

The weights are set in `config.toml` under `[scoring]` (DECISIONS #11). The
numbers shipped are a simple starting point; the Founding Blueprint can tune them.

## Step 1: decide which events count

1. Drop any event that breaks the public schema (see `htn/schema.py`) or whose
   id/signature doesn't check out.
2. Treat copies of the same event (same id) as one event.
3. Sort the rest by `created_at`, then by `id`, and apply the rules in that order.
   An event that breaks a rule is rejected and has no effect. The rules:

| Event | Who must sign | Main rules |
|---|---|---|
| job offer | client | job id unused; client ≠ worker; recipient (optional) ≠ both |
| job accepted | the named worker (or their agent) | once; everything below needs it |
| handoff | current holder (starts as the worker) | sequence 1, 2, 3…; can't hand to yourself |
| completion | **client or recipient, never the worker** | names the job's real worker; first one counts |
| dispute filed | **client or recipient, never the worker** | within D of the job |
| dispute resolved | acting arbiter (or the filer, to withdraw) | within D of the job; once per dispute |
| vouch issued | voucher (not client/worker/recipient) | within D; amount within min/max; ≤ cap active vouches; a bond is named together with its own fresh bond key, and neither is ever reused; mustn't change the job's arbiter |
| vouch cleared | the same voucher | after D; no upheld dispute (undecided disputes have lapsed) |

**Acting arbiter:** the Founder key, unless the Founder is a party to the job
(client, worker, recipient, or a voucher on it). Then the backup arbiter acts.
If both are parties, nobody can resolve.

**Upheld dispute:** every active vouch on that job becomes *forfeited*.

**Keys and operators (Phase 2):** before any of the rules above, the onboard,
rotate and recover records are applied to work out which keys belong to which
operator. Every "same party?" check in the table above compares operators, not
keys. Two kinds of event are excluded as **disputable**: anything signed by a key
at or after the time a recovery marked it compromised, and any job naming such
a key as its worker. Anything signed by a key after an ordinary rotation retired
it is rejected.

**Agents (Phase 2b):** an agent key counts as its operator, but only for the
record kinds in its scope, from its delegation until it expires or is revoked.

**As-of time:** a dispute nobody has decided is *pending* while the window is open
and *lapsed* (it doesn't count against anyone) once the window has closed. Whether
it has closed is judged against the as-of time printed in the output. Same events
plus same as-of always gives the same scores.

## Step 2: check vouch bonds on the chain (DECISIONS #43)

A vouch earns weight only if its bond checks out on the chain. The checker
rebuilds the expected bond address from public facts (the job's client, the
vouch's own bond key, the arbiter by the recusal rule, and T), then requires the
bond to be:
- **present:** the named transaction exists and has that output;
- **confirmed**, and not locked more than 2 hours before the job (a bond locked
  early would start its timelock early);
- **the right size:** it holds the amount the vouch states, and at least the
  configured minimum;
- **unspent:** still sitting there, or spent only by an **honest reclaim**. That
  means the voucher alone took it back through the timelock path after T. A clean
  vouch keeps counting after that, following the Nucleus "long clean history"
  (DECISIONS #47). Any other spend, e.g. a forfeit, stops it counting.

The chain height and block hash used are printed as `chain_tip`, so anyone can
repeat the check against the same chain state. Without chain access (`score`
without `--check-bonds`) no vouch carries weight, and the output says so.

## Step 3: count, per operator (all of its keys together)

| Count | Meaning |
|---|---|
| `completed_jobs` | **clean completions**: jobs you worked with a valid completion, no upheld dispute, and no dispute still pending at the as-of time |
| `clean_vouches` | your **cleared** vouches whose bond checks out (Step 2): still locked, or honestly reclaimed |
| `lost_disputes` | `upheld_disputes` (as worker) + `forfeited_vouches` (as voucher) |
| `clean_vouches_not_counted`, `active_vouches` | shown for information; not scored |

## Step 4: score

```
score = clean_completion × completed_jobs      (shipped:  1)
      + clean_vouch      × clean_vouches       (shipped:  2)
      + lost_dispute     × lost_disputes       (shipped: -5)
```

The output also includes:
- `weights`: the numbers used;
- `bond_checks`: the result for every cleared vouch, with reasons;
- `disputable_events`: how many records were excluded because of compromised keys;
- `event_set_hash`: SHA-256 of the sorted list of accepted event ids. Two people
  who get the same hash scored the same evidence.

## Known limits (to address before real use)

- `created_at` is set by the signer. A timestamp proof shows an event existed *by*
  a certain time, but nothing stops a signer from back-dating it inside that limit.
  Counterparty signatures stop workers from inflating their own record. They don't
  stop a client and a worker colluding.
- Nothing yet stops one person from running many keys (Sybil attacks).
- The Nucleus says vouch weight should grow with "long clean history". In v1 every
  clean vouch counts the same (+2); a growing weight is for the Blueprint to define.
- A thief can back-date events to before the "compromised since" time. Timestamp
  proofs limit how far back; a dispute can catch the rest.
