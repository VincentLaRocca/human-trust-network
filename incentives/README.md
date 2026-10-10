# Human Trust Network — Incentives Layer (prototype)

> **Phase numbers:** the sections below use the numbering of the first brief. The
> updated brief renumbers them: 1 events → 2 keys → 3 scoring → 4 bond → 5 payments
> (see DECISIONS #45). What the update added is in the last section.

A command-line prototype of the network's incentives layer: signed public
records of work, timestamps, scoring, and later bonds and Lightning payments.

**Test networks only.** Bitcoin regtest/signet only. No mainnet keys, no real sats.
Public events carry only hashes, job ids and public keys, never client data.

| File | What it is |
|---|---|
| `config.toml` | every tunable number (test placeholders, not policy) |
| `DECISIONS.md` | why things were built the way they were; open questions |
| `SCORING.md` | the public scoring formula |
| `htn/` | the code |
| `tests/` | automated tests |
| `.keys/`, `.recovery/`, `data/` | created when you run it; **private, never committed** |

## Setup (once)

```powershell
cd incentives        # this folder
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

Run all tests:

```powershell
.venv\Scripts\python -m pytest
```

---

## Phase 1 — Events, timestamps, scoring (no money) ✅

### What was built, in plain English

- **Eight kinds of public record** ("events"): job offer, job accepted, handoff,
  completion, dispute filed, dispute resolved, vouch issued, vouch cleared. Each one is a
  standard Nostr event, signed with the signer's key.
- **A strict privacy filter.** Every event must match an exact template that only
  has room for random job ids, public keys, and hashes. A name, an address, a
  readable job id or an extra field gets the event rejected before it is saved.
  Private files (job terms, receipts, complaints) are hashed on your machine with a
  random salt, so the hash can't be reversed by guessing.
- **Counterparty-only sign-off.** A completion or dispute counts only when it is
  signed by the client or recipient. If the worker signs one, it is rejected.
- **A rules engine.** It checks every event against the rules: dispute window,
  arbiter recusal, vouch limits, bond size, and the handoff chain.
- **Timestamps.** Each event's hash gets an OpenTimestamps proof (`.ots` file).
  By default this uses an offline test calendar. `--public` uses the real public
  calendars and sends only the hash.
- **A deterministic score.** Anyone with the same public events gets the same
  numbers, plus a fingerprint (`event_set_hash`) that proves it. See SCORING.md.

### Try it

```powershell
$py = ".venv\Scripts\python"
& $py -m htn keygen client
& $py -m htn keygen worker
"Deliver sealed case to Jane Smith" | Out-File terms.txt   # stays private

& $py -m htn job-offer --as client --worker worker --terms-file terms.txt
#   job_offer event 3b1e12...   job id 9f04c2...  (= hash of terms + secret nonce)
& $py -m htn accept --as worker --job 9f04c2...

& $py -m htn complete --as worker --job 9f04c2... --receipt-file terms.txt
#   error: refused: completion must be signed by the client or recipient, not the worker

& $py -m htn complete --as client --job 9f04c2... --receipt-file terms.txt
& $py -m htn verify 3b1e12...       # signature + timestamp proof
& $py -m htn check                  # every stored event against the rules
& $py -m htn score worker           # -> completed_jobs 1, score 1 (formula v1)
```

Other commands: `handoff`, `dispute-file`, `dispute-resolve`, `vouch-issue`,
`vouch-clear`, `stamp [--public]`, `upgrade`, `keys`. Add `-h` to any command for help.
Use `--at <unix seconds>` to simulate time passing (for example, to clear a vouch
after the 7-day window). Dispute resolution needs the arbiter keys set under
`[arbiters]` in `config.toml`.

### What the tests check

- **Schema/privacy:** extra fields, extra tags, non-empty content, readable job
  ids, plaintext in hash fields and duplicate tags are all rejected. No private
  text appears in any event. The store refuses to save a bad event.
- **Signatures:** the BIP340 test vector passes. Changing any field, or signing
  with the wrong key, breaks verification.
- **Counterparty-only:** worker-signed completions and disputes are rejected,
  and so are completions from strangers.
- **Rules:** dispute window, arbiter recusal (Founder → backup), withdrawals,
  vouch cap (6th vouch rejected), bond limits, clearing only after the window,
  forfeiture on an upheld dispute, and the handoff chain.
- **Deterministic scoring:** shuffled and duplicated inputs give the same output,
  and forged or junk events change nothing.
- **Hard rules:** no mainnet addresses or private keys in the repo, secret
  folders are gitignored, mainnet config is refused, and the config enforces
  T > D and a fee split that adds up to 100%.

---

## Phase 2 — Keys: rotation, revocation, recovery ✅

### What was built, in plain English

- **Onboarding.** An operator publishes an "onboard" record that contains a
  fingerprint (hash) of a second, **recovery key**. The recovery key itself stays
  hidden and offline. The onboard record's id becomes the operator's
  permanent identity, and it is timestamped like every other record.
- **Ordinary rotation.** The current working key signs "my new key is X". The old
  key is retired: anything it signs afterwards is refused.
- **Recovery beats everything.** If a key is stolen or lost, the operator signs a
  "recover" record with the recovery key. It names a new working key and the
  time the trouble started. Every working key held from that time on, including
  any key a thief rotated to, is marked **compromised**. Everything those keys
  signed from that time is flagged **disputable** and left out of scoring. A thief
  can rotate as often as they like, and one recovery undoes it all.
- **Scores follow the operator, not the key.** All of an operator's keys count as
  one party. A key change doesn't reset their record or their 5-vouch limit, and
  they still can't sign off their own work with a different key.

### Try it

```powershell
& $py -m htn keygen alice
& $py -m htn recovery-keygen alice-recovery          # its own folder, .recovery\
& $py -m htn onboard --as alice --recovery-pub <recovery public key>
#   operator id 7c41...   (now move .recovery\alice-recovery.json OFFLINE)

& $py -m htn keygen alice2
& $py -m htn rotate --as alice --new alice2          # ordinary rotation

# alice2 was stolen at unix time 1791600000:
& $py -m htn keygen alice3
& $py -m htn recover --recovery-file E:\alice-recovery.json --new alice3 --since 1791600000
& $py -m htn identity alice                           # shows COMPROMISED keys
& $py -m htn check                                    # thief's records marked DISPUTABLE
```

### What the tests check

- **Thief scenario:** the thief rotates with a stolen key, takes jobs and vouches. The
  recovery overrides the rotation. The thief's records are disputable, work done
  before the theft still counts, and the thief's later attempts still fail.
- **Lost key:** the key is replaced through recovery, and the operator's history
  carries over to the new key.
- **Post-compromise exclusion:** the thief's forfeited vouches don't count against
  the real operator, and they are counted as disputable.
- **Rules:** only the current key can rotate; a retired key can't sign; nobody can
  take over another operator's key; the recovery key can never become a working key;
  the wrong recovery key is refused; a recovery can't reach back before the
  previous one; chained thief rotations are all undone by one recovery.
- **Identity:** the vouch limit survives rotation; Founder recusal still applies
  after a key change; scoring stays identical under shuffling.

---

## Nucleus alignment + Phase 2b — Agent keys ✅

`NUCLEUS.txt` is the owner's source-of-truth document, saved byte-for-byte. Git
is told never to touch its line endings, so its timestamp proof stays valid.
`NUCLEUS.md` is the same text, formatted for reading.

### What changed, in plain English

- **Job ID = fingerprint of the agreed terms plus a secret random number.** The
  parties keep the secret number (in `data/private/`), so they can later prove which
  terms a job ID stands for. Nobody else can work them out.
- **Offer, then acceptance.** The client offers (`job-offer`), and the named worker
  must accept (`accept`) before any handoff, completion, dispute or vouch counts.
  No one can be dragged into a job they never agreed to.
- **A silent arbiter means the dispute lapses.** If no decision is published inside
  the dispute window, the dispute lapses and the voucher can reclaim. The score
  takes an "as of" time (`score --as-of`, default now) and prints it, so anyone can
  reproduce the same numbers.
- **Revoke without a replacement.** `recover` can now leave out `--new`.
- **Timestamp any document:** `stamp-file`, `verify-file`, `upgrade-file`. These are
  compatible with the standard `ots` tool.
- **Agent keys (Phase 2b).** An operator can give a separate key to an agent (a
  helper or a piece of software) with a limited scope, such as "may accept jobs and
  sign handoffs", and an optional expiry time. The agent counts as the operator, but
  can't do anything outside its scope. It can never change the operator's own keys,
  and it can't sign off its own operator's work. The operator's key or the recovery
  key can revoke it at any time without rotating the human's key. An agent created
  by a thief with a stolen key is void after recovery, and a thief can't revoke a
  legitimate agent.

### Try it

```powershell
& $py -m htn stamp-file NUCLEUS.txt              # creates NUCLEUS.txt.ots (offline test calendar)
& $py -m htn verify-file NUCLEUS.txt

& $py -m htn keygen alice-bot
& $py -m htn delegate --as alice --agent alice-bot --scope job_accepted,handoff
& $py -m htn accept --as alice-bot --job <job id>    # agent accepts for alice
& $py -m htn revoke-agent --as alice --agent alice-bot   # or --recovery-file <file>
```

### What the tests check

Job IDs commit to the terms; nothing counts before acceptance; only the named
worker accepts, once; an undecided dispute is pending inside the window and lapses
after it; revoke-only recovery; document proofs break if one character changes. For
agents: scope, expiry, revocation by the operator or recovery key, no identity
powers, no self-sign-off, and the thief delegation and thief revocation cases.

---

## Lightning sandbox (regtest) ✅

A private practice Lightning network on this PC: one Bitcoin Core node and two
Lightning (LND) nodes called **client** and **worker**, joined by a 1,000,000-sat
channel. The coins are regtest coins, created on demand and worthless.

- **Regtest only, hard-wired.** There is no setting that points it at real Bitcoin.
- **Only reachable from this PC** (127.0.0.1), on its own ports, so it never touches
  the other Bitcoin nodes already running here.
- **Verified software.** `scripts/fetch_tools.py` downloads Bitcoin Core 31.1 and
  LND v0.21.4-beta. It checks each download's checksum, then checks the developers'
  signatures with keys fetched separately from GitHub: at least 5 independent
  Bitcoin Core builders (11 signed), and LND's lead maintainer. It refuses to
  install anything that fails. Everything lands in `tools/`, which is gitignored.

```powershell
.venv\Scripts\python scripts\fetch_tools.py      # once: download + verify
& $py -m htn sandbox up        # start (first time: funds client, opens channel)
& $py -m htn sandbox status    # balances and channel
& $py -m htn sandbox mine 6    # make 6 regtest blocks
& $py -m htn sandbox down      # stop all three nodes
& $py -m htn sandbox reset     # delete sandbox data (when stopped)
```

**Tested:** a hold invoice end to end. The worker creates an invoice locked to a
secret's hash; the client pays and the money is *held*; a wrong secret can't
collect it; the right secret settles it. The live test runs only while the sandbox
is up and is skipped otherwise.

---

## Phase 4 — Hold-invoice payments (regtest Lightning) ✅

Built before the Taproot bond, following the Nucleus ("now: paid jobs").

### What was built, in plain English

1. The **recipient** makes a random secret and gives the worker only its
   fingerprint (hash).
2. The **worker** creates a Lightning *hold invoice* locked to that hash, but only
   if the job is expected to take **6 hours or less** (`max_hold_seconds` in
   `config.toml`). Longer jobs are refused and pointed to "fresh hold invoice near
   completion, or on-chain escrow".
3. The **client** pays. The money leaves the client but is *held*: nobody can
   claim it without the secret.
4. On delivery the **recipient** signs a **private receipt** containing the secret
   and hands it to the worker. It is never published. They also publish the normal
   completion record, which carries only the payment hash.
5. The **worker**'s tool checks the receipt: signed by the job's recipient or
   client, for this job and this payment, with a secret that fits the hash. Then it
   settles, and the payment completes.

**If nobody signs:** the payment is cancelled and the client gets every sat
back. Two layers make sure of it:
- `hold-check` cancels anything held longer than the limit.
- Lightning's own **backstop**: the invoice is built so that LND cancels the hold
  automatically before its block deadline (about 7 hours at most), even if the
  worker does nothing.

The fee split (worker 85% / network 10% / voucher 5%, placeholders) is
calculated and shown on each invoice. Actually forwarding the network and voucher
shares isn't automated yet; it's for the Blueprint to decide (see DECISIONS #35).

### Try it (sandbox must be up: `sandbox up`)

```powershell
& $py -m htn job-offer --as client --worker worker --recipient recipient --terms-file terms.txt
& $py -m htn accept --as worker --job <job>
& $py -m htn pay-secret --job <job>                      # recipient -> prints payment hash
& $py -m htn invoice --job <job> --hash <hash> --amount 15000 --expected-minutes 90
& $py -m htn pay <payment request>                        # client pays; money is held
& $py -m htn hold-check                                   # shows ACCEPTED (held)
& $py -m htn receipt --as recipient --job <job>           # private receipt + public completion
& $py -m htn settle --job <job> --receipt <receipt file>  # worker collects
```

### What the tests check

Offline (fake Lightning) and **live on the sandbox**:
- **Happy path:** held, then settled with the receipt; the worker's balance goes up.
- **Recipient never signs:** the watchdog cancels and the client is refunded in full.
  Live, the Lightning backstop also cancels with no watchdog at all, after the
  right number of blocks and not before.
- **Worker can't settle without the secret:** a guessed secret, a receipt the
  worker signed itself, a tampered receipt and a receipt for another job are all
  refused.
- Jobs over 6 hours are refused; the secret never appears in public records; the
  fee split adds up.
- The full flow also runs through the command-line tool.

## Phase 3 — Taproot vouch bond (regtest) ✅

Code: `htn/bond.py`. Tests: `tests/test_bond.py`.

### What was built, in plain English

A voucher backs a job with real (test) coins. The coins go into a Bitcoin
address that can be spent in only two ways:

1. **Any two of: client, voucher, arbiter.** This is how a bad vouch is punished.
   If the arbiter upholds a dispute, the client and the arbiter sign a transaction
   that pays the bond to the client.
2. **The voucher alone, but only after T blocks** (2016, about two weeks). If no one
   proves a bad vouch in time, the voucher gets the coins back. Bitcoin enforces
   the wait: an earlier attempt is refused by the network.

Nobody can spend it any other way. There is no hidden master key: the address is
built on a public "nothing up my sleeve" point that nobody holds a key for.

**Who is the arbiter?** The founder, unless the founder is involved in the job
(as client, worker, recipient or voucher). Then the backup arbiter is written into
the bond instead. The recusal is part of the address itself, so the founder
can't sign for that bond at all.

**Bitcoin can't force the forfeit to go to the client.** Any two signers could
send it anywhere. The rule is enforced by the arbiter's tool, which signs only if:
- the public record shows an upheld dispute on this vouch;
- the client has already signed the exact same transaction, so the client chose
  where the money goes;
- the arbiter is the one actually written into this bond.

**Anyone can check a bond.** The vouch record names the funding transaction.
From public facts alone (the client, the voucher, the arbiter rule and T), anyone
can rebuild the expected address. They then confirm that the coins are there, in
the right amount, and weren't locked before the job (an early lock would let the
two-week clock run out sooner).

Bitcoin Core independently derives the same address from a standard description
of the rules, so the address maths is checked by Bitcoin's own reference software.

### Try it (sandbox must be up: `sandbox up`)

```powershell
& $py -m htn bond-fund --as voucher --job <job> --amount 30000      # prints txid
& $py -m htn vouch-issue --as voucher --job <job> --amount 30000 --bond <txid>
& $py -m htn bond-check <vouch>                                      # anyone
# after an upheld dispute:
& $py -m htn bond-forfeit --as client --vouch <vouch> --to <client regtest address>
& $py -m htn bond-arbiter-sign --as founder --vouch <vouch> --broadcast
# or, if nothing was proven, after T blocks:
& $py -m htn bond-reclaim --vouch <vouch> --to <address> --broadcast   # uses the bond's own key
```

### What the tests check

Live on the regtest chain, with Bitcoin Core accepting or refusing each attempt:
- **Address:** Bitcoin Core derives the same address on its own.
- **Forfeit pays the client:** client + founder sign, and the coins arrive at the
  client's address.
- **Recusal:** when the founder is the voucher, the backup signs instead, and the
  founder is refused.
- **The network refuses:** a spend with only one signature, a spend signed by an
  outsider, and the voucher reclaiming early.
- **Timelock:** the voucher's reclaim is refused at T−1 blocks and accepted at
  exactly T.
- **The full flow through the command-line tool:** the arbiter refuses before the
  dispute is upheld, and the wrong arbiter is refused.

Offline:
- **Arbiter's tool refuses** when the dispute wasn't upheld, the client hasn't
  signed, or someone other than the bond's arbiter tries to sign.
- **Signatures can't be moved:** a client signature can't be reused on a
  transaction paying somewhere else.
- **Saved files are re-checked:** a signed file that was edited afterwards is refused.
- **Mainnet addresses are refused** as destinations.
- **Ledger:** a bond can't back two vouches, and a late vouch can't change the
  arbiter already written into existing bonds.

Each of these safeguards was also removed on purpose, and the tests failed every time.

## Updated brief: closed decisions and new checks ✅

What changed, in plain English:

- **Every bond has its own fresh key (#39).** Funding a bond makes a brand-new key,
  used for that bond only. The voucher's everyday key never appears on the
  blockchain and can't spend the bond, and changing the everyday key doesn't touch
  locked bonds. The vouch record names the bond key, and a bond key that belongs to
  anyone's everyday key, or was used before, is refused.
- **A vouch scores only while its bond is really there (#43).** The checker
  rebuilds the expected bond address from public facts and asks the chain whether
  the coins are there:
  - in the right amount, and at least the minimum;
  - confirmed;
  - not locked before the job;
  - not yet spent.

  A missing, too-small or early bond earns nothing, and so does one that was
  spent any way other than the voucher's honest reclaim after the timelock. An
  honestly reclaimed bond keeps counting: a clean history stays clean (your
  choice, following the Nucleus).
- **A simple public score (#11):** +1 per clean job, +2 per clean vouch with a
  live bond, −5 per lost dispute. The weights are in `config.toml`; the formula is
  in `SCORING.md`.
- **Fee shares get paid (#35).**
  - The network's 10% is due at once. It is paid as its own Lightning payment, or
    collected and sent on-chain in one go to a set address (your choice in
    `config.toml`).
  - The voucher's 5% is held back until the dispute window closes, then paid by
    Lightning. If the vouch was lost, that 5% goes to the client.
- **Recovery keys stay out of the everyday tool.** They are made in their own
  folder. Onboarding only needs the recovery key's *public* half. Every normal
  command refuses to open a recovery key; only `recover` and `revoke-agent` read
  one, from a file you point to (e.g. a USB stick).
- **Secrets never leak.** A test collects every secret nonce and salt the tool
  stored and fails if any of them shows up in anything published.
- **Check one job's whole story:** `verify-job <job id>` lists every public record
  for the job in order, with who signed it, whether the rules accepted it, and its
  timestamp, and flags anything missing or rejected.

### Try it

```powershell
& $py -m htn verify-job <job>
& $py -m htn score --check-bonds              # vouches count only with a live bond
& $py -m htn fees                             # what the worker owes, and when
& $py -m htn fees-pay <share id> --invoice <payee's invoice for that amount>
& $py -m htn fees-sweep                       # when fees.payout = "sweep"
```

### What the tests check

- Nonces and salts never appear in published records or proofs.
- `verify-job` passes a complete job, and catches a worker-signed completion, a
  missing offer and a missing timestamp proof.
- **Recovery keys:** they live apart, are refused by normal commands, and an
  everyday key can't be used to recover.
- **Bond keys:** they are fresh and used once. On chain, the voucher's everyday key
  can't spend the bond, and the bond key reclaims it.
- **Silent arbiter** (on chain): a dispute is filed but never decided, and the
  voucher reclaims at exactly T, after being refused one block earlier.
- **Scoring:** two independent runs agree. A forfeited, missing, too-small or
  early bond earns nothing, and so does an unbonded vouch. An honestly reclaimed
  bond keeps counting; on chain, a real reclaim is recognised and a real forfeit
  is not.
- **Fees, live:**
  - the network share is paid by Lightning, and an invoice for the wrong amount
    is refused;
  - the voucher share is refused before the window closes and paid after;
  - in sweep mode, two jobs' network shares go out on-chain in one payment.
