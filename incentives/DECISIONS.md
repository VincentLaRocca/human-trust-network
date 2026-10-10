# Decisions log

Plain-English record of choices made while building. **[You approved]** marks
choices Vinny made. **[Open]** marks choices that need Vinny's sign-off before
they become final.

## 2026-10-09 — Setup

1. **Language: Python 3.11.** [You approved] The OpenTimestamps reference tool is
   Python, and your other projects already use it. Libraries: `coincurve`
   (libsecp256k1, the same crypto library Bitcoin Core uses), `opentimestamps`, `pytest`.
2. **Location: its own folder and git repo on Vinny's PC** (later moved into the
   GitHub repo as `incentives/`, see #52). [You approved]
3. **Timestamps: tests run offline. Public calendars only when you ask.** [You approved]
   The default "local-test" calendar never touches the network, and its proofs
   say `test_only: true`. Setting `timestamps.mode = "public"` in `config.toml`, or
   running `stamp --public`, sends **only the event hash** to the public
   OpenTimestamps calendars. Those calendars anchor into mainnet Bitcoin; we
   hold no keys and spend no sats.

## 2026-10-09 — Phase 1

4. **Key format: standard Nostr keys.** These are secp256k1 keys with 32-byte "x-only"
   public keys and BIP340 Schnorr signatures. Nostr requires this, so there was no real
   choice. A test checks our signer against the official BIP340 test vector.
   Keys are stored as JSON in `.keys/` (gitignored). They aren't encrypted at rest
   yet, which is acceptable for a test-network prototype.
5. **Event format: standard Nostr (NIP-01) events. `content` is always empty and
   all data goes in tags.** Tags let relays filter by job and by public key, and
   having a single place for data makes the privacy check simple and strict.
6. **Event kind numbers 3910–3916.** [Open] These are provisional. Before
   anything goes to a public relay, they must be checked against the Nostr NIP
   registry for clashes and published as a NIP-style spec. The brief says to ask
   before publishing schemas, so they are not final.
7. **Hashes are salted.** A plain hash of a short secret (an address, a
   name) can be cracked by guessing and hashing candidates. Every hash we publish is
   SHA-256(random salt + private data). The salt stays in `data/private/` (gitignored)
   so the party can later prove what they committed to.
8. **Job ids are random (`job_` + 32 hex characters).** A human-chosen id like
   "smith-delivery" would leak client data, so the schema rejects anything else.
9. **Public keys appear in events.** These are the operators' pseudonymous network
   identities, and signature checks need them. [Open] The recipient's key is also
   public when a recipient is named. If recipients shouldn't be linkable across
   jobs, they could use a fresh key per job. That is a policy question for you.
10. **Interpretations of the brief.** [Open, please confirm]
    - *Dispute resolved* is signed by the **acting arbiter**, or by the person who
      filed the dispute if they withdraw it. It is never signed by the worker.
    - Founder recusal applies when the Founder is the client, worker or recipient,
      **or a voucher on that job** (a voucher has a bond at stake).
    - "Disputes filed and resolved inside the window": a resolution after the
      window is rejected. A dispute left unresolved after the window freezes the
      job: the worker gets no credit and no penalty, and vouches can't clear.
    - *Vouch cleared* is signed by the voucher after the window, and counts only
      if the job has no upheld or unresolved dispute.
    - *Handoff* is signed by whoever currently holds the item (the worker at
      first), naming the next holder, with sequence numbers 1, 2, 3…
    - A vouch must be issued inside the dispute window.
11. **Scoring weights (+10 completed job, +3 clean vouch, −25 upheld dispute,
    −15 forfeited vouch) are placeholders** in `config.toml`. [Closed → #48] The formula is
    in SCORING.md.
12. **Rule order is by `(created_at, id)`.** This makes results identical for
    everyone. Known limit: `created_at` is set by the signer (see SCORING.md).
13. **Events are stored locally, not sent to relays yet.** Publishing to Nostr
    relays is outward-facing, so it waits for your go-ahead.

## 2026-10-10 — Phase 2

14. **Three new record kinds: onboard (3920), rotate (3921), recover (3922).**
    [Open] These numbers are provisional, like #6.
15. **Recovery-key commitment = SHA-256 of the recovery public key.** The
    recovery key is a normal Nostr key. Only its hash is published at onboarding,
    so the key stays unknown until the day it's needed. No salt is needed because a
    public key can't be guessed. [Open] This is a key-format choice, so please
    confirm it. Nothing has been published, so it's still easy to change.
16. **An operator's identity is the id of their onboard record.** It never
    changes, however many keys they rotate through. A key that never onboarded is
    its own identity (Phase 1 behaviour).
17. **"Compromised since" is chosen by the operator** when they recover.
    The default is the moment of recovery, as for a lost key. For a theft they set
    it to when they believe the key was stolen. Every working key held at or after
    that time becomes compromised from that time. A new recovery can't
    reach back before the previous recovery, so settled history stays settled.
18. **Old keys stop working after a rotation.** Anything an old key signs after a
    normal rotation is refused as "retired". This is not "disputable"; it is simply
    invalid.
19. **Interpretation:** [Open] Besides events *signed* by a compromised key, a
    **job naming a compromised key as its worker** after the compromise time is also
    disputable and excluded. Otherwise a thief could work jobs under the
    operator's name and the operator would wear the penalties.
20. **Known limits.** The recovery key itself can't be rotated yet. Anyone who steals
    the recovery key controls the identity, which is why it must be kept offline.
    A thief can also back-date events to before the "since" time. Timestamp proofs
    narrow this; a dispute can catch the rest.

## 2026-10-10 — Nucleus alignment

Vinny supplied the Nucleus (saved as `NUCLEUS.md`). Compared with Phases 1–2:

**Already matches:** public events carry only hashes and job ids; only the
client or recipient can sign completions and disputes; disputes are filed and
decided within D; the Founder recuses to the backup arbiter; the recovery key
overrides any rotation; "compromised since" covers keys rotated to afterwards;
those events are excluded from a deterministic public score; T > D.

**Settled by the Nucleus:**
- #15 is confirmed. The commitment may hold "the recovery-key public key (or its
  hash)". We use the hash.
- #10 (partly). The arbiter decision must fall within D, and the Founder recuses.

**Differences — Vinny approved A, B, C, D (as Phase 2b), E, H, and G (Lightning before bonds):**
- A. **Job ID = hash(agreed parameters + private nonce)** (Nucleus §4). Right now it
  is just random. Change: job ID = SHA-256(terms file + secret nonce), so the
  parties can later prove what a job ID stood for.
- B. **A dispute with no decision by the end of D lapses** (§2, §8: "arbiter silent →
  voucher reclaims"). Right now it freezes the vouch. Change: after D, an
  undecided dispute counts as not upheld, and the vouch can clear.
- C. **Job offer / acceptance** (§4). Right now only the client signs the job.
  Add an "accepted" record signed by the worker.
- D. **Agent key delegation / revocation** (§5). Not built yet. An operational key
  signs "agent key X may act within scope Y". The operational or recovery key
  can revoke it without rotating the human's key.
- E. **Revoke without a replacement** (§8 "recovery key rotates *or revokes*").
  Right now a recovery must name a new key. Change: make the new key optional.
- F. **Vouch weight grows with a long clean history** (§2). Not in the v0 score yet.
- G. **Order of phases** (§9): paid jobs with hold invoices come "now"; bonded
  vouching comes later, once there are several operators. That suggests building
  Phase 4 (Lightning) before Phase 3 (Taproot bond). The brief says not to skip
  ahead, so this needs Vinny's decision.
- H. **Timestamp the Nucleus and the config** once the placeholders are filled
  (§9). Add a command that stamps any file.

### Done on 2026-10-10

21. **A done.** Job ID = SHA-256(32-byte random nonce + agreed-terms file), as 64
    hex characters. The separate "terms" hash was dropped because the job ID is now
    the commitment. The nonce is saved in `data/private/<job id>.json`.
22. **C done.** "job created" was renamed **job offer** (still kind 3910), and **job
    accepted** (3917) is new, signed by the worker or their agent. Handoff,
    completion, dispute and vouch all require an accepted job.
    Note: two records with the same `created_at` second are ordered by id, so an
    acceptance and a completion in the same second may fall in either order. Real
    use won't hit this, because a completion follows the acceptance by more than a second.
23. **B done.** An undecided dispute lapses when the window closes; the vouch can
    then clear. For scoring, whether the window has closed depends on a
    reference time. `score` takes `--as-of` (default now) and prints it, so the
    result stays reproducible: same events plus same as-of gives the same score.
    Without an as-of time, undecided disputes count as pending.
24. **E done.** A recovery can omit the new key ("revoke only"). Until a later
    recovery names one, the operator has no working key.
25. **H done.** `stamp-file` / `verify-file` / `upgrade-file`. The proof sits next to the file
    as `<file>.ots`, the same format as the standard `ots` tool.
26. **D done (Phase 2b): agent keys.** Delegate (3923) is signed by the operator's
    current key. It names the agent key, a scope (a comma-separated list of record
    kinds) and an optional expiry. Agent revoke (3924) is signed by the current key or
    the recovery key. Agents can never sign identity records. [Open] The scope is a
    list of record kinds. Finer limits (job types, sat amounts) can be added once
    the Blueprint defines job types.
27. **G decided.** Build Lightning hold-invoice payments (brief Phase 4) **before**
    the Taproot bond (brief Phase 3), following Nucleus section 9.
28. **Provisional kind numbers so far:** 3910–3917 job records, 3920–3924 identity
    records. [Open] They must be registered or checked before publishing (#6).

## 2026-10-10 — Timestamp + Lightning sandbox

29. **NUCLEUS.txt was timestamped on the public OpenTimestamps calendars** (approved by
    Vinny). SHA-256 `1041c165eaf4fb6d36c22899e204edd223cc4a9f1d0ff988f2efe0785ba0b9e5`.
    All 4 calendars accepted it. The proof is `NUCLEUS.txt.ots`, which is "pending"
    until the calendars' Bitcoin transaction confirms (usually a few hours). Then
    run `upgrade-file NUCLEUS.txt` and commit the upgraded proof.
30. **Sandbox software: Bitcoin Core 31.1 (newest final; 32.0 is still a release
    candidate) and LND v0.21.4-beta,** both official Windows builds,
    signature-checked (see README). LND was chosen because its hold invoices
    (`addholdinvoice` / `settleinvoice` / `cancelinvoice`) are built in.
31. **Sandbox ports are non-default** (bitcoind RPC 28443; LND 11009/11010,
    18180/18181, 19735/19736). The development PC also runs other Bitcoin nodes,
    one of them on the default regtest port. The sandbox never connects to them,
    and refuses to start if a port is taken.
32. **The LND wallets have no password and no seed backup (`--noseedbackup`).** This
    is acceptable only because the coins are worthless regtest coins.

## 2026-10-10 — Phase 4: hold-invoice payments

33. **The receipt containing the secret is PRIVATE.** It is a signed message from the
    recipient to the worker, never published. The public completion record carries
    only the payment **hash**, following "public events contain only hashes". The
    worker accepts a receipt signed by the job's recipient or, if there is none,
    the client.
34. **Two layers refund the client.** The worker-side watchdog (`hold-check`) cancels
    after `max_hold_seconds`. The Lightning backstop is the invoice's block
    deadline: ceil(max hold / 10 min) + 18 + 6 blocks, minimum 25. LND cancels
    18 blocks before that deadline (measured in the sandbox, and set explicitly
    with `--invoices.holdexpirydelta=18`). With the 6-hour default, the backstop
    fires after about 45 blocks, about 7.5 hours.
35. **Fee split is calculated, not yet forwarded.** The hold invoice pays the
    worker the full amount. The 10% network and 5% voucher shares are worked out
    (rounding remainders go to the worker) but not automatically paid on.
    [Closed → #49] Should the worker forward them afterwards, or should the client pay
    separate invoices? And who gets the 5% when there is no vouch (now: shown as
    "voucher_held")? This is a Blueprint decision.
36. **Same-second ordering fixed.** Within one second, records are applied in their
    natural sequence (offer → accept → handoff → vouch → completion → dispute →
    decision → clear, with handoffs by sequence number), then by id. This replaces
    the note in #22; at computer speed it really happened.
37. **Cleanup done with Vinny's OK.** An older local regtest test node was stopped
    and its data deleted. Its local copy of the GitHub repo, with uncommitted edits,
    was kept and backed up. No other node was touched. [Closed → #52] Should this
    project move into the GitHub repo?

## 2026-10-10 — Phase 3: Taproot vouch bond

38. **Bond script (regtest).** Taproot with an unspendable internal key (BIP341
    NUMS point) and two leaves: `multi_a(2, client, voucher, arbiter)` and
    `and_v(v:pk(voucher), older(T))`. Both are standard miniscript, so the bond is
    the Bitcoin Core descriptor `tr(NUMS,{multi_a(2,C,V,A),and_v(v:pk(V),older(T))})`.
    Tests check that Core derives the same address. T = `bond.timelock_blocks`
    (2016), counted from the block that confirms the bond. [Revisit before
    anything real] Fixed NUMS means anyone can tell the bond has no key path;
    a randomized NUMS hides that, if it matters.
39. **Bond keys are the parties' operational keys** (the same x-only keys that
    sign their records); the arbiter keys come from `[arbiters]` in config. This
    is the simplest choice for the prototype. [Closed → #46: dedicated bond keys] Before mainnet:
    should bonds use separate per-bond keys? That would keep identity keys off
    chain and stop key rotation from affecting bonds that are already locked.
40. **Recusal is written into the bond.** The arbiter in the script is the
    founder, unless the founder is the client, worker, recipient or this voucher;
    then it is the backup. To keep that stable, a later vouch that would change
    the job's arbiter (e.g. the founder vouching after a bond already names the
    founder) is refused, and so is a vouch for which no arbiter is eligible. This
    applies only when arbiters are configured.
41. **The forfeit destination is enforced by the arbiter's tool, not the script**
    (no covenants, per the Nucleus). `arbiter_sign_forfeit` signs only if the
    vouch is forfeited by an upheld dispute on record, the spend matches this
    bond, the signer is the bond's arbiter, and the client has already signed
    the exact transaction.
42. **The vouch record's `bond` tag holds the funding txid.** The output is
    found by rebuilding the expected address from public facts. A txid is a
    public chain reference, not client data. One bond can back only one vouch.
    `check_bond` also flags a bond confirmed more than 2 hours before the job
    (its timelock would have started early).
43. **Unbonded vouches are still allowed** (the `bond` tag is optional, as in
    Phase 1). [Closed → #47: yes] Should scoring count a vouch only if its bond checks out?
    That needs chain access when scoring, which is currently offline.
44. **Spend fee is a flat 1,000 sats** (regtest). Real fee estimation comes later.

## 2026-10-10 — Updated brief ("Nucleus prototype", with closed decisions)

45. **The updated brief is now the plan; nothing was rebuilt.** Its phases map onto
    the work already done:
    - New 1 (events, job IDs, timestamps) = old Phase 1.
    - New 2 (keys and agents) = old Phase 2 + 2b.
    - New 3 (scoring) = the scoring from old Phase 1, updated below.
    - New 4 (bond + disputes) = old Phase 3.
    - New 5 (hold invoices) = old Phase 4.

    What was added for the update is listed in #46–#52.
46. **#39 closed: every bond has its own fresh key** (Vinny's decision). The bond
    key is generated when the bond is funded (`.keys/bonds/`, role "bond") and goes
    into the script in the voucher's place, for both the 2-of-3 and the reclaim
    path. The vouch record names it in a new optional `bondkey` tag, always
    together with `bond`. The rules refuse a bond key that is any key seen in
    the record (signer or named party) or an arbiter key, and a bond key or bond
    used twice. The voucher's operational key can't spend the bond (tested on
    chain). Recusal is still decided by the voucher's operational identity.
    [Open, small] The **client's** key in the script is still the client's
    operational key, because the brief speaks only of the voucher. Should clients
    also get a per-bond key? (It would need the client to take part when the bond
    is created.)
47. **#43 closed: a vouch counts only if its bond is live on-chain.** "Live"
    means:
    - the transaction exists and has the expected output;
    - it is confirmed, and wasn't locked more than 2 h before the job;
    - it holds the vouched amount and at least `bond.min_sats`;
    - it is unspent.

    `score --check-bonds` asks the sandbox node. Without chain access, vouches
    carry no weight, and the output says so. The chain tip used is printed for
    repeatability. Unbonded vouches are still accepted as records but never
    score.
    **Resolved by Vinny in favour of the Nucleus ("long clean history"):** a
    cleared vouch keeps counting after an **honest reclaim**. That means the bond
    passed every check above and was then spent through the voucher-alone
    timelock path. The checker finds the spending transaction and confirms its
    witness used the reclaim script with a sequence of at least T. Any other
    spend stops the vouch counting, e.g. a 2-of-3 forfeit, or a client+voucher
    early release. The report shows `live` (still locked), `counts` (live or
    honestly reclaimed) and `reclaimed_by`. Finding the spender needs the
    sandbox node; a real deployment would use an indexer.
48. **#11 closed: formula v1** (`SCORING.md`). It is `1 × clean completions +
    2 × clean vouches with a live bond − 5 × lost disputes`, all three weights
    in `config.toml`. A "lost dispute" is an upheld dispute against you as
    worker, or a vouch of yours forfeited by one. The output prints the
    weights used.
49. **#35 closed: fee shares, simple.** `fees.payout` chooses the mechanism:
    - `"lightning"`: each share is a separate Lightning payment to the payee's
      invoice, which must be for exactly the amount owed.
    - `"sweep"`: network shares accumulate and are swept on-chain to
      `fees.sweep_address`, which must be a test-network address.

    Voucher shares are always withheld until the job's dispute window closes,
    then paid by Lightning, split evenly among the job's vouchers.
    Confirmed by Vinny:
    - A forfeited vouch's share goes to the client.
    - With no vouch, the worker keeps the 5% (`fees.unvouched_share = "worker"`;
      it can be switched to the network).

    The list of shares owed is private bookkeeping (`data/private/fees.json`).
    It can't count the same payment twice.
50. **Recovery keys are kept apart from the running tool.**
    - `recovery-keygen` writes them to their own gitignored folder (`.recovery/`)
      with role "recovery".
    - `onboard` takes only the recovery **public** key (`--recovery-pub`).
    - `recover` and `revoke-agent` read the recovery key only from an explicit
      file path (`--recovery-file`), meant to be used offline.
    - Every normal command refuses a recovery-role key, even one dropped into the
      everyday keys folder.
51. **New Phase 1 checks.** A test collects every salt and nonce the tool
    stored privately (job-ID nonce, item, receipt, reason, ruling), plus the
    private terms text, and fails if any of them appears in a published record
    or timestamp proof, as text or as raw bytes. `verify-job <job id>`
    rebuilds one job's chain from the public record: every record that names
    the job, in order, with its signer, its status under the rules, what it
    references and its timestamp status. It fails if anything is rejected,
    missing or unproven.
52. **Moving into the GitHub repo (#37): approved by Vinny** as an `incentives/`
    folder in github.com/VincentLaRocca/human-trust-network, on a new branch with
    a pull request so it can be reviewed before it reaches `main`. Before
    publishing, details about the development PC (folder paths, other local nodes)
    were made generic in #2, #31 and #37, since they have no bearing on the
    prototype. Because older commits still contain those details, the project is
    published as one snapshot commit; the step-by-step history stays in the local
    repo.
