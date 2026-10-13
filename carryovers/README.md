# htn-carryovers — LOCAL PROTOTYPE (not pushed, Satoshi Mode)
Bittensor carry-overs (a)-(g) per /workspace/bittensor/review/audit.md, under the locked §0 of
/workspace/stat-truths/spec.md (unchanged). Python 3 + pytest. No real keys: keys are label strings.

| item | files | tests |
|---|---|---|
| a namespaces on one rail/sequencer | htn_carry/scoring.py, sequencer.py | tests/test_a_namespaces.py |
| b weight cap (D1) + 0.8 gate | scoring.py, registry.py, params.py (exposure_cap) | tests/test_b_weight_cap_gate.py |
| c sats fees only, no emission | rewards.py | tests/test_c_rewards.py |
| d sybil cost = bond at risk | registry.py | tests/test_d_sybil_bond.py |
| e timelocked params, no halt, forfeit+handoff | params.py, sequencer.py | tests/test_e_governance_sequencer.py |
| f commit-before-output, recompute_and_verify | commit.py, verify.py | tests/test_f_commit_verify.py |
| g mirrors = one source/one cap, commit-reveal, no copy slash | clusters.py, scoring.py, commit.py, registry.py | tests/test_g_correlation_commit_reveal.py |

## Design notes / deviations to review
- Withholding: spec §7a says it is not provable by one message, so a withholding sequencer is handed off
  after WITHHOLD_TIMEOUT=2 epochs WITHOUT bond forfeit. Forfeit happens on equivocation (S3 chain-data proof).
- S2 is a consumer-side refusal to release while a fraud proof is open; it is not a protocol halt switch.
- Mirror detection (>=95% agreement over >=5 shared items) also merges honest attesters who agree on everything.
  That is conservative (correlated-by-default, §4) but under-counts honest independents; spec §4.5's timing condition
  is not modelled.
- Fee rewards pay by capped cluster weight for participation, not agreement; ground-truth weighting is STUB.
- WITHHOLD_TIMEOUT, TIMELOCK_EPOCHS=4, S_REF=100, mirror thresholds are prototype values, not §0 decisions.

## STUBs (htn_carry/stubs.py, each raises)
dispute procedure, ground truth, Bitcoin anchoring/confirmations, Lightning settlement, funding-ancestry clustering, signatures.
