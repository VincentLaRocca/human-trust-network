"""(f) Commit every input before output; anyone with public data recomputes payouts.
Rejects any output whose inputs were committed at or after the output's own seq (the Bittensor StakeWeight
circularity: Yuma's stake input was read at the block the epoch itself writes)."""
from .commit import CommitLog, CommitError, attest_commitment, check_reveal, h
from .registry import Registry
from .scoring import cluster_contributions
from .rewards import distribute
from .clusters import clusters


class VerifyError(Exception):
    pass


def registry_snapshot(reg):
    return sorted([{"key": a.key, "bond": a.bond, "funding_outpoint": a.funding_outpoint,
                    "first_epoch": a.first_epoch, "slashed": a.slashed} for a in reg.attesters.values()],
                  key=lambda x: x["key"])


def _compute(snapshot, reveals, fee_sats, namespace, epoch):
    reg = Registry()
    for r in snapshot:
        a = reg.register(r["key"], r["bond"], r["funding_outpoint"], r["first_epoch"])
        a.slashed = r["slashed"]
    tuples = [(r["attester"], r["subject"], r["epoch"], r["outcome"]) for r in reveals if r["namespace"] == namespace]
    cmap = clusters(reg, epoch, tuples)
    contribs, weights, members = {}, {}, {}
    for subj in sorted({t[1] for t in tuples if t[2] == epoch}):
        c, _ = cluster_contributions(reg, epoch, tuples, subj)
        contribs[subj] = c
    for a, s, e, o in tuples:
        if e == epoch:
            cid = cmap[a]
            members.setdefault(cid, set()).add(a)
    for cid, mem in members.items():
        weights[cid] = min(1.0, sum(reg.attesters[m].at_risk for m in mem) / 100.0)
    payouts = distribute(fee_sats, weights, {k: list(v) for k, v in members.items()})
    return {"contributions": contribs, "payouts": payouts}


def run_epoch(log: CommitLog, reg: Registry, namespace, epoch, reveals, fees, reveal_floor):
    """reveals already checked against commits by caller or here. Commits the registry snapshot and fees as
    inputs, then the output, and returns the public data blob."""
    snap = registry_snapshot(reg)
    snap_d = h({"registry": snap, "epoch": epoch})
    if snap_d not in log.by_digest:
        log.commit("registry", snap_d)
    fee_ds = []
    for f in fees:
        d = h({"fee": f})
        if d not in log.by_digest:
            log.commit("fee", d)
        fee_ds.append(d)
    inputs = [snap_d] + fee_ds + [attest_commitment(r["attester"], r["namespace"], r["subject"], r["epoch"],
                                                    r["outcome"], r["salt"]) for r in reveals]
    res = _compute(snap, reveals, sum(f["sats"] for f in fees), namespace, epoch)
    out_d = h({"inputs": inputs, "result": res})
    out_seq = log.commit("output", out_d)
    return {"commits": [list(i) for i in log.items], "registry": snap, "reveals": reveals, "fees": fees,
            "reveal_floor": reveal_floor, "namespace": namespace, "epoch": epoch,
            "output": {"seq": out_seq, "inputs": inputs, "result": res}}


def recompute_and_verify(pd):
    log = CommitLog()
    for seq, kind, d in pd["commits"]:
        if seq != len(log.items):
            raise VerifyError("commit log not contiguous")
        log.commit(kind, d)
    out = pd["output"]
    out_seq = out["seq"]
    if log.items[out_seq][1] != "output" or log.items[out_seq][2] != h({"inputs": out["inputs"], "result": out["result"]}):
        raise VerifyError("output not committed as claimed")
    snap_d = h({"registry": pd["registry"], "epoch": pd["epoch"]})
    fee_ds = [h({"fee": f}) for f in pd["fees"]]
    rev_ds = [attest_commitment(r["attester"], r["namespace"], r["subject"], r["epoch"], r["outcome"], r["salt"])
              for r in pd["reveals"]]
    if out["inputs"] != [snap_d] + fee_ds + rev_ds:
        raise VerifyError("output inputs do not match public data")
    for d in out["inputs"]:
        try:
            s = log.seq_of(d)
        except CommitError:
            raise VerifyError("input never committed")
        if s >= out_seq:
            raise VerifyError(f"circularity: input committed at seq {s} >= output seq {out_seq}")
    for r in pd["reveals"]:
        try:
            check_reveal(log, r["commit_seq"], pd["reveal_floor"], r["attester"], r["namespace"], r["subject"],
                         r["epoch"], r["outcome"], r["salt"])
        except CommitError as e:
            raise VerifyError(str(e))
    res = _compute(pd["registry"], pd["reveals"], sum(f["sats"] for f in pd["fees"]), pd["namespace"], pd["epoch"])
    if h(res) != h(out["result"]):
        raise VerifyError("recomputed payouts differ")
    return res
