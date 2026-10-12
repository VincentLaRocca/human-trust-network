import copy, pytest
from htn_carry.verify import run_epoch, recompute_and_verify, VerifyError
from htn_carry.commit import h
from conftest import make_world, commit_reveals

NS, EP = "deliv", 10


def world():
    log, reg = make_world(5)
    rev, floor = commit_reveals(log, [(f"h{i}", "subj", 1) for i in range(5)], NS, EP)
    pd = run_epoch(log, reg, NS, EP, rev, [{"txid": "fee1", "sats": 12345}], floor)
    return pd


def test_honest_recompute_matches():
    pd = world()
    res = recompute_and_verify(pd)
    assert sum(res["payouts"].values()) == 12345


def test_adv_tampered_payout_rejected():
    pd = world()
    pd["output"]["result"]["payouts"]["h0"] += 1
    with pytest.raises(VerifyError):
        recompute_and_verify(pd)


def test_adv_late_commit_stakeweight_circularity_rejected():
    """Registry (stake) committed AFTER the output -> the Bittensor StakeWeight circularity."""
    pd = world()
    out_seq = pd["output"]["seq"]
    snap_d = pd["output"]["inputs"][0]
    commits = [c for c in pd["commits"] if c[2] != snap_d]
    commits = [[i, k, d] for i, (_, k, d) in enumerate(commits)]
    commits.append([len(commits), "registry", snap_d])
    pd["commits"] = commits
    pd["output"]["seq"] = out_seq - 1
    with pytest.raises(VerifyError, match="circularity"):
        recompute_and_verify(pd)


def test_adv_uncommitted_input_rejected():
    pd = world()
    pd["fees"].append({"txid": "ghost", "sats": 1})
    pd["output"]["inputs"].insert(2, h({"fee": pd["fees"][-1]}))
    with pytest.raises(VerifyError):
        recompute_and_verify(pd)


def test_adv_late_attestation_commit_rejected():
    log, reg = make_world(5)
    rev, floor = commit_reveals(log, [(f"h{i}", "subj", 1) for i in range(4)], NS, EP)
    late, _ = commit_reveals(log, [("h4", "subj", 0)], NS, EP)   # committed after reveal phase opened
    pd = run_epoch(log, reg, NS, EP, rev + late, [{"txid": "f", "sats": 100}], floor)
    with pytest.raises(VerifyError, match="late commit"):
        recompute_and_verify(pd)


def test_adv_reveal_changed_outcome_rejected():
    pd = world()
    pd["reveals"][0]["outcome"] = 0
    with pytest.raises(VerifyError):
        recompute_and_verify(pd)
