import pytest
from htn_carry.registry import Registry, RegistryError
from htn_carry.scoring import cluster_contributions
from htn_carry.commit import CommitLog, attest_commitment, check_reveal, CommitError


def cartel_world():
    r = Registry()
    r.register("honest", 250, "hon:0", 0)
    for i in range(10):
        r.register(f"m{i}", 250, f"mtx{i}:0", 0)      # distinct funding: only mirroring links them
    votes = [("honest", f"s{j}", 10, 1) for j in range(6)]
    votes += [(f"m{i}", f"s{j}", 10, 0 if j == 0 else (j % 2)) for i in range(10) for j in range(6)]
    return r, votes


def test_adv_mirror_cartel_counts_as_one():
    r, votes = cartel_world()
    c, cmap = cluster_contributions(r, 10, votes, "s0")
    assert len({cmap[f"m{i}"] for i in range(10)}) == 1
    assert sorted(c) == [(1.0, 0), (1.0, 1)]


def test_mirror_cluster_shares_one_weight_cap():
    r, votes = cartel_world()
    c, _ = cluster_contributions(r, 10, votes, "s0")
    assert max(w for w, _ in c) == 1.0           # 2500 stake, still one capped source


def test_adv_copying_is_not_slashed():
    r, _ = cartel_world()
    with pytest.raises(RegistryError):
        r.slash_wrong_confirmer("m0", shown_wrong=False, amount=250)
    assert r.attesters["m0"].slashed == 0


def test_only_shown_wrong_slashed_reporter_cap():
    r, _ = cartel_world()
    amt, rep = r.slash_wrong_confirmer("m0", shown_wrong=True, amount=250)
    assert amt == 250 and rep == 62.5


def test_adv_copy_after_reveal_impossible_commit_first():
    log = CommitLog()
    s = log.commit("attest", attest_commitment("a", "ns", "x", 1, 1, "salt"))
    floor = log.commit("phase", "open")
    s2 = log.commit("attest", attest_commitment("copier", "ns", "x", 1, 1, "salt2"))
    assert check_reveal(log, s, floor, "a", "ns", "x", 1, 1, "salt")
    with pytest.raises(CommitError):
        check_reveal(log, s2, floor, "copier", "ns", "x", 1, 1, "salt2")


def test_adv_reveal_cannot_switch_outcome():
    log = CommitLog()
    s = log.commit("attest", attest_commitment("a", "ns", "x", 1, 1, "salt"))
    floor = log.commit("phase", "open")
    with pytest.raises(CommitError):
        check_reveal(log, s, floor, "a", "ns", "x", 1, 0, "salt")
