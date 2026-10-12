import pytest
from htn_carry.registry import Registry, RegistryError
from htn_carry.scoring import cluster_contributions


def test_registration_by_burn_refused():
    with pytest.raises(RegistryError):
        Registry().register("x", 250, "x:0", 0, burn=0.0005)


def test_sybil_cost_is_linear_locked_bond_no_decay():
    r = Registry()
    assert r.sybil_cost(1000) == 250_000
    assert r.sybil_cost(1000) == r.sybil_cost(1000)  # no time argument; nothing decays to a floor


def test_adv_sybil_flood_counts_as_one_newcomer_source():
    r = Registry()
    r.register("old", 250, "old:0", 0)
    for i in range(200):
        r.register(f"syb{i}", 250, f"s{i}:0", 9)        # distinct funding, all new
    votes = [("old", "x", 10, 1)] + [(f"syb{i}", "x", 10, 0) for i in range(200)]
    c, _ = cluster_contributions(r, 10, votes, "x")
    assert sorted(c) == [(1.0, 0), (1.0, 1)]           # 200 sybils = 1 source; 50,000 locked


def test_adv_bond_cannot_exit_with_live_exposure():
    r = Registry(); r.register("a", 250, "a:0", 0)
    with pytest.raises(RegistryError):
        r.withdraw("a", live_exposure=10)
    assert r.withdraw("a", 0) == 250
