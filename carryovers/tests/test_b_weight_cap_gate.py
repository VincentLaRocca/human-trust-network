import pytest
from htn_carry import params
from htn_carry.scoring import Namespace, cluster_contributions
from htn_carry.registry import Registry, RegistryError
from conftest import make_world


def test_exposure_cap_formula_locked_values():
    assert params.exposure_cap(250, 0, 1) == pytest.approx(40)            # G0*sqrt(1)
    assert params.exposure_cap(250, 0, 100) == pytest.approx(125)         # f*(B) binds
    assert params.exposure_cap(250, 375, 400) == pytest.approx(312.5)
    assert params.G0 == 40 and params.F == 0.5 and params.GATE == 0.8


def test_weight_per_cluster_capped_at_one_never_stake_weighted():
    log, reg = make_world(0)
    reg.register("whale", 1_000_000, "w:0", 0)
    reg.register("small", 250, "s:0", 0)
    c, _ = cluster_contributions(reg, 10, [("whale", "x", 10, 0), ("small", "x", 10, 1)], "x")
    assert sorted(w for w, _ in c) == [1.0, 1.0]   # 4000x stake, same weight


def test_adv_cap_bypass_by_splitting_bond_same_funding():
    reg = Registry()
    for i in range(8):
        reg.register(f"split{i}", 250, f"bigtx:{i}", 0)   # one funding tx, 8 outputs
    c, _ = cluster_contributions(reg, 10, [(f"split{i}", "x", 10, 1) for i in range(8)], "x")
    assert len(c) == 1 and c[0][0] == 1.0


def test_adv_cap_bypass_by_splitting_below_B_refused():
    reg = Registry()
    with pytest.raises(RegistryError):
        reg.register("tiny", 249.99, "t:0", 0)


def test_adv_D1_stake_cannot_back_two_subjects():
    reg = Registry()
    reg.register("a", 250, "a:0", 0)
    reg.allocate("a", "subj1")
    with pytest.raises(RegistryError):
        reg.allocate("a", "subj2")
    with pytest.raises(RegistryError):
        reg.register("a2", 250, "a:0", 0)   # same outpoint reused


def test_gate_08_lower_bound():
    ns = Namespace("d", "delivery")
    ns.update("thin", [(1.0, 1)] * 3, 1.0)
    assert not ns.passes_gate("thin")          # mean 0.8 but lower bound far below
    ns.update("thick", [(1.0, 1)] * 20, 1.0)
    assert ns.passes_gate("thick")
    assert ns.confidence("thick") >= 0.8
