import pytest, pathlib, re
from htn_carry.rewards import distribute, RewardError


def test_conservation_exact_sats():
    p = distribute(1001, {"c1": 1.0, "c2": 0.5, "c3": 0.5}, {"c1": ["a"], "c2": ["b", "c"], "c3": ["d"]})
    assert sum(p.values()) == 1001 and all(isinstance(v, int) for v in p.values())


def test_zero_fees_pays_zero():
    assert distribute(0, {"c": 1.0}, {"c": ["a"]}) == {}


@pytest.mark.parametrize("bad", [-5, 10.5, "100"])
def test_adv_emission_attempt_via_pool_rejected(bad):
    with pytest.raises(RewardError):
        distribute(bad, {"c": 1.0}, {"c": ["a"]})


def test_adv_no_emission_or_mint_code_path():
    src = "".join(p.read_text() for p in pathlib.Path("htn_carry").glob("*.py"))
    defs = re.findall(r"def (\w+)", src)
    assert not [d for d in defs if re.search(r"mint|emi(t|ssion)|inflat|block_reward", d, re.I)]


def test_adv_mirrors_gain_nothing_by_multiplying_keys():
    one = distribute(1000, {"c1": 1.0, "c2": 1.0}, {"c1": ["a"], "c2": ["m"]})
    many = distribute(1000, {"c1": 1.0, "c2": 1.0}, {"c1": ["a"], "c2": [f"m{i}" for i in range(10)]})
    assert one["a"] == many["a"] == 500
    assert sum(v for k, v in many.items() if k != "a") == 500
