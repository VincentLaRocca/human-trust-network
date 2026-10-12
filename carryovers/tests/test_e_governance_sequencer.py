import pytest, pathlib, re
from htn_carry import params
from htn_carry.params import ParamLog, ParamError
from htn_carry.sequencer import Rail, Sequencer, SeqError, Batch


@pytest.mark.parametrize("name", ["halt", "pause", "freeze", "emergency_stop", "kill_switch", "emission_rate", "mint"])
def test_adv_halt_or_emission_param_attempt_rejected(name):
    with pytest.raises(ParamError):
        ParamLog().propose(name, True, 0)


def test_adv_no_halt_function_in_code():
    src = "".join(p.read_text() for p in pathlib.Path("htn_carry").glob("*.py"))
    assert not [d for d in re.findall(r"def (\w+)", src) if re.search(r"halt|pause|kill|emergency|freeze", d, re.I)]


@pytest.mark.parametrize("name", list(params.LOCKED))
def test_adv_locked_decisions_cannot_change(name):
    with pytest.raises(ParamError):
        ParamLog().propose(name, 1, 0)


def test_timelock_visible_then_effective():
    pl = ParamLog()
    pl.propose("half_life_delivery", 6, announce_epoch=10)
    assert pl.entries[0]["effective"] == 14
    assert pl.value("half_life_delivery", 13) == 3 and pl.value("half_life_delivery", 14) == 6
    assert pl.verify()


def test_adv_timelock_bypass_and_tamper():
    pl = ParamLog()
    with pytest.raises(ParamError):
        pl.propose("half_life_delivery", 1, 10, effective_epoch=11)
    pl.propose("half_life_delivery", 6, 10)
    pl.entries[0]["effective"] = 11
    assert not pl.verify()


def test_adv_equivocation_forfeits_bond_and_hands_off():
    rail = Rail([Sequencer("S0", 1000), Sequencer("S1", 1000), Sequencer("S2", 1000)])
    b0 = rail.submit_batch([{"kind": "reservation", "amount": 100}], 1)
    fake = Batch(0, b0.prev, [{"kind": "reservation", "amount": 999}], "S0", 1).header()
    res = rail.observe_header(fake)
    assert res["sequencer"] == "S0" and res["amount"] == 1000
    assert rail.seq.key == "S1" and rail.order[0].forfeited
    rail.submit_batch([{"kind": "reservation", "amount": 1}], 3)   # S1 continues
    assert rail.batches[-1].signer == "S1"


def test_adv_sequencer_withholding_blocks_release_then_handoff_no_forfeit():
    rail = Rail([Sequencer("S0", 1000), Sequencer("S1", 1000)])
    rail.submit_batch([{"kind": "reservation", "amount": 100}], 1, published=False)
    rail.submit_batch([{"kind": "reservation", "amount": 100}], 2)
    assert not rail.can_release(1, tip_height=50)          # D10 rule 3
    assert rail.tick(5) is None and rail.tick(6) is None
    nxt = rail.tick(7)
    assert nxt.key == "S1" and not rail.order[0].forfeited   # withholding not provable -> liveness handoff


def test_adv_no_successor_falls_back_to_presplit():
    rail = Rail([Sequencer("S0", 1000)])
    rail.submit_batch([], 1)
    with pytest.raises(SeqError, match="pre-split"):
        rail.observe_header(Batch(0, "00" * 32, ["x"], "S0", 1).header())


def test_k6_and_N0():
    rail = Rail([Sequencer("S0", 1000)])
    rail.submit_batch([{"kind": "reservation", "amount": 10}], 100)
    assert not rail.can_release(0, 104) and rail.can_release(0, 105)
    assert not rail.can_release(0, 200, observed_own_node=False)


def test_adv_bond_below_exposure_refuses_reservations():
    rail = Rail([Sequencer("S0", 300)])
    rail.submit_batch([{"kind": "reservation", "amount": 250}], 1)
    with pytest.raises(SeqError):
        rail.submit_batch([{"kind": "reservation", "amount": 51}], 2)
