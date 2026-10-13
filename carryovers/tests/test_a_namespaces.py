import pytest
from htn_carry.scoring import Namespace, NamespaceError
from htn_carry.sequencer import Rail, Sequencer, SeqError
from htn_carry.params import ParamLog


def test_namespaces_share_one_rail_and_sequencer():
    rail = Rail([Sequencer("S0", 10_000)])
    a, b = Namespace("deliv", "delivery"), Namespace("vet", "records")
    rail.register_namespace(a); rail.register_namespace(b)
    assert set(rail.namespaces) == {"deliv", "vet"}
    rail.submit_batch([{"ns": "deliv", "kind": "reservation", "amount": 10}], 1)
    rail.submit_batch([{"ns": "vet", "kind": "reservation", "amount": 10}], 2)
    assert {x.signer for x in rail.batches} == {"S0"}
    assert rail.batches[1].prev == rail.batches[0].root()


@pytest.mark.parametrize("attr", ["sequencer", "token", "mint", "emission"])
def test_adv_namespace_cannot_get_own_sequencer_or_token(attr):
    ns = Namespace("x", "delivery")
    with pytest.raises(NamespaceError):
        setattr(ns, attr, object())


def test_adv_second_sequencer_cannot_sign_for_a_namespace():
    rail = Rail([Sequencer("S0", 1000), Sequencer("S1", 1000)])
    with pytest.raises(SeqError):
        rail.submit_batch([{"ns": "deliv"}], 1, signer="S1")


def test_namespaces_score_independently_with_own_half_life():
    plog = ParamLog()
    a, b = Namespace("deliv", "delivery"), Namespace("id", "identity")
    for ns in (a, b):
        ns.update("subj", [(1.0, 1)] * 5, ns.lam(plog, 0))
    for _ in range(6):
        a.update("subj", [], a.lam(plog, 0)); b.update("subj", [], b.lam(plog, 0))
    assert a.state["subj"][0] < b.state["subj"][0]   # 3-month decays faster than 24-month
