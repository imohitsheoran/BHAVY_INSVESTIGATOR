from si.reasoner import Reasoner
from si.abr import ABR

def test_reasoner_retains_uaf_as_not_testable():
    hs=Reasoner().generate(ABR([],None,{}, {'kind':'near_null'}, [], []))
    uaf=next(h for h in hs if h.id=='H-UAF')
    assert uaf.testability=='NOT TESTABLE with current evidence'

def test_rule_based_reasoner_label():
    assert Reasoner.__name__=='Reasoner'
