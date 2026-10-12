"""STUBs: named, unbuilt pieces. Each raises so nothing silently pretends to work."""


class StubError(NotImplementedError):
    pass


def STUB_dispute_procedure(*a, **k):
    raise StubError("STUB: counter/dispute procedure (§8 review -> collapse -> slash) not built")


def STUB_ground_truth(*a, **k):
    raise StubError("STUB: ground-truth resolution (and the p in [0.5,1.5] prediction multiplier) not built")


def STUB_bitcoin_settlement(*a, **k):
    raise StubError("STUB: real Bitcoin anchoring/confirmations (bitcoind) not wired; heights are simulated ints")


def STUB_lightning_settlement(*a, **k):
    raise StubError("STUB: Lightning fee collection/payout not built; fees are given integer sats")


def STUB_funding_ancestry(*a, **k):
    raise StubError("STUB: real funding-ancestry/vouch-graph clustering; only same-txid funding + mirroring + newcomer rules built")


def STUB_signatures(*a, **k):
    raise StubError("STUB: no real keys or signatures; keys are label strings")
