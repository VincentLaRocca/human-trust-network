"""(a)+(e) ONE rail, ONE active bonded sequencer (k=6, bond>=1x max concurrent exposure, S1-S3 modelled).
Failure: equivocation -> bond forfeit + handoff to next in order. Withholding -> no release (D10 rule 3),
then handoff after WITHHOLD_TIMEOUT. No halt function exists anywhere.
STUB: real Bitcoin anchoring / confirmations / LN settlement are simulated integers, not bitcoind."""
from dataclasses import dataclass, field
from . import params
from .commit import h

WITHHOLD_TIMEOUT = 2  # epochs of unavailable batch contents before handoff


class SeqError(Exception):
    pass


@dataclass
class Sequencer:
    key: str
    bond: float
    forfeited: bool = False


@dataclass
class Batch:
    seq: int
    prev: str
    items: list
    signer: str
    anchor_height: int
    published: bool = True

    def root(self):
        return h({"seq": self.seq, "prev": self.prev, "items": self.items})

    def header(self):  # S3: what goes in the OP_RETURN of a sequencer-key-signed anchor
        return {"seq": self.seq, "prev": self.prev, "root": self.root(), "signer": self.signer}


@dataclass
class Rail:
    order: list                         # successors in order
    active: int = 0
    batches: list = field(default_factory=list)
    headers_seen: list = field(default_factory=list)   # all anchor headers seen on chain (any branch)
    live_exposure: float = 0.0
    forfeits: list = field(default_factory=list)
    unavailable_since: int | None = None
    namespaces: dict = field(default_factory=dict)

    @property
    def seq(self):
        return self.order[self.active]

    def register_namespace(self, ns):
        if ns.name in self.namespaces:
            raise SeqError("namespace exists")
        self.namespaces[ns.name] = ns   # shares this rail and this sequencer; nothing per-namespace

    def submit_batch(self, items, anchor_height, published=True, signer=None):
        signer = signer or self.seq.key
        if signer != self.seq.key:
            raise SeqError("only the active sequencer signs batches")
        add = sum(i.get("amount", 0) for i in items if i.get("kind") == "reservation")
        if self.live_exposure + add > self.seq.bond * params.SEQ_BOND_MULT:
            raise SeqError("bond < max concurrent live exposure: reservations refused")
        prev = self.batches[-1].root() if self.batches else "00" * 32
        b = Batch(len(self.batches), prev, items, signer, anchor_height, published)
        self.batches.append(b)
        self.headers_seen.append(b.header())
        self.live_exposure += add
        return b

    def observe_header(self, header):
        """Any header seen on any branch (S3). Two headers with same signer+seq (or same prev) and different
        roots are an equivocation proof from chain data alone."""
        self.headers_seen.append(header)
        return self.check_equivocation()

    def check_equivocation(self):
        seen = {}
        for hd in self.headers_seen:
            for key in (("seq", hd["signer"], hd["seq"]), ("prev", hd["signer"], hd["prev"])):
                if key in seen and seen[key] != hd["root"]:
                    return self._forfeit_and_handoff(hd["signer"], "equivocation")
                seen[key] = hd["root"]
        return None

    def _forfeit_and_handoff(self, signer, reason):
        s = next(x for x in self.order if x.key == signer)
        if not s.forfeited:
            s.forfeited = True
            self.forfeits.append({"sequencer": signer, "amount": s.bond, "reason": reason,
                                  "paid_first_to": "consumers who released on voided branch (STUB: dispute payout)"})
        if self.seq.key == signer:
            self._handoff()
        self.headers_seen = [x for x in self.headers_seen if x["signer"] != signer]
        return self.forfeits[-1]

    def _handoff(self):
        for i in range(self.active + 1, len(self.order)):
            if not self.order[i].forfeited:
                self.active = i
                self.unavailable_since = None
                return self.order[i]
        raise SeqError("no bonded successor: fall back to anchored pre-split (>=144 conf)")

    def can_release(self, batch_seq, tip_height, observed_own_node=True):
        """D10 rules 1-3 + S1 + S2 from the consumer's side."""
        if not observed_own_node:
            return False                          # N0 / S1
        if any(s.forfeited for s in self.order[: self.active + 1]) and self.check_equivocation():
            return False                          # S2: consumer refuses while a fraud proof is open
        for b in self.batches[: batch_seq + 1]:
            if not b.published:
                return False                      # rule 3: data availability
        b = self.batches[batch_seq]
        return tip_height - b.anchor_height + 1 >= params.K_CONF   # rule 1, k=6

    def tick(self, epoch):
        """Liveness: if any batch contents stay unpublished for WITHHOLD_TIMEOUT epochs, hand off.
        Withholding is not provable by one message (spec §7a) so the bond is NOT forfeited for it."""
        if any(not b.published for b in self.batches):
            if self.unavailable_since is None:
                self.unavailable_since = epoch
            elif epoch - self.unavailable_since >= WITHHOLD_TIMEOUT:
                return self._handoff()
        else:
            self.unavailable_since = None
        return None
