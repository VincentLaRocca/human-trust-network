"""(a)+(b)+(g) Scoring namespaces. Each namespace = a claim_type with its own half-life and scoring state.
All namespaces share ONE rail (Rail) and ONE sequencer. A namespace cannot own a sequencer or a token."""
from dataclasses import dataclass, field
from scipy.stats import beta as _beta
from . import params
from .clusters import clusters

S_REF = 100.0
HALF_LIFE_PARAM = {"delivery": "half_life_delivery", "records": "half_life_records",
                   "identity": "half_life_identity", "custody": "half_life_custody"}


class NamespaceError(Exception):
    pass


@dataclass
class Namespace:
    name: str
    claim_type: str
    alpha0: float = 1.0   # fixed prior (D5), never decayed
    beta0: float = 1.0
    state: dict = field(default_factory=dict)   # subject -> [a, b]

    def __setattr__(self, k, v):
        if k in ("sequencer", "token", "mint", "emission"):
            raise NamespaceError("a namespace cannot own a sequencer, token, mint or emission")
        object.__setattr__(self, k, v)

    def lam(self, plog, epoch):
        h = plog.value(HALF_LIFE_PARAM[self.claim_type], epoch)
        return 2 ** (-1 / h)

    def update(self, subject, contributions, lam):
        """contributions: list of (weight, outcome) with one entry per CLUSTER (already collapsed)."""
        a, b = self.state.get(subject, [0.0, 0.0])
        a = lam * a + sum(w for w, o in contributions if o == 1)
        b = lam * b + sum(w for w, o in contributions if o == 0)
        self.state[subject] = [a, b]

    def confidence(self, subject):
        a, b = self.state.get(subject, [0.0, 0.0])
        return float(_beta.ppf(0.025, self.alpha0 + a, self.beta0 + b))   # lower bound of 95% CI

    def passes_gate(self, subject):
        return self.confidence(subject) >= params.GATE


def cluster_contributions(registry, epoch, reveals_all, subject):
    """Collapse reveals for `subject` at `epoch` to one contribution per cluster.
    Cluster weight = min(1, cluster bond at risk / S_REF): capped per cluster, so splitting a bond or
    mirroring adds nothing. Never stake-weighted beyond the cap. Conflicting votes inside a cluster -> majority,
    ties dropped."""
    cmap = clusters(registry, epoch, reveals_all)
    per = {}
    for a, s, e, o in reveals_all:
        if s == subject and e == epoch and a in registry.attesters:
            per.setdefault(cmap[a], []).append((a, o))
    out = []
    for cid, items in sorted(per.items()):
        stake = sum(registry.attesters[k].at_risk for k in {a for a, _ in items})
        w = min(1.0, stake / S_REF)
        ones = sum(o for _, o in items)
        zeros = len(items) - ones
        if ones == zeros:
            continue
        out.append((w, 1 if ones > zeros else 0))
    return out, cmap
