"""(e) Locked §0 values plus a time-locked, visible parameter log. There is no halt function."""
from dataclasses import dataclass, field
import hashlib, json, math

B = 250.0
F = 0.5
G0 = 0.16 * B          # 40; 0.32*B only after D10 proven (D13) -- not switchable here
GATE = 0.8
S_COUNTER = 375.0
REPORTER_MAX = 0.25    # (1-f)/2
K_CONF = 6
SEQ_BOND_MULT = 1.0
TIMELOCK_EPOCHS = 4    # delay before a visible change takes effect

# Locked decisions: no change path at all.
LOCKED = {"B": B, "F": F, "G0": G0, "GATE": GATE, "S_COUNTER": S_COUNTER,
          "REPORTER_MAX": REPORTER_MAX, "K_CONF": K_CONF, "SEQ_BOND_MULT": SEQ_BOND_MULT}
# Small set of tunables that may change, only via the time-locked log.
TUNABLE = {"half_life_delivery": 3, "half_life_records": 12, "half_life_identity": 24,
           "half_life_custody": 6, "commit_window": 1}
FORBIDDEN_NAMES = {"halt", "pause", "freeze", "emergency_stop", "kill_switch",
                   "emission", "emission_rate", "mint", "mint_rate", "burn_price", "registration_burn"}


class ParamError(Exception):
    pass


@dataclass
class ParamLog:
    """Append-only, hash-chained. Every change is visible from announcement and only applies
    at announce_epoch + TIMELOCK_EPOCHS."""
    entries: list = field(default_factory=list)

    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else "00" * 32

    def propose(self, name, value, announce_epoch, effective_epoch=None):
        if name in FORBIDDEN_NAMES:
            raise ParamError(f"{name}: no such function exists (no halt, no emission)")
        if name in LOCKED:
            raise ParamError(f"{name} is a locked §0 decision")
        if name not in TUNABLE:
            raise ParamError(f"unknown parameter {name}")
        eff = announce_epoch + TIMELOCK_EPOCHS if effective_epoch is None else effective_epoch
        if eff < announce_epoch + TIMELOCK_EPOCHS:
            raise ParamError("timelock bypass: effective epoch earlier than announce + TIMELOCK")
        body = {"name": name, "value": value, "announce": announce_epoch, "effective": eff, "prev": self.head()}
        h = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        self.entries.append({**body, "hash": h})
        return h

    def verify(self):
        prev = "00" * 32
        for e in self.entries:
            body = {k: e[k] for k in ("name", "value", "announce", "effective", "prev")}
            if e["prev"] != prev or hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != e["hash"]:
                return False
            if e["effective"] < e["announce"] + TIMELOCK_EPOCHS:
                return False
            prev = e["hash"]
        return True

    def value(self, name, epoch):
        if name in LOCKED:
            return LOCKED[name]
        v = TUNABLE[name]
        for e in self.entries:
            if e["name"] == name and e["effective"] <= epoch:
                v = e["value"]
        return v


def exposure_cap(bond, s_at_risk, n):
    """§7: min(f*(B+S_at_risk), G0*sqrt(n)), n>=1."""
    return min(F * (bond + s_at_risk), G0 * math.sqrt(max(1, n)))
