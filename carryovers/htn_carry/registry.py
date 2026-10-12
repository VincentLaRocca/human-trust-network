"""(d)+(b) Registration costs a locked, slashable bond (D1 exclusive). Never a burn, never a price curve."""
from dataclasses import dataclass, field
from . import params


class RegistryError(Exception):
    pass


@dataclass
class Attester:
    key: str
    bond: float
    funding_outpoint: str          # used by clustering (shared funding ancestry)
    first_epoch: int
    slashed: float = 0.0
    allocated_to: str | None = None  # D1: a stake unit backs one subject at a time

    @property
    def at_risk(self):
        return self.bond - self.slashed


@dataclass
class Registry:
    attesters: dict = field(default_factory=dict)
    used_outpoints: set = field(default_factory=set)

    def register(self, key, bond, funding_outpoint, epoch, burn=None):
        if burn is not None:
            raise RegistryError("registration is never priced by burn; post a bond")
        if bond < params.B:
            raise RegistryError(f"bond {bond} < B={params.B}")
        if key in self.attesters:
            raise RegistryError("key already registered")
        if funding_outpoint in self.used_outpoints:
            raise RegistryError("D1: outpoint already locks another bond (no reuse)")
        self.used_outpoints.add(funding_outpoint)
        a = Attester(key, float(bond), funding_outpoint, epoch)
        self.attesters[key] = a
        return a

    def allocate(self, key, subject):
        a = self.attesters[key]
        if a.allocated_to not in (None, subject):
            raise RegistryError("D1: stake already backs another subject")
        a.allocated_to = subject

    def slash_wrong_confirmer(self, key, shown_wrong: bool, amount):
        """Only confirmers SHOWN WRONG (resolved ground truth / upheld counter) are slashed. STUB: the dispute
        procedure that produces `shown_wrong` is not built."""
        if not shown_wrong:
            raise RegistryError("slash refused: only confirmers shown wrong are slashed")
        a = self.attesters[key]
        amt = min(amount, a.at_risk)
        a.slashed += amt
        return amt, amt * params.REPORTER_MAX  # (slashed, max reporter reward <= 0.25)

    def withdraw(self, key, live_exposure):
        if live_exposure > 0:
            raise RegistryError("bond locked while exposure outstanding")
        a = self.attesters.pop(key)
        return a.at_risk

    def sybil_cost(self, n_identities):
        """Capital locked and slashable for n identities. Does not decay."""
        return n_identities * params.B
