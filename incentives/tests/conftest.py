import dataclasses
import os

import pytest

from htn import events as ev
from htn import keys
from htn.config import Config

T0 = 1_700_000_000
DAY = 24 * 3600


class World:
    """A cast of keys plus helpers for building signed events in tests."""

    def __init__(self):
        for name in ("client", "worker", "recipient", "voucher", "founder", "backup",
                     "stranger", "courier2", "worker_rec", "worker_new", "thief", "agent"):
            setattr(self, name, keys.generate(name))
        self.config = Config(founder_arbiter=self.founder.pubkey, backup_arbiter=self.backup.pubkey)
        self.events: list[dict] = []

    def cfg(self, **changes) -> Config:
        return dataclasses.replace(self.config, **changes)

    def emit(self, key, kind, tags, at):
        e = ev.sign_event(key, kind, tags, at)
        self.events.append(e)
        return e

    def job(self, client=None, worker=None, recipient=None, at=T0, job_id=None, accept=True):
        """Client offers a job; by default the worker accepts one second later."""
        client, worker = client or self.client, worker or self.worker
        job_id = job_id or ev.make_job_id(b"private terms")[0]
        tags = [["job", job_id], ["p", worker.pubkey, "worker"]]
        if recipient:
            tags.append(["p", recipient.pubkey, "recipient"])
        offer = self.emit(client, ev.JOB_OFFER, tags, at)
        if accept:
            self.accept(worker, offer, at=at + 1)
        return offer

    def accept(self, signer, job_event, at):
        return self.emit(signer, ev.JOB_ACCEPTED, [["job", self.job_id(job_event)], ["e", job_event["id"]]], at)

    @staticmethod
    def job_id(job_event):
        return next(t[1] for t in job_event["tags"] if t[0] == "job")

    def handoff(self, signer, job_event, to, seq, at=T0 + 60):
        return self.emit(signer, ev.HANDOFF, [
            ["job", self.job_id(job_event)], ["e", job_event["id"]], ["p", to.pubkey, "to"],
            ["item", ev.commit(b"seal 1")[0]], ["seq", str(seq)]], at)

    def complete(self, signer, job_event, at=T0 + 3600, worker=None):
        return self.emit(signer, ev.COMPLETION, [
            ["job", self.job_id(job_event)], ["e", job_event["id"]],
            ["p", (worker or self._worker_of(job_event)), "worker"],
            ["receipt", ev.commit(b"receipt")[0]]], at)

    def dispute(self, signer, job_event, at=T0 + DAY):
        return self.emit(signer, ev.DISPUTE_FILED, [
            ["job", self.job_id(job_event)], ["e", job_event["id"]],
            ["p", self._worker_of(job_event), "worker"], ["reason", ev.commit(b"broken seal")[0]]], at)

    def resolve(self, signer, dispute_event, outcome, at=T0 + 2 * DAY):
        return self.emit(signer, ev.DISPUTE_RESOLVED, [
            ["job", self.job_id(dispute_event)], ["e", dispute_event["id"]], ["outcome", outcome]], at)

    def vouch(self, signer, job_event, amount=50_000, at=T0 + 600, bond=None, bondkey=None):
        tags = [["job", self.job_id(job_event)], ["e", job_event["id"]],
                ["p", self._worker_of(job_event), "worker"], ["amount", str(amount)]]
        if bond:
            tags += [["bond", bond], ["bondkey", bondkey]]
        return self.emit(signer, ev.VOUCH_ISSUED, tags, at)

    def bonded_vouch(self, signer, job_event, chain=None, amount=50_000, at=T0 + 600, sats=None,
                     txid=None, blocktime=None):
        """Fresh bond key + bond terms; the bond is put on the fake chain if one is given.
        Returns (vouch event, bond key, txid)."""
        from htn import bond
        from htn.ledger import Ledger
        bkey = keys.generate("bond")
        terms = bond.terms_for(Ledger.build(self.events, self.config), self.job_id(job_event),
                               signer.pubkey, bkey.pubkey)
        txid = txid or os.urandom(32).hex()
        if chain is not None:
            chain.add(txid, terms, amount if sats is None else sats,
                      blocktime=job_event["created_at"] + 600 if blocktime is None else blocktime)
        return self.vouch(signer, job_event, amount, at, bond=txid, bondkey=bkey.pubkey), bkey, txid

    def clear(self, signer, vouch_event, at=T0 + 8 * DAY):
        return self.emit(signer, ev.VOUCH_CLEARED, [
            ["job", self.job_id(vouch_event)], ["e", vouch_event["id"]]], at)

    def onboard(self, key, recovery_key, at=T0 - DAY):
        return self.emit(key, ev.ONBOARD, [["recovery", ev.recovery_commitment(recovery_key.pubkey)]], at)

    def rotate(self, signer, onboard_event, new, at):
        return self.emit(signer, ev.ROTATE, [["op", onboard_event["id"]], ["p", new.pubkey, "new"]], at)

    def recover(self, recovery_key, onboard_event, new, since, at):
        return self.emit(recovery_key, ev.RECOVER, [
            ["op", onboard_event["id"]], ["p", new.pubkey, "new"], ["since", str(since)]], at)

    def delegate(self, signer, onboard_event, agent, scope, at, expires=None):
        tags = [["op", onboard_event["id"]], ["p", agent.pubkey, "agent"], ["scope", scope]]
        if expires is not None:
            tags.append(["expires", str(expires)])
        return self.emit(signer, ev.DELEGATE, tags, at)

    def revoke_agent(self, signer, onboard_event, agent, at):
        return self.emit(signer, ev.AGENT_REVOKE, [["op", onboard_event["id"]], ["p", agent.pubkey, "agent"]], at)

    @staticmethod
    def _worker_of(job_event):
        return next(t[1] for t in job_event["tags"] if t[0] == "p" and t[2] == "worker")


class FakeChain:
    """Offline stand-in for the chain questions bond checks ask (see sandbox.SandboxChain)."""

    def __init__(self, height=1_000):
        self.txs, self.spent, self.spenders, self.height = {}, set(), {}, height

    def spend(self, txid, terms, path):
        """Mark the bond spent by a reclaim (voucher alone, after T) or a 2-of-3 forfeit."""
        if path == "reclaim":
            witness = ["11" * 64, terms.reclaim_script.hex(), "c0"]
            seq = terms.timelock_blocks
        else:
            witness = ["22" * 64, "", "33" * 64, terms.multisig_script.hex(), "c0"]
            seq = 0xFFFFFFFD
        self.spent.add((txid, 0))
        self.spenders[(txid, 0)] = {"txid": "ee" * 32, "vin": [
            {"txid": txid, "vout": 0, "sequence": seq, "txinwitness": witness}]}

    def spending_tx(self, txid, vout):
        return self.spenders.get((txid, vout))

    def add(self, txid, terms, sats, blocktime, confirmations=6):
        self.txs[txid] = {"txid": txid, "confirmations": confirmations, "blocktime": blocktime,
                          "vout": [{"n": 0, "value": sats / 100_000_000,
                                    "scriptPubKey": {"hex": terms.script_pubkey.hex()}}]}

    def get_tx(self, txid):
        return self.txs.get(txid)

    def utxo(self, txid, vout):
        return None if (txid, vout) in self.spent or txid not in self.txs else {"vout": vout}

    def tip(self):
        return {"height": self.height, "hash": "00" * 32}


@pytest.fixture
def world():
    return World()


@pytest.fixture
def chain():
    return FakeChain()
