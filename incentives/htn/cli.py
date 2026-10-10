"""Command-line tool: `python -m htn <command>`. Run `python -m htn -h` for help."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import events as ev
from . import bond, fees, keys, payments, sandbox, scoring, timestamps
from .config import load_config
from .ledger import Ledger
from .store import Store

REPO = Path(__file__).resolve().parent.parent


class CliError(Exception):
    pass


class Ctx:
    def __init__(self, args):
        self.config = load_config(args.config)
        self.store = Store(Path(args.home))
        self.keys_dir = Path(args.keys_dir)

    def key(self, name: str) -> keys.Key:
        return keys.load(name, self.keys_dir)

    def pub(self, name_or_hex: str) -> str:
        return keys.resolve_pubkey(name_or_hex, self.keys_dir)

    def ledger(self) -> Ledger:
        return Ledger.build(self.store.load_events(), self.config)

    def calendars(self, public: bool):
        if public or self.config.timestamp_mode == "public":
            return timestamps.public_calendars()
        return [timestamps.LocalTestCalendar()]

    def commit_file(self, job_id: str, label: str, path: str) -> str:
        """Hash a private file locally (salted). Only the hash leaves this machine."""
        h, salt = ev.commit(Path(path).read_bytes())
        self.store.save_salt(job_id, label, h, salt)
        return h

    def publish(self, key: keys.Key, kind: int, tags: list, at: int | None, public=False) -> dict:
        event = ev.sign_event(key, kind, tags, at if at is not None else int(time.time()))
        led = Ledger.build(self.store.load_events() + [event], self.config)
        if event["id"] in led.rejected:
            raise CliError(f"refused: {led.rejected[event['id']]}")
        self.store.save_event(event)
        print(f"{ev.KIND_NAMES[kind]} event {event['id']}")
        try:
            dtf = timestamps.stamp(event["id"], self.calendars(public))
            self.store.save_proof(event["id"], timestamps.to_bytes(dtf))
        except timestamps.TimestampError as e:
            print(f"warning: event saved but not timestamped ({e}); retry with `stamp`")
        return event


def _job(ctx: Ctx, job_id: str):
    job = ctx.ledger().jobs.get(job_id)
    if job is None:
        raise CliError(f"unknown job {job_id}")
    return job


# -- commands ---------------------------------------------------------------

def cmd_keygen(ctx, a):
    key = keys.generate(a.name)
    path = keys.save(key, ctx.keys_dir)
    print(f"{key.name} {key.pubkey}\nsaved to {path} (keep this folder private)")


def cmd_recovery_keygen(ctx, a):
    """Make a recovery key in its own folder, away from the everyday keys."""
    out = Path(a.out)
    if out.resolve() == ctx.keys_dir.resolve():
        raise CliError("recovery keys must not live in the everyday keys folder")
    key = keys.generate(a.name)
    path = keys.save(key, out, role="recovery")
    print(f"recovery public key {key.pubkey}\nsaved to {path}\n"
          f"Onboard with:  onboard --as <your key> --recovery-pub {key.pubkey}\n"
          "Then move the file OFFLINE (USB stick / paper). It is only needed to recover.")


def cmd_keys(ctx, a):
    for k in keys.list_keys(ctx.keys_dir):
        print(f"{k.name:16} {k.pubkey}")


def cmd_job_offer(ctx, a):
    # Job ID = hash(nonce + agreed terms). Keep the nonce (saved privately) and
    # share it only with the other parties so they can check the job ID.
    job_id, nonce = ev.make_job_id(Path(a.terms_file).read_bytes())
    ctx.store.save_salt(job_id, "job_id_nonce", job_id, nonce)
    tags = [["job", job_id], ["p", ctx.pub(a.worker), "worker"]]
    if a.recipient:
        tags.append(["p", ctx.pub(a.recipient), "recipient"])
    ctx.publish(ctx.key(a.signer), ev.JOB_OFFER, tags, a.at)
    print(f"job id {job_id}")


def cmd_accept(ctx, a):
    job = _job(ctx, a.job)
    ctx.publish(ctx.key(a.signer), ev.JOB_ACCEPTED, [["job", job.job_id], ["e", job.event_id]], a.at)


def cmd_handoff(ctx, a):
    job = _job(ctx, a.job)
    tags = [["job", job.job_id], ["e", job.event_id], ["p", ctx.pub(a.to), "to"],
            ["item", ctx.commit_file(job.job_id, "item", a.item_file)],
            ["seq", str(job.handoffs + 1)]]
    ctx.publish(ctx.key(a.signer), ev.HANDOFF, tags, a.at)


def cmd_complete(ctx, a):
    job = _job(ctx, a.job)
    tags = [["job", job.job_id], ["e", job.event_id], ["p", job.worker, "worker"],
            ["receipt", ctx.commit_file(job.job_id, "receipt", a.receipt_file)]]
    ctx.publish(ctx.key(a.signer), ev.COMPLETION, tags, a.at)


def cmd_dispute_file(ctx, a):
    job = _job(ctx, a.job)
    tags = [["job", job.job_id], ["e", job.event_id], ["p", job.worker, "worker"],
            ["reason", ctx.commit_file(job.job_id, "reason", a.reason_file)]]
    ctx.publish(ctx.key(a.signer), ev.DISPUTE_FILED, tags, a.at)


def cmd_dispute_resolve(ctx, a):
    d = ctx.ledger().disputes.get(a.dispute)
    if d is None:
        raise CliError(f"unknown dispute {a.dispute}")
    tags = [["job", d.job_id], ["e", d.event_id], ["outcome", a.outcome]]
    if a.ruling_file:
        tags.append(["ruling", ctx.commit_file(d.job_id, "ruling", a.ruling_file)])
    ctx.publish(ctx.key(a.signer), ev.DISPUTE_RESOLVED, tags, a.at)


def cmd_vouch_issue(ctx, a):
    job = _job(ctx, a.job)
    tags = [["job", job.job_id], ["e", job.event_id], ["p", job.worker, "worker"],
            ["amount", str(a.amount)]]
    if a.bond:
        _, rec = _private(ctx, "bonds", job.job_id)
        if rec is None or rec["txid"] != a.bond:
            raise CliError("no bond with that txid funded here for this job (run bond-fund)")
        tags += [["bond", a.bond], ["bondkey", rec["bond_key"]]]
    ctx.publish(ctx.key(a.signer), ev.VOUCH_ISSUED, tags, a.at)


def cmd_vouch_clear(ctx, a):
    v = ctx.ledger().vouches.get(a.vouch)
    if v is None:
        raise CliError(f"unknown vouch {a.vouch}")
    ctx.publish(ctx.key(a.signer), ev.VOUCH_CLEARED, [["job", v.job_id], ["e", v.event_id]], a.at)


def cmd_onboard(ctx, a):
    """Commits to the recovery PUBLIC key only; the recovery secret is never read."""
    pub = a.recovery_pub.lower()
    if not keys._HEX64.match(pub):
        raise CliError("--recovery-pub must be the 64-hex public key printed by recovery-keygen")
    signer = ctx.key(a.signer)
    if pub == signer.pubkey:
        raise CliError("the recovery key must differ from the operational key")
    event = ctx.publish(signer, ev.ONBOARD, [["recovery", ev.recovery_commitment(pub)]], a.at)
    print(f"operator id {event['id']}\n"
          "Keep the recovery key OFFLINE; it is only needed to recover.")


def _operator_for(ctx, a, signer_pub: str, by_recovery=False):
    reg = ctx.ledger().registry
    if a.operator:
        return a.operator
    for op in reg.operators.values():
        if by_recovery and op.recovery_commitment == ev.recovery_commitment(signer_pub):
            return op.op_id
        if not by_recovery and signer_pub in (k for k, _, _ in op.history):
            return op.op_id
    raise CliError("could not find the operator; pass --operator")


def cmd_rotate(ctx, a):
    key = ctx.key(a.signer)
    op = _operator_for(ctx, a, key.pubkey)
    ctx.publish(key, ev.ROTATE, [["op", op], ["p", ctx.pub(a.new), "new"]], a.at)


def cmd_recover(ctx, a):
    key = keys.load_file(Path(a.recovery_file), role="recovery")
    op = _operator_for(ctx, a, key.pubkey, by_recovery=True)
    at = a.at if a.at is not None else int(time.time())
    since = a.since if a.since is not None else at
    tags = [["op", op]]
    if a.new:
        tags.append(["p", ctx.pub(a.new), "new"])
    tags.append(["since", str(since)])
    ctx.publish(key, ev.RECOVER, tags, at)


def cmd_delegate(ctx, a):
    key = ctx.key(a.signer)
    op = _operator_for(ctx, a, key.pubkey)
    tags = [["op", op], ["p", ctx.pub(a.agent), "agent"], ["scope", a.scope]]
    if a.expires is not None:
        tags.append(["expires", str(a.expires)])
    ctx.publish(key, ev.DELEGATE, tags, a.at)


def cmd_revoke_agent(ctx, a):
    if bool(a.signer) == bool(a.recovery_file):
        raise CliError("sign with either --as (operational key) or --recovery-file")
    key = (keys.load_file(Path(a.recovery_file), role="recovery") if a.recovery_file
           else ctx.key(a.signer))
    agent = ctx.pub(a.agent)
    reg = ctx.ledger().registry
    op = a.operator or (reg.agents[agent].op_id if agent in reg.agents else None)
    if op is None:
        raise CliError("not a known agent key")
    ctx.publish(key, ev.AGENT_REVOKE, [["op", op], ["p", agent, "agent"]], a.at)


def cmd_identity(ctx, a):
    reg = ctx.ledger().registry
    ident = a.who if a.who in reg.operators else reg.identity(ctx.pub(a.who))
    op = reg.operators.get(ident)
    if op is None:
        print(f"{ident} has not onboarded (no recovery key on record)")
        return
    print(f"operator {op.op_id}\ncurrent key {op.current}")
    for key, start, end in op.history:
        if key in reg.compromised:
            status = f"COMPROMISED since {reg.compromised[key]}"
        elif end is not None:
            status = f"retired {end}"
        else:
            status = "current"
        print(f"  {key}  from {start}  {status}")
    for ag in (x for x in reg.agents.values() if x.op_id == op.op_id):
        scope = ",".join(sorted(ev.KIND_NAMES[k] for k in ag.scope))
        state = ("VOID (delegated by compromised key)" if ag.overridden
                 else f"revoked {ag.revoked_at}" if ag.revoked_at is not None else "active")
        print(f"  agent {ag.key}  scope {scope}  {state}")


def cmd_stamp(ctx, a):
    event = ctx.store.get_event(a.event_id)
    dtf = timestamps.stamp(event["id"], ctx.calendars(a.public))
    print(f"proof saved to {ctx.store.save_proof(event['id'], timestamps.to_bytes(dtf))}")


def cmd_stamp_file(ctx, a):
    path = Path(a.path)
    dtf = timestamps.stamp_digest(timestamps.file_digest(path.read_bytes()), ctx.calendars(a.public))
    proof = path.with_name(path.name + ".ots")
    proof.write_bytes(timestamps.to_bytes(dtf))
    print(f"sha256 {timestamps.file_digest(path.read_bytes()).hex()}")
    print(f"proof saved to {proof}")


def cmd_verify_file(ctx, a):
    path = Path(a.path)
    proof = path.with_name(path.name + ".ots")
    if not proof.exists():
        raise CliError(f"no proof at {proof}; run `stamp-file` first")
    report = timestamps.verify_file(path.read_bytes(), timestamps.from_bytes(proof.read_bytes()))
    print(json.dumps(report, indent=2))
    return 0 if report["status"] != "invalid" else 1


def cmd_upgrade_file(ctx, a):
    proof = Path(a.path + ".ots")
    dtf = timestamps.from_bytes(proof.read_bytes())
    n = timestamps.upgrade(dtf, timestamps.default_calendar_for_uri)
    proof.write_bytes(timestamps.to_bytes(dtf))
    print(f"upgraded {n} pending attestation(s)")


def cmd_upgrade(ctx, a):
    path = ctx.store.proof_path(a.event_id)
    dtf = timestamps.from_bytes(path.read_bytes())
    n = timestamps.upgrade(dtf, timestamps.default_calendar_for_uri)
    ctx.store.save_proof(a.event_id, timestamps.to_bytes(dtf))
    print(f"upgraded {n} pending attestation(s)")


def cmd_verify(ctx, a):
    event = ctx.store.get_event(a.event_id)
    path = ctx.store.proof_path(a.event_id)
    if not path.exists():
        raise CliError("no timestamp proof for this event; run `stamp`")
    report = timestamps.verify(event, timestamps.from_bytes(path.read_bytes()))
    print(json.dumps(report, indent=2))
    return 0 if report["status"] != "invalid" else 1


def cmd_verify_job(ctx, a):
    from .chain import job_chain

    def proof_status(event):
        path = ctx.store.proof_path(event["id"])
        if not path.exists():
            return "missing"
        return timestamps.verify(event, timestamps.from_bytes(path.read_bytes()))["status"]

    report = job_chain(ctx.store.load_events(), ctx.config, a.job, proof_status)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


def cmd_check(ctx, a):
    led = ctx.ledger()
    events = {e["id"]: e for e in ctx.store.load_events()}
    for eid in led.accepted:
        print(f"ok        {ev.KIND_NAMES[events[eid]['kind']]:17} {eid}")
    for eid, why in sorted(led.rejected.items()):
        label = "DISPUTABLE" if why.startswith("disputable") else "REJECTED  "
        print(f"{label} {eid}  {why}")
    return 0 if not led.rejected and not led.malformed else 1


def cmd_score(ctx, a):
    as_of = a.as_of if a.as_of is not None else int(time.time())
    chain = None
    if a.check_bonds:
        from .sandbox import SandboxChain
        chain = SandboxChain()
    result = scoring.score_all(ctx.store.load_events(), ctx.config, as_of, chain)
    if a.who:
        led = ctx.ledger()
        ident = a.who if a.who in led.registry.operators else led.ident(ctx.pub(a.who))
        result["operators"] = {ident: scoring.operator_record(led, ident, as_of, result["bond_checks"])}
    print(json.dumps(result, indent=2, sort_keys=True))


def _private(ctx, kind: str, job_id: str):
    path = ctx.store.private_dir / kind / f"{job_id}.json"
    return path, (json.loads(path.read_text()) if path.exists() else None)


def _save_private(ctx, kind: str, job_id: str, data: dict) -> Path:
    path, _ = _private(ctx, kind, job_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    return path


def cmd_pay_secret(ctx, a):
    from . import payments
    job = _job(ctx, a.job)
    secret, h = payments.new_payment_secret()
    _save_private(ctx, "payment_secrets", job.job_id, {"secret": secret, "payment_hash": h})
    print(f"payment hash {h}")
    print("(give this hash to the worker; the secret stays in data/private)")


def cmd_invoice(ctx, a):
    from . import payments
    job = _job(ctx, a.job)
    node = payments.LndNode("worker")
    inv = payments.create_hold_invoice(node, ctx.config, job.job_id, a.hash, a.amount, a.expected_minutes * 60)
    _save_private(ctx, "invoices", job.job_id, inv.__dict__)
    print(f"hold invoice for {a.amount} sats (split {payments.fee_split(a.amount, ctx.config)})")
    print(f"payment request {inv.payment_request}")


def cmd_pay(ctx, a):
    from . import payments
    payments.LndNode("client").pay_in_background(a.invoice)
    print("payment sent; it stays HELD until the worker settles with the recipient's receipt")


def cmd_receipt(ctx, a):
    from . import payments
    job = _job(ctx, a.job)
    _, sec = _private(ctx, "payment_secrets", job.job_id)
    if sec is None:
        raise CliError("no payment secret for this job here; run pay-secret first (as the recipient)")
    key = ctx.key(a.signer)
    at = a.at if a.at is not None else int(time.time())
    receipt = payments.sign_receipt(key, job.job_id, sec["payment_hash"], sec["secret"], at)
    path = _save_private(ctx, "receipts", job.job_id, receipt)
    tags = [["job", job.job_id], ["e", job.event_id], ["p", job.worker, "worker"],
            ["receipt", ev.commit(json.dumps(receipt, sort_keys=True).encode())[0]],
            ["payment", sec["payment_hash"]]]
    ctx.publish(key, ev.COMPLETION, tags, at)
    print(f"PRIVATE receipt saved to {path}; hand it to the worker (never publish it)")


def cmd_settle(ctx, a):
    from . import payments
    job = _job(ctx, a.job)
    _, inv = _private(ctx, "invoices", job.job_id)
    if inv is None:
        raise CliError("no invoice for this job here")
    receipt = json.loads(Path(a.receipt).read_text())
    allowed = {k for k in (job.client, job.recipient) if k}
    payments.settle_with_receipt(payments.LndNode("worker"), payments.HoldInvoice(**inv), receipt, allowed)
    print("settled: payment released to the worker")
    new = fees.accrue(ctx.ledger(), job.job_id, inv["amount_sats"], ctx.config)
    _save_fees(ctx, fees.merge(_load_fees(ctx), new))
    for s in new:
        print(f"fee share owed: {s.kind} {s.sats} sats (id {s.id})")


def _fees_path(ctx) -> Path:
    return ctx.store.private_dir / "fees.json"


def _load_fees(ctx) -> list:
    path = _fees_path(ctx)
    return [fees.Share(**d) for d in json.loads(path.read_text())] if path.exists() else []


def _save_fees(ctx, shares: list) -> None:
    path = _fees_path(ctx)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([s.to_dict() for s in shares], indent=2))


def _now(a) -> int:
    return a.at if a.at is not None else int(time.time())


def cmd_fees(ctx, a):
    led, now = ctx.ledger(), _now(a)
    print(f"fee payout mode: {ctx.config.fee_payout}")
    for s in _load_fees(ctx):
        st = fees.status(s, led, now)
        print(f"{s.id}  {s.kind:8} {s.sats:>8} sats  job {s.job_id[:12]}...  "
              f"{'DUE to ' + st['payee'] if st['due'] else st['why']}")


def cmd_fees_pay(ctx, a):
    """Worker pays one due share as a Lightning payment to the payee's invoice."""
    shares, led = _load_fees(ctx), ctx.ledger()
    share = next((s for s in shares if s.id == a.share), None)
    if share is None:
        raise CliError(f"unknown fee share {a.share}")
    node = payments.LndNode("worker")
    payee = fees.check_payable(share, led, ctx.config, _now(a), node.invoice_sats(a.invoice))
    share.paid_ref, share.status = node.pay_now(a.invoice), "paid"
    _save_fees(ctx, shares)
    print(f"paid {share.sats} sats to the {payee} (payment hash {share.paid_ref})")


def cmd_fees_sweep(ctx, a):
    """Send all due network shares in one on-chain payment to the configured address."""
    shares, led = _load_fees(ctx), ctx.ledger()
    due = fees.sweepable(shares, led, ctx.config, _now(a))
    if not due:
        print("nothing to sweep")
        return
    total = sum(s.sats for s in due)
    txid = payments.LndNode("worker").send_onchain(ctx.config.fee_sweep_address, total)
    for s in due:
        s.status, s.paid_ref = "swept", txid
    _save_fees(ctx, shares)
    print(f"swept {total} sats ({len(due)} shares) to {ctx.config.fee_sweep_address}: txid {txid}")


def cmd_hold_check(ctx, a):
    """Cancel (refund) any held payment older than max_hold_seconds."""
    from . import payments
    node = payments.LndNode("worker")
    folder = ctx.store.private_dir / "invoices"
    now = int(time.time())
    for p in sorted(folder.glob("*.json")) if folder.exists() else []:
        inv = payments.HoldInvoice(**json.loads(p.read_text()))
        state = node.state(inv.payment_hash)
        since = node.held_since(inv.payment_hash) if state == "ACCEPTED" else None
        cancelled = since is not None and payments.enforce_max_hold(node, inv, since, now, ctx.config)
        print(f"{inv.job_id[:16]}...  {'CANCELED (client refunded)' if cancelled else state}")


def cmd_bond_fund(ctx, a):
    """Make a fresh bond key, build the bond address, fund it from the sandbox wallet."""
    from . import bond, sandbox
    job = _job(ctx, a.job)
    if not ctx.config.bond_min_sats <= a.amount <= ctx.config.bond_max_sats:
        raise CliError("bond amount outside the configured min/max")
    bond_key = keys.new_bond_key(ctx.keys_dir)
    terms = bond.terms_for(ctx.ledger(), job.job_id, ctx.key(a.signer).pubkey, bond_key.pubkey)
    txid = sandbox.fund_address(terms.address(ctx.config), a.amount)
    _save_private(ctx, "bonds", job.job_id, {"txid": txid, "bond_key": bond_key.pubkey,
                                             "address": terms.address(ctx.config)})
    print(f"bond funded: {a.amount} sats, txid {txid}")
    print(f"bond key {bond_key.pubkey} (fresh; saved in {ctx.keys_dir / 'bonds'})")
    print(f"next: vouch-issue --as {a.signer} --job {job.job_id} --amount {a.amount} --bond {txid}")


def cmd_bond_check(ctx, a):
    from . import bond, sandbox
    report = bond.check_bond(ctx.ledger(), a.vouch, sandbox.SandboxChain())
    print(json.dumps(report, indent=2))
    return 0 if report["live"] else 1


def _bond_spend(ctx, vouch_id: str, path: str, to: str):
    from . import bond, sandbox
    led = ctx.ledger()
    terms = bond.terms_for_vouch(led, vouch_id)
    txid = led.vouches[vouch_id].bond
    if not txid:
        raise CliError("this vouch names no bond")
    vout, sats = bond.find_output(sandbox.get_tx(txid), terms)
    make = bond.forfeit_to_client if path == "multisig" else bond.reclaim
    return led, make(terms, txid, vout, sats, to, ctx.config)


def _finish(spend, broadcast: bool):
    from . import sandbox
    raw = spend.finalize()
    if broadcast:
        print(f"broadcast: txid {sandbox.broadcast(raw)}")
    else:
        print(f"signed transaction (not broadcast): {raw}")


def cmd_bond_forfeit(ctx, a):
    """Client starts the forfeit: chooses where the sats go and signs first."""
    led, spend = _bond_spend(ctx, a.vouch, "multisig", a.to)
    if led.vouches[a.vouch].status != "forfeited":
        raise CliError(f"vouch is {led.vouches[a.vouch].status}; only a forfeited vouch can be claimed")
    spend.sign(ctx.key(a.signer))
    path = _save_private(ctx, "bond_spends", a.vouch, spend.to_dict())
    print(f"client signature added; send {path} to the arbiter (bond-arbiter-sign)")


def cmd_bond_arbiter_sign(ctx, a):
    from . import bond
    from .bond import Spend
    _, data = _private(ctx, "bond_spends", a.vouch)
    if data is None:
        raise CliError("no client-signed forfeit for this vouch here (bond-forfeit first)")
    spend = Spend.from_dict(data)
    bond.arbiter_sign_forfeit(ctx.ledger(), a.vouch, spend, ctx.key(a.signer))
    _finish(spend, a.broadcast)


def cmd_bond_reclaim(ctx, a):
    """Voucher alone (with the bond's own key), once the bond is T blocks old."""
    _, spend = _bond_spend(ctx, a.vouch, "reclaim", a.to)
    spend.sign(keys.load_bond_key(spend.terms.voucher, ctx.keys_dir))
    _finish(spend, a.broadcast)


def cmd_sandbox(ctx, a):
    from . import sandbox
    try:
        if a.action == "up":
            print("starting regtest bitcoind + 2 LND nodes (first run takes a minute)...")
            print(json.dumps(sandbox.up(), indent=2))
        elif a.action == "status":
            print(json.dumps(sandbox.status(), indent=2))
        elif a.action == "mine":
            print(f"block height {sandbox.mine(a.blocks)}")
        elif a.action == "down":
            sandbox.down()
            print("sandbox stopped")
        elif a.action == "reset":
            sandbox.reset()
            print("sandbox data deleted")
    except sandbox.SandboxError as e:
        raise CliError(str(e))


# -- parser -----------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="htn", description="Human Trust Network prototype (test networks only)")
    p.add_argument("--home", default=os.environ.get("HTN_HOME", str(REPO / "data")),
                   help="local data folder (default ./data)")
    p.add_argument("--keys-dir", default=os.environ.get("HTN_KEYS", str(REPO / ".keys")),
                   help="private key folder (default ./.keys)")
    p.add_argument("--config", default=os.environ.get("HTN_CONFIG"), help="config file (default ./config.toml)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, func, help_, signer=False, at=False):
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(func=func)
        if signer:
            sp.add_argument("--as", dest="signer", required=True, help="name of your local key")
        if at:
            sp.add_argument("--at", type=int, help="event time (unix seconds); default now")
        return sp

    add("keygen", cmd_keygen, "create a new key").add_argument("name")
    add("keys", cmd_keys, "list local keys")
    sp = add("recovery-keygen", cmd_recovery_keygen, "create a recovery key in a separate folder")
    sp.add_argument("name")
    sp.add_argument("--out", default=os.environ.get("HTN_RECOVERY", str(REPO / ".recovery")),
                    help="folder for the recovery key (default ./.recovery; move it offline)")

    sp = add("job-offer", cmd_job_offer, "client offers a job to a worker", True, True)
    sp.add_argument("--worker", required=True)
    sp.add_argument("--recipient")
    sp.add_argument("--terms-file", required=True,
                    help="private agreed-terms file; the job ID is its hash with a secret nonce")

    sp = add("accept", cmd_accept, "worker accepts an offered job", True, True)
    sp.add_argument("--job", required=True)

    sp = add("handoff", cmd_handoff, "current holder hands the item to the next party", True, True)
    sp.add_argument("--job", required=True)
    sp.add_argument("--to", required=True)
    sp.add_argument("--item-file", required=True)

    sp = add("complete", cmd_complete, "client/recipient confirms completion", True, True)
    sp.add_argument("--job", required=True)
    sp.add_argument("--receipt-file", required=True)

    sp = add("dispute-file", cmd_dispute_file, "client/recipient files a dispute", True, True)
    sp.add_argument("--job", required=True)
    sp.add_argument("--reason-file", required=True)

    sp = add("dispute-resolve", cmd_dispute_resolve, "arbiter resolves (or filer withdraws) a dispute", True, True)
    sp.add_argument("--dispute", required=True, help="dispute event id")
    sp.add_argument("--outcome", required=True, choices=["upheld", "rejected", "withdrawn"])
    sp.add_argument("--ruling-file")

    sp = add("vouch-issue", cmd_vouch_issue, "voucher vouches for a job", True, True)
    sp.add_argument("--job", required=True)
    sp.add_argument("--amount", type=int, required=True, help="bond size in sats")
    sp.add_argument("--bond", help="txid of the funded bond (see bond-fund); its bond key is added")

    sp = add("vouch-clear", cmd_vouch_clear, "voucher clears a vouch after the dispute window", True, True)
    sp.add_argument("--vouch", required=True, help="vouch event id")

    sp = add("onboard", cmd_onboard, "operator publishes a commitment to their recovery key", True, True)
    sp.add_argument("--recovery-pub", required=True, help="recovery PUBLIC key (from recovery-keygen)")

    sp = add("rotate", cmd_rotate, "current key hands over to a new key", True, True)
    sp.add_argument("--new", required=True)
    sp.add_argument("--operator", help="operator id (found automatically if omitted)")

    sp = add("recover", cmd_recover, "recovery key takes control back (offline step)", False, True)
    sp.add_argument("--recovery-file", required=True, help="path to the recovery key file")
    sp.add_argument("--new", help="replacement operational key (omit to revoke only)")
    sp.add_argument("--since", type=int, help="compromised since (unix seconds); default now")
    sp.add_argument("--operator", help="operator id (found automatically if omitted)")

    sp = add("delegate", cmd_delegate, "operator gives an agent key a limited scope", True, True)
    sp.add_argument("--agent", required=True)
    sp.add_argument("--scope", required=True, help="comma-separated record kinds, e.g. job_accepted,handoff")
    sp.add_argument("--expires", type=int, help="unix seconds")
    sp.add_argument("--operator", help="operator id (found automatically if omitted)")

    sp = add("revoke-agent", cmd_revoke_agent, "operator or recovery key revokes an agent key", False, True)
    sp.add_argument("--as", dest="signer", help="operational key name")
    sp.add_argument("--recovery-file", help="or: path to the recovery key file")
    sp.add_argument("--agent", required=True)
    sp.add_argument("--operator", help="operator id (found automatically if omitted)")

    add("identity", cmd_identity, "show an operator's key history").add_argument("who")

    sp = add("stamp", cmd_stamp, "(re)timestamp an event")
    sp.add_argument("event_id")
    sp.add_argument("--public", action="store_true", help="use public OpenTimestamps calendars (sends the hash only)")

    sp = add("stamp-file", cmd_stamp_file, "timestamp a document (proof saved next to it as <file>.ots)")
    sp.add_argument("path")
    sp.add_argument("--public", action="store_true", help="use public OpenTimestamps calendars (sends the hash only)")
    add("verify-file", cmd_verify_file, "check a document against its .ots proof").add_argument("path")
    add("upgrade-file", cmd_upgrade_file, "fetch the completed proof for a document").add_argument("path")

    add("upgrade", cmd_upgrade, "fetch completed proofs from calendars").add_argument("event_id")
    add("verify", cmd_verify, "verify an event's signature and timestamp proof").add_argument("event_id")
    sp = add("pay-secret", cmd_pay_secret, "recipient makes the payment secret; prints its hash")
    sp.add_argument("--job", required=True)
    sp = add("invoice", cmd_invoice, "worker creates a hold invoice (sandbox worker node)")
    sp.add_argument("--job", required=True)
    sp.add_argument("--hash", required=True, help="payment hash from the recipient")
    sp.add_argument("--amount", type=int, required=True, help="sats")
    sp.add_argument("--expected-minutes", type=int, required=True, help="expected job duration")
    add("pay", cmd_pay, "client pays a hold invoice (sandbox client node)").add_argument("invoice")
    sp = add("receipt", cmd_receipt, "recipient signs the private receipt + publishes completion", True, True)
    sp.add_argument("--job", required=True)
    sp = add("settle", cmd_settle, "worker settles using the recipient's receipt")
    sp.add_argument("--job", required=True)
    sp.add_argument("--receipt", required=True, help="receipt file from the recipient")
    add("hold-check", cmd_hold_check, "cancel and refund payments held past the limit")
    add("fees", cmd_fees, "list fee shares the worker owes and whether they are due", at=True)
    sp = add("fees-pay", cmd_fees_pay, "worker pays a due fee share by Lightning", at=True)
    sp.add_argument("share", help="share id (see fees)")
    sp.add_argument("--invoice", required=True, help="the payee's Lightning invoice for exactly that amount")
    add("fees-sweep", cmd_fees_sweep, "sweep due network shares on-chain (payout = sweep)", at=True)

    sp = add("bond-fund", cmd_bond_fund, "voucher: fund the bond from the sandbox wallet", True)
    sp.add_argument("--job", required=True)
    sp.add_argument("--amount", type=int, required=True, help="sats")
    add("bond-check", cmd_bond_check, "anyone: check a vouch's bond on chain").add_argument("vouch")
    sp = add("bond-forfeit", cmd_bond_forfeit, "client: claim a forfeited bond (signs first)", True)
    sp.add_argument("--vouch", required=True)
    sp.add_argument("--to", required=True, help="client's regtest address")
    sp = add("bond-arbiter-sign", cmd_bond_arbiter_sign, "arbiter: co-sign a forfeit that pays the client", True)
    sp.add_argument("--vouch", required=True)
    sp.add_argument("--broadcast", action="store_true")
    sp = add("bond-reclaim", cmd_bond_reclaim, "voucher: take the bond back after T blocks (uses the bond key)")
    sp.add_argument("--vouch", required=True)
    sp.add_argument("--to", required=True, help="voucher's regtest address")
    sp.add_argument("--broadcast", action="store_true")

    sp = add("sandbox", cmd_sandbox, "local regtest Lightning sandbox (worthless test coins)")
    sp.add_argument("action", choices=["up", "status", "mine", "down", "reset"])
    sp.add_argument("blocks", nargs="?", type=int, default=1, help="for mine: how many blocks")

    add("check", cmd_check, "validate every stored event against the rules")
    add("verify-job", cmd_verify_job, "rebuild and check one job's full event chain").add_argument("job")
    sp = add("score", cmd_score, "compute scores from the stored public events")
    sp.add_argument("who", nargs="?")
    sp.add_argument("--as-of", type=int, help="reference time (unix seconds); default now. Printed in the output.")
    sp.add_argument("--check-bonds", action="store_true",
                    help="check vouch bonds on the sandbox chain (without it, vouches carry no weight)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(Ctx(args), args) or 0
    except (CliError, payments.PaymentError, bond.BondError, sandbox.SandboxError, fees.FeeError,
            keys.KeyNotFound, FileNotFoundError, FileExistsError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
