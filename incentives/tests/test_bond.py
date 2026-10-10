"""Phase 4 (updated brief): the Taproot vouch bond and dispute flow.

Offline tests check the rules and the arbiter's signing policy; the `live_*`
tests put real (regtest) bonds on chain and let Bitcoin Core judge every spend.
Every bond uses its own fresh key (DECISIONS #39), never the voucher's
operational key.
"""
import pytest

from conftest import T0
from htn import bond, keys
from htn import sandbox as sb
from htn.ledger import Ledger

AMOUNT = 50_000
FAKE_TXID = "aa" * 32
CLIENT_ADDR = bond.encode_address("bcrt", 1, bytes(range(32)))


def build(world):
    return Ledger.build(world.events, world.config)


def forfeited_world(world, voucher=None):
    """Job + bonded vouch + dispute upheld by the acting arbiter.
    Returns (job, vouch, arbiter key, bond key, ledger)."""
    voucher = voucher or world.voucher
    job = world.job()
    vouch, bkey, _ = world.bonded_vouch(voucher, job, amount=AMOUNT, txid=FAKE_TXID)
    arbiter = world.founder if build(world).vouches[vouch["id"]].arbiter == world.founder.pubkey else world.backup
    world.resolve(arbiter, world.dispute(world.client, job), "upheld")
    return job, vouch, arbiter, bkey, build(world)


def forfeit_spend(world, led, vouch, dest=CLIENT_ADDR):
    return bond.forfeit_to_client(bond.terms_for_vouch(led, vouch["id"]), FAKE_TXID, 0, AMOUNT,
                                  dest, world.config)


# -- the output ---------------------------------------------------------------

def test_terms_and_address(world):
    job = world.job()
    bkey = keys.generate("b")
    t = bond.terms_for(build(world), world.job_id(job), world.voucher.pubkey, bkey.pubkey)
    assert (t.client, t.voucher, t.arbiter) == (world.client.pubkey, bkey.pubkey, world.founder.pubkey)
    assert t.timelock_blocks == world.config.bond_timelock_blocks == 2016
    addr = t.address(world.config)
    assert addr.startswith("bcrt1p")
    assert bond.address_to_script(addr, world.config) == t.script_pubkey


def test_recusal_founder_vouching_puts_backup_in_the_script(world):
    job = world.job()
    t = bond.terms_for(build(world), world.job_id(job), world.founder.pubkey, keys.generate("b").pubkey)
    assert t.arbiter == world.backup.pubkey


def test_recusal_founder_as_client(world):
    job = world.job(client=world.founder)
    t = bond.terms_for(build(world), world.job_id(job), world.voucher.pubkey, keys.generate("b").pubkey)
    assert t.arbiter == world.backup.pubkey


def test_no_eligible_arbiter(world):
    job = world.job(client=world.founder, recipient=world.backup)
    with pytest.raises(bond.BondError, match="arbiter"):
        bond.terms_for(build(world), world.job_id(job), world.voucher.pubkey, keys.generate("b").pubkey)
    world.vouch(world.voucher, job)
    assert "no eligible arbiter" in str(build(world).rejected)


def test_keys_must_differ(world):
    with pytest.raises(bond.BondError):
        bond.BondTerms(world.client.pubkey, world.client.pubkey, world.founder.pubkey, 2016)


def test_mainnet_and_bad_addresses_refused(world):
    mainnet = bond.encode_address("b" + "c", 1, bytes(32))  # built at runtime; never stored
    broken = CLIENT_ADDR[:-1] + ("q" if CLIENT_ADDR[-1] != "q" else "p")
    for bad in (mainnet, broken, "hello"):
        with pytest.raises(bond.BondError):
            bond.address_to_script(bad, world.config)


# -- dedicated bond keys (#39) ---------------------------------------------------

def test_bond_key_is_not_the_operational_key(world):
    job = world.job()
    for k in (world.voucher, world.client, world.worker, world.founder):
        with pytest.raises(bond.BondError, match="fresh key"):
            bond.terms_for(build(world), world.job_id(job), world.voucher.pubkey, k.pubkey)
    bad = world.vouch(world.voucher, job, bond=FAKE_TXID, bondkey=world.voucher.pubkey)
    assert "fresh key" in build(world).rejected[bad["id"]]


def test_bond_key_used_once_and_named_with_its_bond(world):
    j1, j2 = world.job(), world.job(job_id="cd" * 32, at=T0 + 10)
    _, bkey, _ = world.bonded_vouch(world.voucher, j1)
    again = world.vouch(world.voucher, j2, bond="bb" * 32, bondkey=bkey.pubkey, at=T0 + 700)
    assert "already used" in build(world).rejected[again["id"]]
    j3 = world.job(job_id="ef" * 32, at=T0 + 20)
    half = world.emit(world.voucher, 3915, [["job", "ef" * 32], ["e", j3["id"]],
                                            ["p", world.worker.pubkey, "worker"], ["amount", "50000"],
                                            ["bond", "cc" * 32]], T0 + 800)
    assert "named together" in build(world).rejected[half["id"]]


def test_bond_key_files_are_kept_apart(tmp_path):
    bkey = keys.new_bond_key(tmp_path)
    assert keys.load_bond_key(bkey.pubkey, tmp_path) == bkey
    assert (tmp_path / "bonds").is_dir() and not list(tmp_path.glob("*.json"))
    with pytest.raises(keys.WrongKeyRole):          # never usable as an operational key
        keys.load(bkey.pubkey[:32], tmp_path / "bonds")


# -- ledger rules ---------------------------------------------------------------

def test_bond_cannot_back_two_vouches(world):
    j1 = world.job()
    j2 = world.job(job_id="cd" * 32, at=T0 + 10)
    world.bonded_vouch(world.voucher, j1, txid=FAKE_TXID)
    second, _, _ = world.bonded_vouch(world.voucher, j2, txid=FAKE_TXID, at=T0 + 700)
    assert "already backs" in build(world).rejected[second["id"]]


def test_late_founder_vouch_cannot_change_existing_bond_arbiter(world):
    job = world.job()
    world.vouch(world.voucher, job)                     # bond names the founder as arbiter
    late = world.vouch(world.founder, job, at=T0 + 700)  # founder would become a party
    assert "change the arbiter" in build(world).rejected[late["id"]]


def test_founder_first_then_others_use_backup(world):
    job = world.job()
    world.vouch(world.founder, job)
    v2 = world.vouch(world.voucher, job, at=T0 + 700)
    assert build(world).vouches[v2["id"]].arbiter == world.backup.pubkey


# -- spending policy (offline) ---------------------------------------------------

def test_forfeit_needs_client_then_arbiter(world):
    job, vouch, arbiter, bkey, led = forfeited_world(world)
    spend = forfeit_spend(world, led, vouch)
    with pytest.raises(bond.BondError, match="client must sign first"):
        bond.arbiter_sign_forfeit(led, vouch["id"], spend, arbiter)
    spend.sign(world.client)
    bond.arbiter_sign_forfeit(led, vouch["id"], spend, arbiter)
    assert bytes.fromhex(spend.finalize())  # two valid signatures


def test_arbiter_refuses_without_upheld_dispute(world):
    job = world.job()
    vouch, _, _ = world.bonded_vouch(world.voucher, job, amount=AMOUNT, txid=FAKE_TXID)
    world.resolve(world.founder, world.dispute(world.client, job), "rejected")
    led = build(world)
    spend = forfeit_spend(world, led, vouch)
    spend.sign(world.client)
    with pytest.raises(bond.BondError, match="not forfeited"):
        bond.arbiter_sign_forfeit(led, vouch["id"], spend, world.founder)


def test_recused_founder_cannot_sign(world):
    job, vouch, arbiter, bkey, led = forfeited_world(world, voucher=world.founder)
    assert arbiter == world.backup
    spend = forfeit_spend(world, led, vouch)
    spend.sign(world.client)
    with pytest.raises(bond.BondError, match="cannot sign|not this bond's arbiter"):
        bond.arbiter_sign_forfeit(led, vouch["id"], spend, world.founder)
    bond.arbiter_sign_forfeit(led, vouch["id"], spend, world.backup)


def test_signatures_are_tied_to_the_exact_transaction(world):
    job, vouch, arbiter, bkey, led = forfeited_world(world)
    to_client = forfeit_spend(world, led, vouch)
    sig = world.client.sign(to_client.sighash())
    redirected = forfeit_spend(world, led, vouch, dest=bond.encode_address("bcrt", 1, bytes(32)))
    with pytest.raises(bond.BondError, match="does not match"):
        redirected.add_signature(world.client.pubkey, sig)
    with pytest.raises(bond.BondError, match="cannot sign"):
        to_client.sign(world.stranger)


def test_one_signature_is_not_enough(world):
    job, vouch, arbiter, bkey, led = forfeited_world(world)
    spend = forfeit_spend(world, led, vouch)
    spend.sign(bkey)
    with pytest.raises(bond.BondError, match="2 of the 3"):
        spend.finalize()


def test_reclaim_needs_the_bond_key(world):
    job, vouch, arbiter, bkey, led = forfeited_world(world)
    spend = bond.reclaim(bond.terms_for_vouch(led, vouch["id"]), FAKE_TXID, 0, AMOUNT,
                         CLIENT_ADDR, world.config)
    for k in (world.client, world.voucher):           # not even the voucher's everyday key
        with pytest.raises(bond.BondError):
            spend.sign(k)
    spend.sign(bkey)
    assert spend.sequence == 2016


def test_saved_spend_signatures_are_rechecked(world):
    job, vouch, arbiter, bkey, led = forfeited_world(world)
    spend = forfeit_spend(world, led, vouch)
    spend.sign(world.client)
    d = spend.to_dict()
    assert bond.Spend.from_dict(d).sigs == spend.sigs
    d["fee"] = 2_000  # tamper with the transaction after signing
    with pytest.raises(bond.BondError):
        bond.Spend.from_dict(d)


# -- live, on the regtest chain -------------------------------------------------

live = pytest.mark.skipif(
    not ((sb.BIN / "bitcoin-cli.exe").exists() and sb._bitcoind_up() and sb._lnd_up("client")),
    reason="sandbox not running (python -m htn sandbox up)")


def fund_bond(world, voucher=None):
    """Voucher makes a fresh bond key, funds a real regtest bond, publishes the vouch.
    Returns (job, vouch, terms, txid, vout, bond key)."""
    voucher = voucher or world.voucher
    job = world.job()
    bkey = keys.generate("bond")
    terms = bond.terms_for(build(world), world.job_id(job), voucher.pubkey, bkey.pubkey)
    txid = sb.fund_address(terms.address(world.config), AMOUNT)
    vouch = world.vouch(voucher, job, AMOUNT, bond=txid, bondkey=bkey.pubkey)
    assert vouch["id"] in build(world).accepted
    vout, _ = bond.find_output(sb.get_tx(txid), terms)
    return job, vouch, terms, txid, vout, bkey


def regtest_address():
    return sb.lncli("client", "newaddress", "p2tr")["address"]


@live
def test_live_address_matches_bitcoin_core(world):
    t = bond.BondTerms(world.client.pubkey, keys.generate("b").pubkey, world.founder.pubkey, 2016)
    assert sb.derive_address(t.descriptor()) == t.address(world.config)


@live
def test_live_bond_check(world):
    job, vouch, terms, txid, vout, bkey = fund_bond(world)
    report = bond.check_bond(build(world), vouch["id"], sb.SandboxChain())
    assert report["live"], report
    assert report["sats"] == AMOUNT and report["arbiter"] == world.founder.pubkey
    assert terms.voucher == bkey.pubkey != world.voucher.pubkey     # dedicated bond key on chain


@live
@pytest.mark.parametrize("voucher_name", ["voucher", "founder"])
def test_live_forfeit_pays_client(world, voucher_name):
    """Upheld dispute: client + acting arbiter sign; the bond goes to the client.
    With the founder as voucher, the backup arbiter must be the one who signs."""
    voucher = getattr(world, voucher_name)
    job, vouch, terms, txid, vout, bkey = fund_bond(world, voucher)
    arbiter = world.backup if voucher is world.founder else world.founder
    assert terms.arbiter == arbiter.pubkey
    world.resolve(arbiter, world.dispute(world.client, job), "upheld")
    led = build(world)
    assert led.vouches[vouch["id"]].status == "forfeited"

    dest = regtest_address()
    spend = bond.forfeit_to_client(terms, txid, vout, AMOUNT, dest, world.config)
    spend.sign(world.client)
    if voucher is world.founder:  # the recused founder cannot sign as arbiter
        with pytest.raises(bond.BondError):
            bond.arbiter_sign_forfeit(led, vouch["id"], spend, world.founder)
    bond.arbiter_sign_forfeit(led, vouch["id"], spend, arbiter)
    raw = spend.finalize()
    assert sb.mempool_check(raw)["allowed"]
    assert sb.broadcast(raw) == spend.spend_txid
    sb.mine(1)
    out = sb.get_tx(spend.spend_txid)["vout"][0]
    assert out["scriptPubKey"]["address"] == dest
    assert round(out["value"] * 100_000_000) == AMOUNT - bond.DEFAULT_FEE_SATS
    after = bond.check_bond(build(world), vouch["id"], sb.SandboxChain())
    assert not after["live"] and not after["counts"]          # forfeited: no longer counts


@live
def test_live_chain_rejects_bad_spends(world):
    job, vouch, terms, txid, vout, bkey = fund_bond(world)
    dest = regtest_address()
    spend = bond.forfeit_to_client(terms, txid, vout, AMOUNT, dest, world.config)
    sig_v = bytes.fromhex(bkey.sign(spend.sighash()))
    # stack order is arbiter, voucher, client
    assert not sb.mempool_check(spend.raw_with_stack([b"", sig_v, b""]))["allowed"]       # one signature
    stranger = bytes.fromhex(world.stranger.sign(spend.sighash()))
    assert not sb.mempool_check(spend.raw_with_stack([stranger, sig_v, b""]))["allowed"]  # outsider
    opkey = bytes.fromhex(world.voucher.sign(spend.sighash()))
    assert not sb.mempool_check(spend.raw_with_stack([b"", opkey, b""]))["allowed"]       # operational key
    early = bond.reclaim(terms, txid, vout, AMOUNT, dest, world.config)
    early.sign(bkey)
    res = sb.mempool_check(early.finalize())
    assert not res["allowed"] and "non-BIP68-final" in res["reject-reason"]               # before T


@live
def test_live_silent_arbiter_voucher_reclaims_exactly_at_T(world):
    """A dispute is filed but the arbiter never decides: the voucher alone takes the
    bond back once it is T blocks old (refused one block earlier)."""
    job, vouch, terms, txid, vout, bkey = fund_bond(world)
    world.dispute(world.client, job)                # filed, never resolved
    assert build(world).vouches[vouch["id"]].status == "active"
    spend = bond.reclaim(terms, txid, vout, AMOUNT, regtest_address(), world.config)
    spend.sign(bkey)
    raw = spend.finalize()
    conf = sb.get_tx(txid)["confirmations"]
    sb.mine(terms.timelock_blocks - 1 - conf)       # one block short of T
    res = sb.mempool_check(raw)
    assert not res["allowed"] and "non-BIP68-final" in res["reject-reason"]
    sb.mine(1)                                      # now exactly T
    assert sb.mempool_check(raw)["allowed"]
    sb.broadcast(raw)
    sb.mine(1)
    assert sb.get_tx(spend.spend_txid)["confirmations"] == 1
    # An honest reclaim keeps counting toward the voucher's score (#47).
    report = bond.check_bond(build(world), vouch["id"], sb.SandboxChain())
    assert not report["live"] and report["counts"] and report["reclaimed_by"] == spend.spend_txid


# -- the same story through the command-line tool ------------------------------

from test_cli import last_id, run  # noqa: E402,F401  (run is a fixture)


@live
def test_live_cli_forfeit_flow(run):
    f = str(run.private)
    now = int(__import__("time").time())
    code, out = run("job-offer", "--as", "client", "--worker", "worker", "--terms-file", f, "--at", str(now))
    job = out.split("job id ")[1].strip()
    assert run("accept", "--as", "worker", "--job", job, "--at", str(now + 1))[0] == 0
    code, out = run("bond-fund", "--as", "voucher", "--job", job, "--amount", "30000")
    assert code == 0, out
    txid = out.split("txid ")[1].split()[0]
    bond_key = out.split("bond key ")[1].split()[0]
    assert bond_key != keys.load("voucher", run.home.parent / "keys").pubkey
    code, out = run("vouch-issue", "--as", "voucher", "--job", job, "--amount", "30000",
                    "--bond", txid, "--at", str(now + 60))
    assert code == 0, out
    vouch = last_id(out)
    code, out = run("bond-check", vouch)
    assert code == 0 and '"live": true' in out, out

    dest = regtest_address()
    code, out = run("bond-reclaim", "--vouch", vouch, "--to", dest)      # signed with the bond key,
    raw = out.split("not broadcast): ")[1].strip()                       # but too early for the chain
    assert "non-BIP68-final" in sb.mempool_check(raw)["reject-reason"]

    code, out = run("bond-forfeit", "--as", "client", "--vouch", vouch, "--to", dest)
    assert code == 1 and "only a forfeited vouch" in out          # no upheld dispute yet
    code, out = run("dispute-file", "--as", "client", "--job", job, "--reason-file", f, "--at", str(now + 120))
    dispute = last_id(out)
    assert run("dispute-resolve", "--as", "founder", "--dispute", dispute, "--outcome", "upheld",
               "--at", str(now + 180))[0] == 0
    assert run("bond-forfeit", "--as", "client", "--vouch", vouch, "--to", dest)[0] == 0
    code, out = run("bond-arbiter-sign", "--as", "backup", "--vouch", vouch)
    assert code == 1 and "not this bond's arbiter" in out
    code, out = run("bond-arbiter-sign", "--as", "founder", "--vouch", vouch, "--broadcast")
    assert code == 0, out
    spend_txid = out.split("txid ")[1].split()[0]
    sb.mine(1)
    assert sb.get_tx(spend_txid)["vout"][0]["scriptPubKey"]["address"] == dest
