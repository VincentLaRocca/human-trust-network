"""Local Lightning sandbox: one Bitcoin Core node + two LND nodes, REGTEST ONLY.

Everything lives under tools/ (gitignored):
    tools/bin/        bitcoind.exe, bitcoin-cli.exe, lnd.exe, lncli.exe
                      (fetched and signature-checked by scripts/fetch_tools.py)
    tools/regtest/    node data, logs, generated RPC password

All services listen on 127.0.0.1 only. Regtest coins are worthless and are
created on demand by "mining" blocks locally.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
BIN = TOOLS / "bin"
RUN = TOOLS / "regtest"
NETWORK = "regtest"  # hard-coded on purpose; there is no switch

# Non-default ports so the sandbox never collides with (or talks to) any other
# Bitcoin or Lightning node on this computer.
BTC_RPC_PORT = 28443
NODES = {
    "client": {"rpc": 11009, "rest": 18180, "p2p": 19735},
    "worker": {"rpc": 11010, "rest": 18181, "p2p": 19736},
}
CHANNEL_SATS = 1_000_000

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_DETACHED = (getattr(subprocess, "DETACHED_PROCESS", 0)
             | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))


class SandboxError(RuntimeError):
    pass


def _exe(name: str) -> Path:
    path = BIN / (name + (".exe" if os.name == "nt" else ""))
    if not path.exists():
        raise SandboxError(f"{path} not found. Run: .venv\\Scripts\\python scripts\\fetch_tools.py")
    return path


def _creds() -> dict:
    path = RUN / "rpc.json"
    if not path.exists():
        RUN.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"user": "htn", "password": secrets.token_hex(16)}))
    return json.loads(path.read_text())


def _run(args: list, timeout=60) -> str:
    proc = subprocess.run([str(a) for a in args], capture_output=True, text=True,
                          timeout=timeout, creationflags=_NO_WINDOW)
    if proc.returncode != 0:
        raise SandboxError((proc.stderr or proc.stdout).strip())
    return proc.stdout.strip()


def bitcoin_cli(*args, timeout=60) -> str:
    c = _creds()
    return _run([_exe("bitcoin-cli"), f"-{NETWORK}", f"-datadir={RUN / 'bitcoind'}",
                 f"-rpcport={BTC_RPC_PORT}", f"-rpcuser={c['user']}", f"-rpcpassword={c['password']}",
                 *args], timeout)


def lncli(node: str, *args, timeout=60) -> dict:
    out = _run([_exe("lncli"), f"--network={NETWORK}", f"--lnddir={RUN / node}",
                f"--rpcserver=127.0.0.1:{NODES[node]['rpc']}", *args], timeout)
    return json.loads(out) if out else {}


def _port_in_use(port: int) -> bool:
    import socket
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _require_free(*ports: int) -> None:
    busy = [p for p in ports if _port_in_use(p)]
    if busy:
        raise SandboxError(f"port(s) {busy} already used by another program; "
                           "change the port numbers at the top of htn/sandbox.py")


def _spawn(args: list, log: Path) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "ab") as fh:
        subprocess.Popen([str(a) for a in args], stdout=fh, stderr=subprocess.STDOUT,
                         stdin=subprocess.DEVNULL, creationflags=_DETACHED | _NO_WINDOW)


def pay_detached(node: str, payment_request: str) -> None:
    """Start `lncli payinvoice` as its own process (a held payment can take hours)."""
    _spawn([_exe("lncli"), f"--network={NETWORK}", f"--lnddir={RUN / node}",
            f"--rpcserver=127.0.0.1:{NODES[node]['rpc']}", "payinvoice", "--force", "--json",
            payment_request], RUN / f"{node}-payments.log")


def _wait(what: str, check, timeout=120) -> None:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            if check():
                return
        except Exception as e:  # not up yet
            last = str(e)[:200]
        time.sleep(1)
    raise SandboxError(f"timed out waiting for {what}. Last error: {last}")


def _bitcoind_up() -> bool:
    try:
        bitcoin_cli("getblockchaininfo", timeout=10)
        return True
    except Exception:
        return False


def _lnd_up(node: str) -> bool:
    try:
        lncli(node, "getinfo", timeout=10)
        return True
    except Exception:
        return False


def start_bitcoind() -> None:
    if _bitcoind_up():
        return
    _require_free(BTC_RPC_PORT)
    c = _creds()
    datadir = RUN / "bitcoind"
    datadir.mkdir(parents=True, exist_ok=True)
    _spawn([_exe("bitcoind"), f"-{NETWORK}", f"-datadir={datadir}", "-server", "-listen=0",
            f"-rpcport={BTC_RPC_PORT}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
            f"-rpcuser={c['user']}", f"-rpcpassword={c['password']}",
            "-txindex=1", "-fallbackfee=0.0002"], RUN / "bitcoind.log")
    _wait("bitcoind", _bitcoind_up, 90)


def start_lnd(node: str) -> None:
    if _lnd_up(node):
        return
    c, p = _creds(), NODES[node]
    _require_free(p["rpc"], p["rest"], p["p2p"])
    _spawn([_exe("lnd"), f"--lnddir={RUN / node}", f"--alias=htn-{node}",
            "--bitcoin.active", f"--bitcoin.{NETWORK}", "--bitcoin.node=bitcoind",
            f"--bitcoind.rpchost=127.0.0.1:{BTC_RPC_PORT}",
            f"--bitcoind.rpcuser={c['user']}", f"--bitcoind.rpcpass={c['password']}",
            "--bitcoind.rpcpolling",
            "--noseedbackup",  # regtest only: wallet created and unlocked automatically
            "--invoices.holdexpirydelta=18",  # must match payments.LND_HOLD_EXPIRY_DELTA
            f"--rpclisten=127.0.0.1:{p['rpc']}", f"--restlisten=127.0.0.1:{p['rest']}",
            f"--listen=127.0.0.1:{p['p2p']}"], RUN / f"{node}.log")
    _wait(f"lnd {node}", lambda: _lnd_up(node), 180)


def mine(blocks: int = 1) -> int:
    addr = lncli("client", "newaddress", "p2wkh")["address"]
    bitcoin_cli("generatetoaddress", str(blocks), addr)
    height = int(bitcoin_cli("getblockcount"))
    for node in NODES:
        _wait(f"{node} to sync to block {height}",
              lambda n=node: lncli(n, "getinfo")["block_height"] >= height
              and lncli(n, "getinfo")["synced_to_chain"], 120)
    return height


# -- on-chain helpers for the vouch bond (Phase 3) ------------------------------

def fund_address(address: str, sats: int) -> str:
    """Send regtest coins from the client node's wallet; confirm with one block. Returns txid."""
    if not address.startswith("bcrt1"):
        raise SandboxError("sandbox only pays regtest addresses")
    txid = lncli("client", "sendcoins", f"--addr={address}", f"--amt={sats}")["txid"]
    mine(1)
    return txid


def get_tx(txid: str) -> dict:
    return json.loads(bitcoin_cli("getrawtransaction", txid, "true"))


def rpc(method: str, *params):
    """Direct JSON-RPC call to the sandbox bitcoind (faster than bitcoin-cli for scans)."""
    import base64
    import urllib.request
    c = _creds()
    req = urllib.request.Request(
        f"http://127.0.0.1:{BTC_RPC_PORT}/",
        data=json.dumps({"jsonrpc": "1.0", "id": "htn", "method": method, "params": list(params)}).encode(),
        headers={"Authorization": "Basic " + base64.b64encode(f"{c['user']}:{c['password']}".encode()).decode(),
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            out = json.load(r)
    except urllib.error.HTTPError as e:
        out = json.load(e)
    if out.get("error"):
        raise SandboxError(out["error"].get("message", str(out["error"])))
    return out["result"]


class SandboxChain:
    """Read-only chain questions for bond checks, answered by the sandbox node."""

    def get_tx(self, txid: str) -> dict | None:
        try:
            return get_tx(txid)
        except SandboxError:
            return None

    def utxo(self, txid: str, vout: int) -> dict | None:
        out = bitcoin_cli("gettxout", txid, str(vout))
        return json.loads(out) if out else None

    def tip(self) -> dict:
        return {"height": int(bitcoin_cli("getblockcount")), "hash": bitcoin_cli("getbestblockhash")}

    def spending_tx(self, txid: str, vout: int) -> dict | None:
        """The transaction that spent an output (mempool, then blocks after the funding)."""
        hit = rpc("gettxspendingprevout", [{"txid": txid, "vout": vout}])[0]
        if hit.get("spendingtxid"):
            return rpc("getrawtransaction", hit["spendingtxid"], True)
        funding = rpc("getrawtransaction", txid, True)
        if "blockhash" not in funding:
            return None
        height = rpc("getblockheader", funding["blockhash"])["height"]
        for h in range(height + 1, rpc("getblockcount") + 1):
            for tx in rpc("getblock", rpc("getblockhash", h), 2)["tx"]:
                if any(i.get("txid") == txid and i.get("vout") == vout for i in tx["vin"]):
                    return tx
        return None


def mempool_check(raw_hex: str) -> dict:
    """Would Bitcoin Core accept this transaction now? {"allowed": bool, "reject-reason": ...}"""
    return json.loads(bitcoin_cli("testmempoolaccept", json.dumps([raw_hex])))[0]


def broadcast(raw_hex: str) -> str:
    return bitcoin_cli("sendrawtransaction", raw_hex)


def derive_address(descriptor: str) -> str:
    """Bitcoin Core's own address for a descriptor (independent cross-check)."""
    checksum = json.loads(bitcoin_cli("getdescriptorinfo", descriptor))["checksum"]
    return json.loads(bitcoin_cli("deriveaddresses", f"{descriptor}#{checksum}"))[0]


def _active_channel() -> dict | None:
    chans = lncli("client", "listchannels", "--active_only").get("channels", [])
    return chans[0] if chans else None


def ensure_channel() -> None:
    """Fund the client and open a 1,000,000-sat channel client -> worker."""
    if _active_channel():
        return
    if int(lncli("client", "walletbalance")["confirmed_balance"]) < 2 * CHANNEL_SATS:
        mine(101)  # coinbase coins need 100 blocks to mature
    worker = lncli("worker", "getinfo")["identity_pubkey"]
    peers = [x["pub_key"] for x in lncli("client", "listpeers").get("peers", [])]
    if worker not in peers:
        lncli("client", "connect", f"{worker}@127.0.0.1:{NODES['worker']['p2p']}")
    if not lncli("client", "pendingchannels").get("pending_open_channels"):
        lncli("client", "openchannel", f"--node_key={worker}", f"--local_amt={CHANNEL_SATS}")
    mine(6)
    _wait("channel to become active", _active_channel, 60)


def up() -> dict:
    start_bitcoind()
    for node in NODES:
        start_lnd(node)
    ensure_channel()
    return status()


def status() -> dict:
    out = {"network": NETWORK, "bitcoind": _bitcoind_up()}
    if out["bitcoind"]:
        out["block_height"] = int(bitcoin_cli("getblockcount"))
    for node in NODES:
        if not _lnd_up(node):
            out[node] = "down"
            continue
        info = lncli(node, "getinfo")
        chans = lncli(node, "listchannels").get("channels", [])
        out[node] = {
            "pubkey": info["identity_pubkey"],
            "synced": info["synced_to_chain"],
            "wallet_sats": int(lncli(node, "walletbalance")["confirmed_balance"]),
            "channels": [{"peer": c["remote_pubkey"][:16] + "...", "active": c["active"],
                          "local_sats": int(c["local_balance"]),
                          "remote_sats": int(c["remote_balance"])} for c in chans],
        }
    return out


def down() -> None:
    for node in NODES:
        if _lnd_up(node):
            try:
                lncli(node, "stop")
            except SandboxError:
                pass
    if _bitcoind_up():
        bitcoin_cli("stop")
    _wait("nodes to stop", lambda: not _bitcoind_up() and not any(_lnd_up(n) for n in NODES), 60)


def reset() -> None:
    """Delete all sandbox chain and wallet data (worthless regtest coins)."""
    if _bitcoind_up() or any(_lnd_up(n) for n in NODES):
        raise SandboxError("stop the sandbox first: sandbox down")
    if RUN.exists():
        shutil.rmtree(RUN)
