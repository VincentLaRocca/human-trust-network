#!/usr/bin/env python3
"""Regtest query for a seal close.

A cold lock is minted here from txinwitness on the input that spends the seal.
The proposal does not mint it. An annex starting with 0x50 is skipped. The
script is the item before the control block.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from base64 import b64encode
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "human-witness"))

from client_observer import AnchorProof, Reject, WitnessLock, mint_lock  # noqa: E402


class AnchorMiss(Exception):
    pass


def rpc(url: str, user: str, password: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "1.0", "id": "htn", "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": "Basic " + b64encode(f"{user}:{password}".encode()).decode(),
    })
    with urllib.request.urlopen(req, timeout=5) as resp:
        payload = json.loads(resp.read().decode())
    if payload.get("error"):
        raise AnchorMiss(str(payload["error"]))
    return payload["result"]


def carries_bundle(tx: dict, bundle: bytes) -> bool:
    needle = bundle.hex()
    for vout in tx.get("vout", []):
        script = vout.get("scriptPubKey", {})
        if needle in script.get("asm", "") or needle in script.get("hex", ""):
            return True
    return False


def spending_input(tx: dict, spent_txid: str, spent_vout: int) -> dict:
    for vin in tx.get("vin", []):
        if vin.get("txid") == spent_txid and vin.get("vout") == spent_vout:
            return vin
    raise AnchorMiss("transaction does not spend the outpoint")


def stack(vin: dict) -> list[bytes]:
    raw = vin.get("txinwitness")
    if not raw:
        raise AnchorMiss("input has no witness")
    return [bytes.fromhex(item) for item in raw]


def leaf_and_control(items: list[bytes]) -> tuple[bytes, bytes]:
    if len(items) >= 2 and items[-1][:1] == b"\x50":
        items = items[:-1]
    if len(items) < 2:
        raise AnchorMiss("not a script-path witness")
    script, control = items[-2], items[-1]
    if not control or control[0] & 0xFE != 0xC0:
        raise AnchorMiss("control block leaf version")
    if len(control) < 33 or (len(control) - 33) % 32 != 0:
        raise AnchorMiss("control block length")
    return script, control


def witness_lock(tx: dict, spent_txid: str, spent_vout: int, script: bytes | None = None, key_path: bool = False) -> WitnessLock:
    items = stack(spending_input(tx, spent_txid, spent_vout))
    if script is not None:
        revealed, control = leaf_and_control(items)
        if revealed != script:
            raise AnchorMiss("witness script is not the revealed cold script")
        return mint_lock("script", revealed, control)
    if key_path:
        if len(items) != 1 or len(items[0]) not in (64, 65):
            raise AnchorMiss("key-path witness is not one Schnorr signature")
        return mint_lock("key", b"", b"")
    return mint_lock("unchecked", b"", b"")


def fetch_anchor(
    url: str,
    user: str,
    password: str,
    spent_txid: str,
    spent_vout: int,
    spending_txid: str,
    bundle: bytes,
    min_conf: int = 1,
    script: bytes | None = None,
    key_path: bool = False,
) -> tuple[AnchorProof, WitnessLock]:
    if len(bundle) != 32 or len(bytes.fromhex(spent_txid)) != 32 or len(bytes.fromhex(spending_txid)) != 32:
        raise Reject("anchor id")
    if rpc(url, user, password, "gettxout", [spent_txid, spent_vout]) is not None:
        raise AnchorMiss("outpoint still unspent")
    tx = rpc(url, user, password, "getrawtransaction", [spending_txid, True])
    if int(tx.get("confirmations") or 0) < min_conf:
        raise AnchorMiss("spend is not confirmed")
    if not carries_bundle(tx, bundle):
        raise AnchorMiss("bundle not in the spending transaction")
    lock = witness_lock(tx, spent_txid, spent_vout, script, key_path)
    proof = AnchorProof(
        bytes.fromhex(spending_txid),
        0,
        bytes.fromhex(spent_txid),
        spent_vout,
        bundle,
        True,
    )
    return proof, lock
