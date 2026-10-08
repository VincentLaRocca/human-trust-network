#!/usr/bin/env python3
"""Regtest query for a seal close.

Asks a local bitcoind whether a known spending transaction spends the outpoint,
is confirmed, and carries the expected bundle. gettxout does not name the
spender, so the spending txid is an argument. This file does not build or
broadcast a transaction. The Core regtest builder is not in this tree. A
failed query does not return an AnchorProof.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from base64 import b64encode
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "human-witness"))

from client_observer import AnchorProof, Reject  # noqa: E402


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


def fetch_anchor(
    url: str,
    user: str,
    password: str,
    spent_txid: str,
    spent_vout: int,
    spending_txid: str,
    bundle: bytes,
    min_conf: int = 1,
) -> AnchorProof:
    if len(bundle) != 32 or len(bytes.fromhex(spent_txid)) != 32 or len(bytes.fromhex(spending_txid)) != 32:
        raise Reject("anchor id")
    if rpc(url, user, password, "gettxout", [spent_txid, spent_vout]) is not None:
        raise AnchorMiss("outpoint still unspent")
    tx = rpc(url, user, password, "getrawtransaction", [spending_txid, True])
    spends = any(
        vin.get("txid") == spent_txid and vin.get("vout") == spent_vout
        for vin in tx.get("vin", [])
    )
    if not spends:
        raise AnchorMiss("transaction does not spend the outpoint")
    if int(tx.get("confirmations") or 0) < min_conf:
        raise AnchorMiss("spend is not confirmed")
    if not carries_bundle(tx, bundle):
        raise AnchorMiss("bundle not in the spending transaction")
    return AnchorProof(
        bytes.fromhex(spending_txid),
        0,
        bytes.fromhex(spent_txid),
        spent_vout,
        bundle,
        True,
    )
