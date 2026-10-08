#!/usr/bin/env python3
"""Regtest spend that a later fetch_anchor can read.

Creates one transaction: the given outpoint, an OP_RETURN of the 32-byte
bundle, and a destination output. Signs with a WIF or with the node wallet.
Broadcasts, then mines one block. Refuses any chain other than regtest.

This does not run consider() and it does not produce an observer split.
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from base64 import b64encode


class BuildFail(Exception):
    pass


def rpc(url: str, user: str, password: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "1.0", "id": "htn", "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": "Basic " + b64encode(f"{user}:{password}".encode()).decode(),
    })
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode())
    if payload.get("error"):
        raise BuildFail(str(payload["error"]))
    return payload["result"]


def require_regtest(url: str, user: str, password: str) -> None:
    info = rpc(url, user, password, "getblockchaininfo", [])
    if info.get("chain") != "regtest":
        raise BuildFail("refusing non-regtest chain")


def build(url: str, user: str, password: str, txid: str, vout: int, dest: str, amount: float, bundle_hex: str, wif: str | None, mine_to: str) -> str:
    require_regtest(url, user, password)
    raw = bytes.fromhex(bundle_hex)
    if len(raw) != 32:
        raise BuildFail("bundle must be 32 bytes")
    unsigned = rpc(url, user, password, "createrawtransaction", [
        [{"txid": txid, "vout": vout}],
        [{dest: amount}, {"data": bundle_hex}],
    ])
    if wif:
        prev = rpc(url, user, password, "gettxout", [txid, vout])
        if prev is None:
            raise BuildFail("outpoint missing or already spent")
        signed = rpc(url, user, password, "signrawtransactionwithkey", [unsigned, [wif], [{
            "txid": txid,
            "vout": vout,
            "scriptPubKey": prev["scriptPubKey"]["hex"],
            "amount": prev["value"],
        }]])
    else:
        signed = rpc(url, user, password, "signrawtransactionwithwallet", [unsigned])
    if not signed.get("complete"):
        raise BuildFail("sign incomplete: " + json.dumps(signed.get("errors")))
    spending = rpc(url, user, password, "sendrawtransaction", [signed["hex"]])
    rpc(url, user, password, "generatetoaddress", [1, mine_to])
    return spending


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:18443")
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--txid", required=True)
    parser.add_argument("--vout", type=int, required=True)
    parser.add_argument("--dest", required=True)
    parser.add_argument("--amount", type=float, required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--wif")
    parser.add_argument("--mine-to", required=True)
    args = parser.parse_args()
    spending = build(args.url, args.user, args.password, args.txid, args.vout, args.dest, args.amount, args.bundle, args.wif, args.mine_to)
    print(spending)


if __name__ == "__main__":
    main()
