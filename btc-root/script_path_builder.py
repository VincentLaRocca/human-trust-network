#!/usr/bin/env python3
"""Regtest script-path witness the anchor query can read.

Builds the cold script and control block, then a witness stack of signature,
script, control block. Broadcasts only on regtest. This file does not advance
a title. The observer must take the lock from fetch_anchor, not from here.
"""

from __future__ import annotations

import argparse
import hashlib
import struct

from builder import require_regtest, rpc
from operator_cold_leaf import build_control_seal, pubkey_from_secret, sha256


class BuildFail(Exception):
    pass


def compact(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    raise BuildFail("item too long")


def witness_stack(sig: bytes, script: bytes, control: bytes) -> list[bytes]:
    if len(sig) not in (64, 65):
        raise BuildFail("script-path signature must be 64 or 65 bytes")
    if not control or control[0] & 0xFE != 0xC0:
        raise BuildFail("control block")
    return [sig, script, control]


def raw_spend(prev_txid: str, vout: int, dest_script: bytes, amount: int, witness: list[bytes]) -> bytes:
    out = b""
    out += struct.pack("<I", 2)
    out += bytes.fromhex(prev_txid)[::-1]
    out += struct.pack("<I", vout)
    out += b"\x00"
    out += struct.pack("<I", 0xFFFFFFFF)
    out += struct.pack("<B", 2)
    out += struct.pack("<q", amount)
    out += compact(len(dest_script)) + dest_script
    data = b"\x6a\x20" + hashlib.sha256(b"bundle-placeholder").digest()
    out += struct.pack("<q", 0)
    out += compact(len(data)) + data
    out += b"\x00\x00\x00\x00"
    raw = b"\x02\x00\x00\x00" + b"\x00\x01" + out
    # marker/flag already placed by the version dance above is wrong for witness.
    # Build the segwit serialization directly.
    body = struct.pack("<I", 2)
    body += b"\x00\x01"
    body += b"\x01"
    body += bytes.fromhex(prev_txid)[::-1] + struct.pack("<I", vout) + b"\x00" + struct.pack("<I", 0xFFFFFFFF)
    body += b"\x02"
    body += struct.pack("<q", amount) + compact(len(dest_script)) + dest_script
    body += struct.pack("<q", 0) + compact(len(data)) + data
    body += b"\x01" + bytes([len(witness)])
    for item in witness:
        body += compact(len(item)) + item
    body += struct.pack("<I", 0)
    return body


def opening_for(cold_secret: bytes):
    cold = pubkey_from_secret(cold_secret)
    hot = pubkey_from_secret(sha256(b"script-path-internal"))
    script = b"\x20" + cold[1:] + b"\xac"
    return build_control_seal(hot, cold, __import__("operator_cold_leaf").cold_leaf_hash(script))


def broadcast(url: str, user: str, password: str, raw: bytes, mine_to: str) -> str:
    require_regtest(url, user, password)
    txid = rpc(url, user, password, "sendrawtransaction", [raw.hex()])
    rpc(url, user, password, "generatetoaddress", [1, mine_to])
    return txid


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--show-witness", action="store_true")
    args = parser.parse_args()
    opening = opening_for(sha256(b"cold-key"))
    stack = witness_stack(b"\x11" * 64, opening.cold_script, opening.control_block)
    if args.show_witness:
        print("script", opening.cold_script.hex())
        print("control", opening.control_block.hex())
        print("stack", len(stack))
    print("script-path witness shape ok")


if __name__ == "__main__":
    main()
