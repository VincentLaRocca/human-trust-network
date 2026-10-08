#!/usr/bin/env python3
"""Witness stack for a cold script-path spend.

Signature, then the cold script, then the control block. This file does not
sign a BIP-341 sighash and it does not broadcast. fetch_anchor mints the lock
from a confirmed transaction's txinwitness. A stack built here is not a lock.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from operator_cold_leaf import build_control_seal, cold_leaf_hash, cold_script, pubkey_from_secret, sha256


class BuildFail(Exception):
    pass


def witness_stack(sig: bytes, script: bytes, control: bytes) -> list[bytes]:
    if len(sig) not in (64, 65):
        raise BuildFail("script-path signature must be 64 or 65 bytes")
    if not control or control[0] & 0xFE != 0xC0:
        raise BuildFail("control block")
    return [sig, script, control]


def opening_for(cold_secret: bytes):
    cold = pubkey_from_secret(cold_secret)
    hot = pubkey_from_secret(sha256(b"script-path-internal"))
    script = cold_script(cold)
    return build_control_seal(hot, cold, cold_leaf_hash(script))


def main() -> None:
    opening = opening_for(sha256(b"cold-key"))
    stack = witness_stack(b"\x11" * 64, opening.cold_script, opening.control_block)
    if stack[-2] != opening.cold_script or stack[-1] != opening.control_block:
        raise SystemExit("stack order")
    print("script-path witness shape ok")


if __name__ == "__main__":
    main()
