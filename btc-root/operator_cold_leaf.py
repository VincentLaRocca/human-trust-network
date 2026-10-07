#!/usr/bin/env python3
"""Operator wallet check: a new control seal must commit to the genesis cold leaf.

Public verifiers do not run this. The wallet does, on every hot rotation,
then stores the Taproot opening for a later script-path recovery.

BIP-341 single-leaf tree. The leaf is the cold spend script. Global state
commits to TaggedHash("urn:lagroka:agent:cold:v1", script), not to the raw
cold pubkey. The on-chain output commits to that leaf via the TapTweak.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def tagged_hash(tag: str, payload: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + payload).digest()


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def ser_script(script: bytes) -> bytes:
    n = len(script)
    if n < 0xFD:
        return bytes([n]) + script
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n) + script
    raise ValueError("script too long for this routine")


def inv(a: int, mod: int = P) -> int:
    return pow(a, mod - 2, mod)


def lift_x(x: int) -> tuple[int, int]:
    if x >= P:
        raise ValueError("x out of range")
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y * y) % P != y2:
        raise ValueError("not on curve")
    return x, y if y % 2 == 0 else P - y


def add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if x1 == x2 and y1 == y2:
        lam = (3 * x1 * x1) * inv(2 * y1) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return x3, y3


def mul(k: int, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        k >>= 1
    return result


def xonly(pk: bytes) -> bytes:
    if len(pk) == 33:
        if pk[0] not in (2, 3):
            raise ValueError("compressed pubkey")
        return pk[1:]
    if len(pk) == 32:
        return pk
    raise ValueError("pubkey must be 32 or 33 bytes")


def cold_script(cold_pk: bytes) -> bytes:
    return b"\x20" + xonly(cold_pk) + b"\xac"


def cold_leaf_hash(script: bytes) -> bytes:
    return tagged_hash("urn:lagroka:agent:cold:v1", script)


def tapleaf_hash(script: bytes, leaf_version: int = 0xC0) -> bytes:
    return tagged_hash("TapLeaf", bytes([leaf_version]) + ser_script(script))


@dataclass(frozen=True)
class SealOpening:
    internal_xonly: bytes
    cold_script: bytes
    cold_leaf: bytes
    tapleaf: bytes
    output_xonly: bytes
    parity: int
    script_pubkey: bytes
    control_block: bytes

    def store(self, path: Path) -> None:
        path.write_text(json.dumps({
            "internal_xonly": self.internal_xonly.hex(),
            "cold_script": self.cold_script.hex(),
            "cold_leaf": self.cold_leaf.hex(),
            "tapleaf": self.tapleaf.hex(),
            "output_xonly": self.output_xonly.hex(),
            "parity": self.parity,
            "script_pubkey": self.script_pubkey.hex(),
            "control_block": self.control_block.hex(),
        }, indent=2) + "\n")


class ColdLeafDropped(Exception):
    pass


def build_control_seal(hot_pk: bytes, cold_pk: bytes, expected_cold_leaf: bytes) -> SealOpening:
    script = cold_script(cold_pk)
    leaf = cold_leaf_hash(script)
    if leaf != expected_cold_leaf:
        raise ColdLeafDropped("genesis cold_leaf does not match the cold script")
    internal = xonly(hot_pk)
    point = lift_x(int.from_bytes(internal, "big"))
    leaf_hash = tapleaf_hash(script)
    tweak = int.from_bytes(tagged_hash("TapTweak", internal + leaf_hash), "big")
    if tweak >= N:
        raise ColdLeafDropped("tweak out of range")
    tweaked = add(point, mul(tweak, (GX, GY)))
    if tweaked is None:
        raise ColdLeafDropped("tweak produced infinity")
    qx, qy = tweaked
    parity = qy % 2
    output = qx.to_bytes(32, "big")
    control = bytes([0xC0 + parity]) + internal
    script_pubkey = b"\x51\x20" + output
    opening = SealOpening(internal, script, leaf, leaf_hash, output, parity, script_pubkey, control)
    if not opening_commits(opening):
        raise ColdLeafDropped("output key does not commit to cold_leaf")
    return opening


def opening_commits(opening: SealOpening) -> bool:
    if cold_leaf_hash(opening.cold_script) != opening.cold_leaf:
        return False
    if tapleaf_hash(opening.cold_script) != opening.tapleaf:
        return False
    if opening.control_block[1:33] != opening.internal_xonly:
        return False
    if opening.control_block[0] != 0xC0 + opening.parity:
        return False
    point = lift_x(int.from_bytes(opening.internal_xonly, "big"))
    tweak = int.from_bytes(tagged_hash("TapTweak", opening.internal_xonly + opening.tapleaf), "big")
    tweaked = add(point, mul(tweak, (GX, GY)))
    if tweaked is None:
        return False
    qx, qy = tweaked
    return qx.to_bytes(32, "big") == opening.output_xonly and (qy % 2) == opening.parity


def dropped_leaf_output(hot_pk: bytes) -> bytes:
    internal = xonly(hot_pk)
    point = lift_x(int.from_bytes(internal, "big"))
    tweak = int.from_bytes(tagged_hash("TapTweak", internal), "big")
    tweaked = add(point, mul(tweak, (GX, GY)))
    assert tweaked is not None
    return b"\x51\x20" + tweaked[0].to_bytes(32, "big")


def pubkey_from_secret(secret: bytes) -> bytes:
    point = mul(int.from_bytes(secret, "big"), (GX, GY))
    if point is None:
        raise ValueError("bad secret")
    x, y = point
    return bytes([2 + (y % 2)]) + x.to_bytes(32, "big")


def main() -> None:
    hot = pubkey_from_secret(sha256(b"hot-key"))
    cold = pubkey_from_secret(sha256(b"cold-key"))
    expected = cold_leaf_hash(cold_script(cold))
    opening = build_control_seal(hot, cold, expected)
    out = Path("control_seal_opening.json")
    opening.store(out)
    bare = dropped_leaf_output(hot)
    print("cold_leaf", opening.cold_leaf.hex())
    print("output   ", opening.output_xonly.hex())
    print("control  ", opening.control_block.hex())
    print("commits  ", opening_commits(opening))
    print("bare drop differs", bare != opening.script_pubkey)
    try:
        build_control_seal(hot, cold, sha256(b"other-leaf"))
    except ColdLeafDropped as exc:
        print("wrong genesis leaf rejected:", exc)
    else:
        raise SystemExit("wrong cold_leaf was accepted")
    print("opening stored", out)


if __name__ == "__main__":
    main()
