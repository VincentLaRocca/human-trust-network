#!/usr/bin/env python3
"""Pay-to-contract tweak for a file bundle.

The seal key is Q = P + H(P || bundle)·G. Spending Q proves the key holder
committed to that bundle: a different digest is a different key. This is not
the cold-leaf TapTweak, and it does not check the file against the object.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from operator_cold_leaf import GX, GY, N, add, lift_x, mul, tagged_hash, xonly


class BundleMiss(Exception):
    pass


def file_bundle(data: bytes) -> bytes:
    return tagged_hash("urn:htn:file:v1", data)


def tweak_scalar(internal_xonly: bytes, bundle: bytes) -> int:
    internal = xonly(internal_xonly)
    if len(bundle) != 32:
        raise BundleMiss("bundle must be 32 bytes")
    scalar = int.from_bytes(tagged_hash("urn:htn:bundle-tweak:v1", internal + bundle), "big")
    if scalar >= N or scalar == 0:
        raise BundleMiss("tweak out of range")
    return scalar


def tweaked_output(internal_xonly: bytes, bundle: bytes) -> bytes:
    """X-only output key committed to this bundle."""
    internal = xonly(internal_xonly)
    point = lift_x(int.from_bytes(internal, "big"))
    tweaked = add(point, mul(tweak_scalar(internal, bundle), (GX, GY)))
    if tweaked is None:
        raise BundleMiss("tweak produced infinity")
    return tweaked[0].to_bytes(32, "big")


def output_commits(internal_xonly: bytes, bundle: bytes, output_xonly: bytes) -> bool:
    try:
        return tweaked_output(internal_xonly, bundle) == xonly(output_xonly)
    except (BundleMiss, ValueError):
        return False


def file_opens(internal_xonly: bytes, file_bytes: bytes, output_xonly: bytes) -> bool:
    """True only if these exact bytes reproduce the spent seal key."""
    return output_commits(internal_xonly, file_bundle(file_bytes), output_xonly)


def main() -> None:
    internal = bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    body = b"pouch-VA-00421"
    bundle = file_bundle(body)
    output = tweaked_output(internal, bundle)
    if not file_opens(internal, body, output):
        raise SystemExit("file did not reproduce its seal key")
    if file_opens(internal, body + b"\x00", output):
        raise SystemExit("altered file reproduced the seal key")
    if output_commits(internal, bytes(32), output):
        raise SystemExit("unrelated bundle reproduced the seal key")
    try:
        tweaked_output(internal, b"\x11" * 31)
    except BundleMiss:
        pass
    else:
        raise SystemExit("short bundle accepted")
    print("bundle tweak ok")
    print("output", output.hex())


if __name__ == "__main__":
    main()
