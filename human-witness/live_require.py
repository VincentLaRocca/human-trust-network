#!/usr/bin/env python3
"""Objective require for consider().

This is the BIP-340 check. It is not a signer-set lookup. The witness set is
the one on the custody schema. schema_encoder.WitnessSet.require verifies a
64-byte Schnorr signature over the operation id and enforces the threshold.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "personal-chains"))

from schema_encoder import Reject, WitnessSet  # noqa: E402


def live_require(witnesses: WitnessSet):
    def require(op_id: bytes, sigs: dict[bytes, bytes]) -> None:
        if len(op_id) != 32:
            raise Reject("op id")
        witnesses.require(op_id, sigs)

    return require
