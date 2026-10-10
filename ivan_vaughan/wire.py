"""Binary-safe wire and storage format using CBOR.

Never JSON for signature bytes. All serialization flows through here.
"""

from __future__ import annotations

import cbor2
from typing import Any


def encode(obj: dict[str, Any]) -> bytes:
    """Encode to CBOR. Keys are strings, values may be bytes or primitives."""
    return cbor2.dumps(obj, canonical=True)


def decode(data: bytes) -> dict[str, Any]:
    """Decode from CBOR."""
    return cbor2.loads(data)


def length_prefix(data: bytes) -> bytes:
    """4-byte big-endian length prefix."""
    if len(data) > 0xFFFFFFFF:
        raise ValueError("data too large for length prefix")
    return len(data).to_bytes(4, "big") + data


def read_length_prefixed(data: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Read a length-prefixed chunk. Returns (chunk, new_offset)."""
    if offset + 4 > len(data):
        raise ValueError("truncated length prefix")
    length = int.from_bytes(data[offset : offset + 4], "big")
    if offset + 4 + length > len(data):
        raise ValueError("truncated data")
    return data[offset + 4 : offset + 4 + length], offset + 4 + length
