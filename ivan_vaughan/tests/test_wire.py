"""Tests for binary-safe wire format (CBOR)."""

import os
import pytest

from ivan_vaughan.wire import encode, decode, length_prefix, read_length_prefixed


class TestCBOREncoding:
    """Tests for CBOR encoding."""

    def test_encode_decode_roundtrip(self):
        """Data survives CBOR roundtrip."""
        data = {
            "string": "hello",
            "bytes": b"\x00\x01\x02\xff",
            "number": 42,
            "list": [1, 2, 3],
        }
        encoded = encode(data)
        decoded = decode(encoded)

        assert decoded["string"] == data["string"]
        assert decoded["bytes"] == data["bytes"]
        assert decoded["number"] == data["number"]
        assert decoded["list"] == data["list"]

    def test_binary_bytes_preserved(self):
        """Binary bytes are preserved exactly (no JSON corruption)."""
        # This specifically tests the requirement to avoid JSON
        binary = os.urandom(64)
        data = {"signature": binary}

        encoded = encode(data)
        decoded = decode(encoded)

        assert decoded["signature"] == binary

    def test_all_byte_values(self):
        """All 256 byte values are preserved."""
        all_bytes = bytes(range(256))
        data = {"all": all_bytes}

        encoded = encode(data)
        decoded = decode(encoded)

        assert decoded["all"] == all_bytes

    def test_no_json_in_output(self):
        """Output is not JSON (no curly braces)."""
        data = {"key": "value"}
        encoded = encode(data)

        # CBOR doesn't use { } [ ] as delimiters in the same way
        # First byte of CBOR map is 0xa0-0xbf or 0xbf for indefinite
        assert encoded[0] in range(0xa0, 0xc0) or encoded[0] == 0xbf

    def test_canonical_encoding(self):
        """Encoding is canonical (deterministic)."""
        data = {"z": 1, "a": 2, "m": 3}

        encoded1 = encode(data)
        encoded2 = encode(data)

        assert encoded1 == encoded2


class TestLengthPrefix:
    """Tests for length-prefixed encoding."""

    def test_length_prefix_format(self):
        """Length prefix is 4-byte big-endian."""
        data = b"hello"
        prefixed = length_prefix(data)

        assert len(prefixed) == 4 + len(data)
        assert prefixed[:4] == (5).to_bytes(4, "big")
        assert prefixed[4:] == data

    def test_read_length_prefixed(self):
        """Read length-prefixed data correctly."""
        data = b"world"
        prefixed = length_prefix(data)

        chunk, offset = read_length_prefixed(prefixed, 0)
        assert chunk == data
        assert offset == len(prefixed)

    def test_multiple_prefixed_chunks(self):
        """Read multiple length-prefixed chunks."""
        chunk1 = b"first"
        chunk2 = b"second"
        combined = length_prefix(chunk1) + length_prefix(chunk2)

        c1, offset = read_length_prefixed(combined, 0)
        c2, offset = read_length_prefixed(combined, offset)

        assert c1 == chunk1
        assert c2 == chunk2

    def test_truncated_prefix_raises(self):
        """Truncated length prefix raises."""
        with pytest.raises(ValueError, match="truncated"):
            read_length_prefixed(b"\x00\x00", 0)

    def test_truncated_data_raises(self):
        """Truncated data raises."""
        prefixed = length_prefix(b"hello")
        truncated = prefixed[:-2]

        with pytest.raises(ValueError, match="truncated"):
            read_length_prefixed(truncated, 0)

    def test_empty_data(self):
        """Empty data is valid."""
        prefixed = length_prefix(b"")
        chunk, offset = read_length_prefixed(prefixed, 0)
        assert chunk == b""


class TestSignaturePreservation:
    """Tests specifically for signature byte preservation."""

    def test_ed25519_signature_preserved(self):
        """Ed25519-sized signature (64 bytes) preserved."""
        sig = os.urandom(64)
        data = {"sig": sig}

        for _ in range(100):
            encoded = encode(data)
            decoded = decode(encoded)
            assert decoded["sig"] == sig

    def test_es256_signature_preserved(self):
        """ES256-sized signature (64-72 bytes) preserved."""
        for size in [64, 70, 72]:
            sig = os.urandom(size)
            data = {"sig": sig}
            decoded = decode(encode(data))
            assert decoded["sig"] == sig

    def test_nested_signatures_preserved(self):
        """Nested structure with signatures preserved."""
        sig_a = os.urandom(64)
        sig_b = os.urandom(64)
        nonce_a = os.urandom(32)
        nonce_b = os.urandom(32)

        data = {
            "edge": {
                "sig_a": {"signature": sig_a, "nonce": nonce_a},
                "sig_b": {"signature": sig_b, "nonce": nonce_b},
            }
        }

        decoded = decode(encode(data))
        assert decoded["edge"]["sig_a"]["signature"] == sig_a
        assert decoded["edge"]["sig_b"]["signature"] == sig_b
        assert decoded["edge"]["sig_a"]["nonce"] == nonce_a
        assert decoded["edge"]["sig_b"]["nonce"] == nonce_b
