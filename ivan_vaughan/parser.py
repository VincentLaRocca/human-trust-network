"""Canonical parser for git commit objects. (Law 2)

Version-pinned. Roles come only from this parser on raw bytes.
Upgrades do not reclassify old edges. No free-text roles.

Yields:
- repo:commit_author for the key in the author header
- repo:reviewer for a second key that signed a protocol-fixed review payload

No substring matching. No default role for leftover signers.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .keys import NodeKey, verify_signature


PARSER_VERSION = 1


class Role(Enum):
    COMMIT_AUTHOR = "repo:commit_author"
    REVIEWER = "repo:reviewer"


@dataclass(frozen=True)
class ParsedRole:
    role: Role
    key: NodeKey
    parser_version: int

    def __post_init__(self) -> None:
        if self.parser_version != PARSER_VERSION:
            raise ValueError(f"Parser version mismatch: {self.parser_version} != {PARSER_VERSION}")


@dataclass(frozen=True)
class ReviewPayload:
    """Protocol-fixed review payload structure."""

    commit_hash: bytes  # SHA-256 of the raw commit object
    reviewer_key: NodeKey
    approval: bool  # True = approved, False = reviewed-without-approval

    def canonical_bytes(self) -> bytes:
        """Canonical bytes for signing."""
        approval_byte = b"\x01" if self.approval else b"\x00"
        return (
            b"IVAN_VAUGHAN_REVIEW_V1:"
            + self.commit_hash
            + self.reviewer_key.public_bytes
            + approval_byte
        )


@dataclass
class GitCommitParse:
    """Result of parsing a git commit object."""

    raw_bytes: bytes
    commit_hash: bytes  # SHA-256 of raw bytes
    author_key: Optional[NodeKey]  # Extracted from author header or signature
    author_signature: Optional[bytes]  # Signature over the commit
    review_signatures: list[tuple[NodeKey, bytes, bool]]  # (key, sig, approval)
    parser_version: int

    @property
    def roles(self) -> list[ParsedRole]:
        """Extract roles according to protocol rules."""
        result: list[ParsedRole] = []

        if self.author_key is not None and self.author_signature is not None:
            if verify_signature(self.author_key, self.commit_hash, self.author_signature):
                result.append(ParsedRole(Role.COMMIT_AUTHOR, self.author_key, self.parser_version))

        for key, sig, approval in self.review_signatures:
            if key == self.author_key:
                continue
            payload = ReviewPayload(self.commit_hash, key, approval)
            if verify_signature(key, payload.canonical_bytes(), sig):
                result.append(ParsedRole(Role.REVIEWER, key, self.parser_version))

        return result


def extract_author_key_from_header(raw: bytes) -> Optional[tuple[bytes, str]]:
    """Extract author public key from commit header if present.

    Looks for a header line: author-key <algorithm> <hex-encoded-public-key>
    """
    lines = raw.split(b"\n")
    for line in lines:
        if line.startswith(b"author-key "):
            parts = line[11:].split(b" ", 1)
            if len(parts) == 2:
                try:
                    algorithm = parts[0].decode("ascii")
                    key_bytes = bytes.fromhex(parts[1].decode("ascii"))
                    return key_bytes, algorithm
                except (ValueError, UnicodeDecodeError):
                    continue
    return None


def extract_signature_from_header(raw: bytes) -> Optional[bytes]:
    """Extract author signature from commit header if present.

    Looks for: author-sig <hex-encoded-signature>
    """
    lines = raw.split(b"\n")
    for line in lines:
        if line.startswith(b"author-sig "):
            try:
                return bytes.fromhex(line[11:].decode("ascii").strip())
            except (ValueError, UnicodeDecodeError):
                continue
    return None


def extract_review_block(raw: bytes) -> list[tuple[bytes, str, bytes, bool]]:
    """Extract review signatures from commit trailer.

    Looks for blocks:
    review-key <algorithm> <hex-key>
    review-sig <hex-signature>
    review-approval <1|0>
    """
    reviews: list[tuple[bytes, str, bytes, bool]] = []
    lines = raw.split(b"\n")

    i = 0
    while i < len(lines):
        if lines[i].startswith(b"review-key "):
            try:
                parts = lines[i][11:].split(b" ", 1)
                algorithm = parts[0].decode("ascii")
                key_bytes = bytes.fromhex(parts[1].decode("ascii").strip())

                if i + 1 < len(lines) and lines[i + 1].startswith(b"review-sig "):
                    sig = bytes.fromhex(lines[i + 1][11:].decode("ascii").strip())

                    approval = True  # Default to approved
                    if i + 2 < len(lines) and lines[i + 2].startswith(b"review-approval "):
                        approval = lines[i + 2][16:].strip() == b"1"
                        i += 3
                    else:
                        i += 2

                    reviews.append((key_bytes, algorithm, sig, approval))
                    continue
            except (ValueError, UnicodeDecodeError, IndexError):
                pass
        i += 1

    return reviews


def parse_git_commit(raw: bytes) -> GitCommitParse:
    """Parse a git commit object and extract roles.

    Version-pinned parser. Does not use substring matching.
    """
    commit_hash = hashlib.sha256(raw).digest()

    author_key: Optional[NodeKey] = None
    author_signature: Optional[bytes] = None
    review_signatures: list[tuple[NodeKey, bytes, bool]] = []

    key_data = extract_author_key_from_header(raw)
    if key_data:
        key_bytes, algorithm = key_data
        try:
            author_key = NodeKey(key_bytes, algorithm)
        except ValueError:
            pass

    sig_data = extract_signature_from_header(raw)
    if sig_data:
        author_signature = sig_data

    review_blocks = extract_review_block(raw)
    for key_bytes, algorithm, sig, approval in review_blocks:
        try:
            key = NodeKey(key_bytes, algorithm)
            review_signatures.append((key, sig, approval))
        except ValueError:
            continue

    return GitCommitParse(
        raw_bytes=raw,
        commit_hash=commit_hash,
        author_key=author_key,
        author_signature=author_signature,
        review_signatures=review_signatures,
        parser_version=PARSER_VERSION,
    )


def roles_from_artifact(artifact_bytes: bytes, artifact_type: str = "git_commit") -> list[ParsedRole]:
    """Get roles from an artifact. Only git_commit is supported in v1."""
    if artifact_type != "git_commit":
        return []  # Unknown artifact type yields no roles
    return parse_git_commit(artifact_bytes).roles


def validate_parser_version(version: int) -> bool:
    """Check if a parser version is known."""
    return version == PARSER_VERSION
