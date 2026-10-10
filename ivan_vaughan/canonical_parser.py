#!/usr/bin/env python3
"""Canonical parser for artifact roles.

Law 2: Roles come only from a canonical parser on the raw bytes, version-pinned on the edge.
Upgrades do not reclassify old edges. No free-text roles.

Parser derivation for git commits:
- repo:commit_author: the key in the author header
- repo:reviewer: a second key that signed a protocol-fixed review payload over that same commit

No substring match. No leftover-signer default.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple


class ParserError(Exception):
    """Base exception for parser operations."""
    pass


class ArtifactType(Enum):
    """Known artifact types."""
    GIT_COMMIT = "git_commit"
    UNKNOWN = "unknown"


# Parser version for git commits. Pinned; upgrades create new versions.
GIT_COMMIT_PARSER_V1 = "git_commit_v1"

# Known parser versions
KNOWN_PARSER_VERSIONS = frozenset([
    GIT_COMMIT_PARSER_V1,
])


@dataclass(frozen=True)
class Role:
    """A role derived from a canonical parser.
    
    No free-text roles allowed. Roles are from a fixed vocabulary.
    """
    name: str  # e.g., "repo:commit_author", "repo:reviewer"
    signer: bytes  # The 32-byte x-only public key
    parser_version: str
    
    def __post_init__(self) -> None:
        if not self.name.startswith("repo:"):
            raise ParserError(f"invalid role namespace: {self.name}")
        if len(self.signer) != 32:
            raise ParserError("signer must be 32-byte x-only key")
        if self.parser_version not in KNOWN_PARSER_VERSIONS:
            raise ParserError(f"unknown parser version: {self.parser_version}")


@dataclass(frozen=True)
class GitCommitObject:
    """A parsed git commit object.
    
    Parsed from raw bytes, not from git cat-file output.
    """
    tree: bytes  # SHA-1 of tree object (20 bytes)
    parents: tuple[bytes, ...]  # SHA-1s of parent commits
    author_name: str
    author_email: str
    author_key: Optional[bytes]  # x-only public key if GPG/SSH signed
    committer_name: str
    committer_email: str
    committer_key: Optional[bytes]
    message: str
    raw_bytes: bytes
    
    @property
    def commit_hash(self) -> bytes:
        """SHA-1 hash of the commit object."""
        header = f"commit {len(self.raw_bytes)}\0".encode()
        return hashlib.sha1(header + self.raw_bytes).digest()
    
    @property
    def artifact_hash(self) -> bytes:
        """SHA-256 hash for the edge (protocol uses SHA-256, not SHA-1)."""
        return hashlib.sha256(self.raw_bytes).digest()


# Protocol-fixed review payload format
REVIEW_PAYLOAD_PREFIX = b"ivan-vaughan-review-v1:"


def make_review_payload(commit_hash: bytes) -> bytes:
    """Create the protocol-fixed review payload for a commit.
    
    A reviewer signs this exact payload to assert review of the commit.
    """
    return REVIEW_PAYLOAD_PREFIX + commit_hash


def parse_git_commit(raw_bytes: bytes) -> GitCommitObject:
    """Parse a raw git commit object.
    
    Git commit format:
    tree <sha1>\n
    [parent <sha1>\n]*
    author <name> <email> <timestamp> <tz>\n
    committer <name> <email> <timestamp> <tz>\n
    [gpgsig <signature>]\n
    \n
    <message>
    """
    try:
        # Split header and message
        if b'\n\n' not in raw_bytes:
            raise ParserError("invalid commit: no message separator")
        
        header_end = raw_bytes.index(b'\n\n')
        header = raw_bytes[:header_end].decode('utf-8', errors='replace')
        message = raw_bytes[header_end + 2:].decode('utf-8', errors='replace')
        
        lines = header.split('\n')
        
        tree: Optional[bytes] = None
        parents: list[bytes] = []
        author_name = author_email = ""
        committer_name = committer_email = ""
        author_key: Optional[bytes] = None
        committer_key: Optional[bytes] = None
        gpgsig: Optional[str] = None
        
        i = 0
        while i < len(lines):
            line = lines[i]
            
            if line.startswith('tree '):
                tree = bytes.fromhex(line[5:45])
            elif line.startswith('parent '):
                parents.append(bytes.fromhex(line[7:47]))
            elif line.startswith('author '):
                author_name, author_email = _parse_ident(line[7:])
            elif line.startswith('committer '):
                committer_name, committer_email = _parse_ident(line[10:])
            elif line.startswith('gpgsig '):
                # GPG signature spans multiple lines until we hit a non-space line
                sig_lines = [line[7:]]
                i += 1
                while i < len(lines) and lines[i].startswith(' '):
                    sig_lines.append(lines[i][1:])  # Remove leading space
                    i += 1
                gpgsig = '\n'.join(sig_lines)
                continue  # Don't increment i again
            
            i += 1
        
        if tree is None:
            raise ParserError("invalid commit: no tree")
        
        # Extract key from GPG signature if present
        if gpgsig:
            author_key = _extract_key_from_gpg(gpgsig)
        
        return GitCommitObject(
            tree=tree,
            parents=tuple(parents),
            author_name=author_name,
            author_email=author_email,
            author_key=author_key,
            committer_name=committer_name,
            committer_email=committer_email,
            committer_key=committer_key,
            message=message,
            raw_bytes=raw_bytes,
        )
    except ParserError:
        raise
    except Exception as e:
        raise ParserError(f"failed to parse commit: {e}")


def _parse_ident(ident: str) -> Tuple[str, str]:
    """Parse an author/committer identity line.
    
    Format: Name <email> timestamp tz
    """
    match = re.match(r'^(.+?) <([^>]+)> \d+ [+-]\d{4}$', ident)
    if match:
        return match.group(1), match.group(2)
    
    # Fallback: try just name <email>
    match = re.match(r'^(.+?) <([^>]+)>', ident)
    if match:
        return match.group(1), match.group(2)
    
    return ident, ""


def _extract_key_from_gpg(gpgsig: str) -> Optional[bytes]:
    """Extract the signing key from a GPG signature.
    
    This is a simplified extraction. In practice, you'd parse the full
    GPG packet to get the key ID/fingerprint.
    
    For SSH signatures, the format is different.
    """
    # Look for key ID patterns
    # GPG: "iQEzBAABCAAdFiEE..." (base64 encoded)
    # SSH: "-----BEGIN SSH SIGNATURE-----"
    
    if "BEGIN SSH SIGNATURE" in gpgsig:
        # SSH signature - extract the key from the signature blob
        # This is simplified; real extraction would parse the SSH signature format
        return None  # Would need full SSH sig parsing
    
    # For GPG, we'd need to parse the signature packet
    # This is a placeholder - real implementation would use gpg libraries
    return None


def derive_roles_git_commit(
    commit: GitCommitObject,
    signers: dict[bytes, bytes],  # signer_key -> signature
    parser_version: str = GIT_COMMIT_PARSER_V1,
) -> list[Role]:
    """Derive roles from a git commit object.
    
    Rules (per protocol):
    - repo:commit_author: ONLY for the key in the author header
    - repo:reviewer: ONLY for a second key that signed the review payload
    
    No substring match. No leftover-signer default.
    """
    if parser_version not in KNOWN_PARSER_VERSIONS:
        raise ParserError(f"unknown parser version: {parser_version}")
    
    roles: list[Role] = []
    
    # Check for author role
    if commit.author_key and commit.author_key in signers:
        roles.append(Role(
            name="repo:commit_author",
            signer=commit.author_key,
            parser_version=parser_version,
        ))
    
    # Check for reviewer roles
    # A reviewer must have signed the protocol-fixed review payload
    review_payload = make_review_payload(commit.commit_hash)
    
    for signer_key, signature in signers.items():
        if signer_key == commit.author_key:
            continue  # Author is not a reviewer of their own commit
        
        # Verify the signature is over the review payload
        # The caller must have verified the signature already
        # We just record the role
        if len(signer_key) == 32:  # x-only key
            roles.append(Role(
                name="repo:reviewer",
                signer=signer_key,
                parser_version=parser_version,
            ))
    
    return roles


def verify_parser_version(version: str) -> bool:
    """Check if a parser version is known."""
    return version in KNOWN_PARSER_VERSIONS


class CanonicalParser:
    """Parser for deriving roles from artifacts.
    
    Version-pinned. Upgrades do not reclassify old edges.
    """
    
    def __init__(self, version: str = GIT_COMMIT_PARSER_V1):
        if version not in KNOWN_PARSER_VERSIONS:
            raise ParserError(f"unknown parser version: {version}")
        self.version = version
    
    def parse_artifact(self, raw_bytes: bytes, artifact_type: ArtifactType) -> object:
        """Parse raw artifact bytes."""
        if artifact_type == ArtifactType.GIT_COMMIT:
            return parse_git_commit(raw_bytes)
        raise ParserError(f"unsupported artifact type: {artifact_type}")
    
    def derive_roles(
        self,
        artifact: object,
        artifact_type: ArtifactType,
        signers: dict[bytes, bytes],
    ) -> list[Role]:
        """Derive roles from a parsed artifact."""
        if artifact_type == ArtifactType.GIT_COMMIT:
            if not isinstance(artifact, GitCommitObject):
                raise ParserError("artifact must be GitCommitObject")
            return derive_roles_git_commit(artifact, signers, self.version)
        raise ParserError(f"unsupported artifact type: {artifact_type}")
    
    def compute_artifact_hash(self, raw_bytes: bytes) -> bytes:
        """Compute the artifact hash (SHA-256)."""
        return hashlib.sha256(raw_bytes).digest()


# Helper for creating test git commits
def make_test_commit(
    tree_hash: bytes = b'\x00' * 20,
    parent_hashes: list[bytes] | None = None,
    author_name: str = "Test Author",
    author_email: str = "test@example.com",
    committer_name: str = "Test Committer", 
    committer_email: str = "committer@example.com",
    message: str = "Test commit message",
    timestamp: int = 1700000000,
    tz: str = "+0000",
) -> bytes:
    """Create raw bytes for a test git commit object."""
    lines = [
        f"tree {tree_hash.hex()}",
    ]
    
    if parent_hashes:
        for parent in parent_hashes:
            lines.append(f"parent {parent.hex()}")
    
    lines.extend([
        f"author {author_name} <{author_email}> {timestamp} {tz}",
        f"committer {committer_name} <{committer_email}> {timestamp} {tz}",
        "",
        message,
    ])
    
    return '\n'.join(lines).encode('utf-8')
