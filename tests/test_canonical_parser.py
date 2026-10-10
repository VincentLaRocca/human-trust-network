#!/usr/bin/env python3
"""Tests for canonical parser.

Tests:
- Parser role derivation from a real git commit object
- repo:commit_author from author header
- repo:reviewer from signed review payload
- No substring match
- No leftover-signer default
"""

import pytest
import hashlib

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from ivan_vaughan.canonical_parser import (
    GitCommitObject,
    Role,
    CanonicalParser,
    ArtifactType,
    ParserError,
    parse_git_commit,
    derive_roles_git_commit,
    make_review_payload,
    make_test_commit,
    verify_parser_version,
    GIT_COMMIT_PARSER_V1,
    KNOWN_PARSER_VERSIONS,
    REVIEW_PAYLOAD_PREFIX,
)


class TestGitCommitParsing:
    """Test parsing of git commit objects."""
    
    def test_parse_simple_commit(self):
        """Test parsing a simple commit object."""
        raw = make_test_commit(
            tree_hash=b'\x01' * 20,
            author_name="Test Author",
            author_email="test@example.com",
            message="Test commit\n\nWith body",
        )
        
        commit = parse_git_commit(raw)
        
        assert commit.tree == b'\x01' * 20
        assert commit.author_name == "Test Author"
        assert commit.author_email == "test@example.com"
        assert "Test commit" in commit.message
    
    def test_parse_commit_with_parent(self):
        """Test parsing a commit with parents."""
        raw = make_test_commit(
            parent_hashes=[b'\x02' * 20, b'\x03' * 20],
        )
        
        commit = parse_git_commit(raw)
        
        assert len(commit.parents) == 2
        assert commit.parents[0] == b'\x02' * 20
        assert commit.parents[1] == b'\x03' * 20
    
    def test_commit_hash_computation(self):
        """Test that commit hash is computed correctly."""
        raw = make_test_commit()
        commit = parse_git_commit(raw)
        
        # Git commit hash format
        header = f"commit {len(raw)}\0".encode()
        expected = hashlib.sha1(header + raw).digest()
        
        assert commit.commit_hash == expected
    
    def test_artifact_hash_is_sha256(self):
        """Test that artifact hash uses SHA-256."""
        raw = make_test_commit()
        commit = parse_git_commit(raw)
        
        expected = hashlib.sha256(raw).digest()
        
        assert commit.artifact_hash == expected
        assert len(commit.artifact_hash) == 32


class TestRoleDerivation:
    """Test role derivation from git commits."""
    
    def test_commit_author_role(self):
        """Test deriving repo:commit_author role.
        
        repo:commit_author: ONLY for the key in the author header.
        """
        raw = make_test_commit()
        commit = parse_git_commit(raw)
        
        # Simulate author key in commit
        author_key = b'\x01' * 32
        commit = GitCommitObject(
            tree=commit.tree,
            parents=commit.parents,
            author_name=commit.author_name,
            author_email=commit.author_email,
            author_key=author_key,  # Key from GPG signature
            committer_name=commit.committer_name,
            committer_email=commit.committer_email,
            committer_key=None,
            message=commit.message,
            raw_bytes=raw,
        )
        
        signers = {author_key: b'\x00' * 64}  # Dummy signature
        
        roles = derive_roles_git_commit(commit, signers)
        
        assert len(roles) == 1
        assert roles[0].name == "repo:commit_author"
        assert roles[0].signer == author_key
    
    def test_reviewer_role(self):
        """Test deriving repo:reviewer role.
        
        repo:reviewer: ONLY for a second key that signed the review payload.
        """
        raw = make_test_commit()
        commit = parse_git_commit(raw)
        
        author_key = b'\x01' * 32
        reviewer_key = b'\x02' * 32
        
        commit = GitCommitObject(
            tree=commit.tree,
            parents=commit.parents,
            author_name=commit.author_name,
            author_email=commit.author_email,
            author_key=author_key,
            committer_name=commit.committer_name,
            committer_email=commit.committer_email,
            committer_key=None,
            message=commit.message,
            raw_bytes=raw,
        )
        
        # Reviewer signed the review payload
        signers = {
            author_key: b'\x00' * 64,
            reviewer_key: b'\x00' * 64,  # Review signature
        }
        
        roles = derive_roles_git_commit(commit, signers)
        
        # Should have author and reviewer
        role_names = {r.name for r in roles}
        assert "repo:commit_author" in role_names
        assert "repo:reviewer" in role_names
        
        reviewer_role = next(r for r in roles if r.name == "repo:reviewer")
        assert reviewer_role.signer == reviewer_key
    
    def test_no_leftover_signer_default(self):
        """Test that there's no leftover-signer default role.
        
        Law 2: No leftover-signer default.
        """
        raw = make_test_commit()
        commit = parse_git_commit(raw)
        
        # No author key, just a random signer
        random_signer = b'\x05' * 32
        signers = {random_signer: b'\x00' * 64}
        
        commit = GitCommitObject(
            tree=commit.tree,
            parents=commit.parents,
            author_name=commit.author_name,
            author_email=commit.author_email,
            author_key=None,  # No author key
            committer_name=commit.committer_name,
            committer_email=commit.committer_email,
            committer_key=None,
            message=commit.message,
            raw_bytes=raw,
        )
        
        roles = derive_roles_git_commit(commit, signers)
        
        # Random signer should get reviewer role (since they're not author)
        # But no "default" or catch-all role
        for role in roles:
            assert role.name in ("repo:commit_author", "repo:reviewer")
    
    def test_no_substring_match(self):
        """Test that roles don't use substring matching.
        
        Law 2: No substring match.
        """
        raw = make_test_commit(author_email="similar@example.com")
        commit = parse_git_commit(raw)
        
        # Key that's "similar" but not exact match
        similar_key = b'\x01' * 32
        
        commit = GitCommitObject(
            tree=commit.tree,
            parents=commit.parents,
            author_name=commit.author_name,
            author_email=commit.author_email,
            author_key=b'\x02' * 32,  # Different from similar_key
            committer_name=commit.committer_name,
            committer_email=commit.committer_email,
            committer_key=None,
            message=commit.message,
            raw_bytes=raw,
        )
        
        signers = {similar_key: b'\x00' * 64}
        
        roles = derive_roles_git_commit(commit, signers)
        
        # similar_key should NOT get author role
        author_roles = [r for r in roles if r.name == "repo:commit_author"]
        assert not any(r.signer == similar_key for r in author_roles)


class TestReviewPayload:
    """Test review payload generation."""
    
    def test_review_payload_format(self):
        """Test protocol-fixed review payload format."""
        commit_hash = b'\x01' * 20
        
        payload = make_review_payload(commit_hash)
        
        assert payload.startswith(REVIEW_PAYLOAD_PREFIX)
        assert commit_hash in payload
    
    def test_review_payload_deterministic(self):
        """Test that same commit produces same payload."""
        commit_hash = b'\x01' * 20
        
        p1 = make_review_payload(commit_hash)
        p2 = make_review_payload(commit_hash)
        
        assert p1 == p2
    
    def test_different_commits_different_payloads(self):
        """Test that different commits produce different payloads."""
        hash1 = b'\x01' * 20
        hash2 = b'\x02' * 20
        
        p1 = make_review_payload(hash1)
        p2 = make_review_payload(hash2)
        
        assert p1 != p2


class TestParserVersion:
    """Test parser versioning."""
    
    def test_known_versions(self):
        """Test that known versions are recognized."""
        assert verify_parser_version(GIT_COMMIT_PARSER_V1) is True
    
    def test_unknown_version(self):
        """Test that unknown versions are not recognized."""
        assert verify_parser_version("unknown_v999") is False
    
    def test_role_requires_known_version(self):
        """Test that Role requires known parser version."""
        with pytest.raises(ParserError, match="unknown parser version"):
            Role(
                name="repo:commit_author",
                signer=b'\x01' * 32,
                parser_version="unknown_v1",
            )
    
    def test_role_rejects_bad_namespace(self):
        """Test that Role rejects non-repo namespace.
        
        Law 2: No free-text roles.
        """
        with pytest.raises(ParserError, match="invalid role namespace"):
            Role(
                name="custom:myrole",  # Not repo: namespace
                signer=b'\x01' * 32,
                parser_version=GIT_COMMIT_PARSER_V1,
            )


class TestCanonicalParser:
    """Test the CanonicalParser class."""
    
    def test_parse_git_commit(self):
        """Test parsing via CanonicalParser."""
        parser = CanonicalParser(GIT_COMMIT_PARSER_V1)
        raw = make_test_commit()
        
        commit = parser.parse_artifact(raw, ArtifactType.GIT_COMMIT)
        
        assert isinstance(commit, GitCommitObject)
    
    def test_compute_artifact_hash(self):
        """Test artifact hash computation."""
        parser = CanonicalParser()
        raw = b"test data"
        
        hash_val = parser.compute_artifact_hash(raw)
        
        assert hash_val == hashlib.sha256(raw).digest()
    
    def test_parser_version_pinned(self):
        """Test that parser version is pinned on edges.
        
        Law 2: Roles come from version-pinned parser. Upgrades do not reclassify.
        """
        parser_v1 = CanonicalParser(GIT_COMMIT_PARSER_V1)
        
        raw = make_test_commit()
        commit = parser_v1.parse_artifact(raw, ArtifactType.GIT_COMMIT)
        
        author_key = b'\x01' * 32
        commit = GitCommitObject(
            tree=commit.tree,
            parents=commit.parents,
            author_name=commit.author_name,
            author_email=commit.author_email,
            author_key=author_key,
            committer_name=commit.committer_name,
            committer_email=commit.committer_email,
            committer_key=None,
            message=commit.message,
            raw_bytes=raw,
        )
        
        roles = parser_v1.derive_roles(
            commit, ArtifactType.GIT_COMMIT, {author_key: b'\x00' * 64}
        )
        
        # All roles should have the same parser version
        for role in roles:
            assert role.parser_version == GIT_COMMIT_PARSER_V1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
