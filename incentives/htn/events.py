"""Event kinds and Nostr (NIP-01) event construction, hashing and signing.

An event's id is SHA-256 of the NIP-01 serialization
    [0, pubkey, created_at, kind, tags, content]
and its sig is a BIP340 Schnorr signature over that id.

Kind numbers are PROVISIONAL (see DECISIONS.md) and must be checked against the
Nostr NIP registry before anything is published to public relays.
"""
from __future__ import annotations

import hashlib
import json
import os

from . import keys

JOB_OFFER = 3910
HANDOFF = 3911
COMPLETION = 3912
DISPUTE_FILED = 3913
DISPUTE_RESOLVED = 3914
VOUCH_ISSUED = 3915
VOUCH_CLEARED = 3916
JOB_ACCEPTED = 3917
ONBOARD = 3920
ROTATE = 3921
RECOVER = 3922
DELEGATE = 3923
AGENT_REVOKE = 3924

IDENTITY_KINDS = frozenset({ONBOARD, ROTATE, RECOVER, DELEGATE, AGENT_REVOKE})
# Record kinds an agent may be delegated (never identity records).
AGENT_KINDS = frozenset({3910, 3911, 3912, 3913, 3915, 3916, 3917})

KIND_NAMES = {
    JOB_OFFER: "job_offer",
    HANDOFF: "handoff",
    COMPLETION: "completion",
    DISPUTE_FILED: "dispute_filed",
    DISPUTE_RESOLVED: "dispute_resolved",
    VOUCH_ISSUED: "vouch_issued",
    VOUCH_CLEARED: "vouch_cleared",
    JOB_ACCEPTED: "job_accepted",
    ONBOARD: "onboard",
    ROTATE: "rotate",
    RECOVER: "recover",
    DELEGATE: "delegate",
    AGENT_REVOKE: "agent_revoke",
}


def serialize(pubkey: str, created_at: int, kind: int, tags: list, content: str) -> bytes:
    return json.dumps([0, pubkey, created_at, kind, tags, content],
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_id(event: dict) -> str:
    return hashlib.sha256(serialize(event["pubkey"], event["created_at"], event["kind"],
                                    event["tags"], event["content"])).hexdigest()


def sign_event(key: keys.Key, kind: int, tags: list[list[str]], created_at: int) -> dict:
    """Build and sign an event. Content is always empty: all data lives in tags."""
    event = {"pubkey": key.pubkey, "created_at": created_at, "kind": kind,
             "tags": tags, "content": ""}
    event["id"] = compute_id(event)
    event["sig"] = key.sign(bytes.fromhex(event["id"]))
    return {k: event[k] for k in ("id", "pubkey", "created_at", "kind", "tags", "content", "sig")}


def verify_signature(event: dict) -> bool:
    """True if the id matches the content and the signature is valid for pubkey."""
    try:
        if compute_id(event) != event["id"]:
            return False
        return keys.verify(event["pubkey"], event["sig"], bytes.fromhex(event["id"]))
    except Exception:
        return False


def make_job_id(agreed_terms: bytes) -> tuple[str, str]:
    """Job ID = SHA-256(random nonce || agreed parameters)  (Nucleus section 4).

    The nonce is known only to the parties and never published; with it, the
    parties can later prove which terms a job ID stands for. Returns
    (job_id, nonce_hex).
    """
    return commit(agreed_terms)


def commit(data: bytes) -> tuple[str, str]:
    """Salted hash commitment to private data: SHA-256(salt || data).

    The salt stops anyone guessing short private data (an address, a name) by
    hashing candidates. Returns (hash_hex, salt_hex); keep the salt privately.
    """
    salt = os.urandom(32)
    return hashlib.sha256(salt + data).hexdigest(), salt.hex()


def check_commitment(hash_hex: str, salt_hex: str, data: bytes) -> bool:
    return hashlib.sha256(bytes.fromhex(salt_hex) + data).hexdigest() == hash_hex


def recovery_commitment(pubkey_hex: str) -> str:
    """Published at onboarding: SHA-256 of the recovery key's 32-byte public key.

    The recovery key itself is revealed only when it is first used.
    """
    return hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()
