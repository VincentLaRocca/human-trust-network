"""Strict schema for public events.

The privacy rule: public events carry only hashes, job ids, public keys and a
few small enumerations/numbers. Anything not listed here is rejected, so client
data (names, addresses, contents) has nowhere to go.
"""
from __future__ import annotations

import re

from . import events as ev

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
JOB_ID = HEX64  # SHA-256(nonce || agreed terms); see events.make_job_id
UINT = re.compile(r"^(0|[1-9][0-9]{0,15})$")
OUTCOME = re.compile(r"^(upheld|rejected|withdrawn)$")
SCOPE = re.compile(r"^[a-z_]{1,32}(,[a-z_]{1,32}){0,15}$")  # comma-separated record kinds

TOP_LEVEL = frozenset({"id", "pubkey", "created_at", "kind", "tags", "content", "sig"})

# Tag key -> (value pattern, required). "p:<role>" means ["p", <pubkey>, <role>].
SCHEMAS: dict[int, dict[str, tuple[re.Pattern, bool]]] = {
    ev.JOB_OFFER: {        # signed by the client
        "job": (JOB_ID, True),
        "p:worker": (HEX64, True),
        "p:recipient": (HEX64, False),
    },
    ev.JOB_ACCEPTED: {       # signed by the worker
        "job": (JOB_ID, True),
        "e": (HEX64, True),           # job_offer event id
    },
    ev.HANDOFF: {            # signed by the current holder
        "job": (JOB_ID, True),
        "e": (HEX64, True),           # job_offer event id
        "p:to": (HEX64, True),
        "item": (HEX64, True),        # salted hash of the item/seal manifest
        "seq": (UINT, True),
    },
    ev.COMPLETION: {         # signed by the counterparty (client or recipient)
        "job": (JOB_ID, True),
        "e": (HEX64, True),           # job_offer event id
        "p:worker": (HEX64, True),
        "receipt": (HEX64, True),     # salted hash of the private receipt
        "payment": (HEX64, False),    # hold-invoice payment hash (never the secret)
    },
    ev.DISPUTE_FILED: {      # signed by the counterparty (client or recipient)
        "job": (JOB_ID, True),
        "e": (HEX64, True),           # job_offer event id
        "p:worker": (HEX64, True),
        "reason": (HEX64, True),      # salted hash of the private complaint
    },
    ev.DISPUTE_RESOLVED: {   # signed by the acting arbiter, or the filer (withdraw)
        "job": (JOB_ID, True),
        "e": (HEX64, True),           # dispute_filed event id
        "outcome": (OUTCOME, True),
        "ruling": (HEX64, False),     # salted hash of the written ruling
    },
    ev.VOUCH_ISSUED: {       # signed by the voucher
        "job": (JOB_ID, True),
        "e": (HEX64, True),           # job_offer event id
        "p:worker": (HEX64, True),
        "amount": (UINT, True),       # bond size in sats
        "bond": (HEX64, False),       # funding txid of the Taproot bond
        "bondkey": (HEX64, False),    # the bond's own fresh public key (required with bond)
    },
    ev.VOUCH_CLEARED: {      # signed by the voucher
        "job": (JOB_ID, True),
        "e": (HEX64, True),           # vouch_issued event id
    },
    ev.ONBOARD: {            # signed by the operator's first operational key
        "recovery": (HEX64, True),    # SHA-256 of the recovery public key
    },
    ev.ROTATE: {             # signed by the operator's current operational key
        "op": (HEX64, True),          # operator id (= onboarding event id)
        "p:new": (HEX64, True),
    },
    ev.RECOVER: {            # signed by the operator's recovery key
        "op": (HEX64, True),
        "p:new": (HEX64, False),      # replacement key; omit to revoke only
        "since": (UINT, True),        # keys held from this time on are compromised
    },
    ev.DELEGATE: {           # signed by the operator's current operational key
        "op": (HEX64, True),
        "p:agent": (HEX64, True),
        "scope": (SCOPE, True),       # e.g. "job_accepted,handoff"
        "expires": (UINT, False),
    },
    ev.AGENT_REVOKE: {       # signed by the current operational key or the recovery key
        "op": (HEX64, True),
        "p:agent": (HEX64, True),
    },
}


class SchemaError(ValueError):
    pass


def _tag_key(tag) -> str:
    if not isinstance(tag, list) or not all(isinstance(x, str) for x in tag):
        raise SchemaError("each tag must be a list of strings")
    if not tag:
        raise SchemaError("empty tag")
    if tag[0] == "p":
        if len(tag) != 3:
            raise SchemaError('p tags must be ["p", <pubkey>, <role>]')
        return f"p:{tag[2]}"
    if len(tag) != 2:
        raise SchemaError(f"tag {tag[0]!r} must have exactly one value")
    return tag[0]


def validate(event) -> None:
    """Raise SchemaError if the event has any field outside the allowed schema."""
    if not isinstance(event, dict):
        raise SchemaError("event must be an object")
    keys = set(event)
    if keys != TOP_LEVEL:
        extra, missing = keys - TOP_LEVEL, TOP_LEVEL - keys
        raise SchemaError(f"top-level fields wrong (extra={sorted(extra)}, missing={sorted(missing)})")
    if not isinstance(event["id"], str) or not HEX64.match(event["id"]):
        raise SchemaError("id must be 64 lowercase hex chars")
    if not isinstance(event["pubkey"], str) or not HEX64.match(event["pubkey"]):
        raise SchemaError("pubkey must be 64 lowercase hex chars")
    if not isinstance(event["sig"], str) or not HEX128.match(event["sig"]):
        raise SchemaError("sig must be 128 lowercase hex chars")
    ts = event["created_at"]
    if not isinstance(ts, int) or isinstance(ts, bool) or not 0 < ts < 2**32:
        raise SchemaError("created_at must be a positive unix timestamp")
    kind = event["kind"]
    if not isinstance(kind, int) or isinstance(kind, bool) or kind not in SCHEMAS:
        raise SchemaError(f"unknown event kind {kind!r}")
    if event["content"] != "":
        raise SchemaError("content must be empty; all data goes in tags")
    if not isinstance(event["tags"], list):
        raise SchemaError("tags must be a list")

    spec = SCHEMAS[kind]
    seen: dict[str, str] = {}
    for tag in event["tags"]:
        key = _tag_key(tag)
        if key not in spec:
            raise SchemaError(f"tag {key!r} not allowed on {ev.KIND_NAMES[kind]}")
        if key in seen:
            raise SchemaError(f"duplicate tag {key!r}")
        pattern, _ = spec[key]
        if not pattern.match(tag[1]):
            raise SchemaError(f"tag {key!r} has an invalid value")
        seen[key] = tag[1]
    for key, (_, required) in spec.items():
        if required and key not in seen:
            raise SchemaError(f"missing required tag {key!r} on {ev.KIND_NAMES[kind]}")


def tag_values(event: dict) -> dict[str, str]:
    """Tags as {key: value}. Call only on events that passed validate()."""
    return {_tag_key(t): t[1] for t in event["tags"]}
