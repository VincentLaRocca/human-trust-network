"""OpenTimestamps proofs for event hashes.

Only the 32-byte event id (a hash) is ever sent to a calendar, never content.
The default calendar is a local, offline TEST calendar: its proofs are marked
"pending" forever and prove nothing to anyone else. Public calendars are used
only when explicitly asked for (config `timestamps.mode = "public"` or the
`--public` flag).
"""
from __future__ import annotations

import hashlib
import os

from opentimestamps.calendar import RemoteCalendar
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from . import events as ev

PUBLIC_CALENDARS = (
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
)


# The pool addresses above hand out proofs that name these individual servers;
# `upgrade` only ever contacts servers on this list.
TRUSTED_CALENDAR_SERVERS = (
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
    "https://btc.calendar.catallaxy.com",
)


class TimestampError(Exception):
    pass


class LocalTestCalendar:
    """Offline stand-in for a calendar server. TEST ONLY - anchors nothing."""
    URI = "https://local-test-calendar.invalid"

    def __init__(self, anchor_height: int | None = None):
        # anchor_height lets tests simulate a calendar that later reports a block.
        self.anchor_height = anchor_height

    def submit(self, digest: bytes) -> Timestamp:
        ts = Timestamp(digest)
        ts.attestations.add(PendingAttestation(self.URI))
        return ts

    def get_timestamp(self, commitment: bytes) -> Timestamp:
        if self.anchor_height is None:
            raise TimestampError("not anchored yet")
        ts = Timestamp(commitment)
        ts.attestations.add(BitcoinBlockHeaderAttestation(self.anchor_height))
        return ts


def public_calendars() -> list[RemoteCalendar]:
    return [RemoteCalendar(url) for url in PUBLIC_CALENDARS]


def stamp(event_id: str, calendars) -> DetachedTimestampFile:
    """Commit the event id to one or more calendars. Needs at least one to answer."""
    return stamp_digest(bytes.fromhex(event_id), calendars)


def stamp_digest(digest: bytes, calendars) -> DetachedTimestampFile:
    """Timestamp any SHA-256 digest (an event id, or a file's hash)."""
    dtf = DetachedTimestampFile(OpSHA256(), Timestamp(digest))
    # Random nonce (as the standard ots client does) so calendars learn nothing.
    nonced = dtf.timestamp.ops.add(OpAppend(os.urandom(16)))
    commitment = nonced.ops.add(OpSHA256())
    calendars = list(calendars)
    errors = []
    for cal in calendars:
        try:
            commitment.merge(cal.submit(commitment.msg))
        except Exception as e:  # network errors etc.
            errors.append(f"{getattr(cal, 'url', cal)}: {e}")
    if len(errors) == len(calendars):
        raise TimestampError("no calendar accepted the hash: " + "; ".join(errors))
    return dtf


def _nodes(ts: Timestamp):
    yield ts
    for child in ts.ops.values():
        yield from _nodes(child)


def upgrade(dtf: DetachedTimestampFile, calendar_for_uri) -> int:
    """Ask calendars for completed proofs of pending attestations. Returns # upgraded.

    calendar_for_uri(uri) must return a calendar object, or None to skip a
    calendar we don't trust.
    """
    upgraded = 0
    for node in list(_nodes(dtf.timestamp)):
        for att in list(node.attestations):
            if not isinstance(att, PendingAttestation):
                continue
            cal = calendar_for_uri(att.uri)
            if cal is None:
                continue
            try:
                node.merge(cal.get_timestamp(node.msg))
            except Exception:
                continue
            if any(isinstance(a, BitcoinBlockHeaderAttestation) for _, a in node.all_attestations()):
                node.attestations.discard(att)
                upgraded += 1
    return upgraded


def default_calendar_for_uri(uri: str):
    if uri == LocalTestCalendar.URI:
        return LocalTestCalendar()
    if uri in PUBLIC_CALENDARS or uri in TRUSTED_CALENDAR_SERVERS:
        return RemoteCalendar(uri)
    return None  # never contact calendars we didn't choose


def to_bytes(dtf: DetachedTimestampFile) -> bytes:
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return ctx.getbytes()


def from_bytes(data: bytes) -> DetachedTimestampFile:
    return DetachedTimestampFile.deserialize(BytesDeserializationContext(data))


def verify(event: dict, dtf: DetachedTimestampFile) -> dict:
    """Check that a proof belongs to this event and report what it is anchored to.

    Bitcoin attestations are reported with their block height; confirming the
    block header itself needs a Bitcoin node (or the standard `ots verify`).
    """
    report = {"event_id": event.get("id"), "signature_ok": ev.verify_signature(event),
              "proof_matches_event": False, "anchors": [], "status": "invalid"}
    if not isinstance(dtf.file_hash_op, OpSHA256) or dtf.file_digest.hex() != event.get("id"):
        return report
    report["proof_matches_event"] = True
    report["anchors"] = _anchors(dtf)
    report["status"] = _status(report["anchors"]) if report["signature_ok"] else "invalid"
    return report


def file_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def verify_file(data: bytes, dtf: DetachedTimestampFile) -> dict:
    """Like verify(), for a plain file (e.g. NUCLEUS.txt). Compatible with `ots verify`."""
    report = {"file_sha256": file_digest(data).hex(), "proof_matches_file": False,
              "anchors": [], "status": "invalid"}
    if not isinstance(dtf.file_hash_op, OpSHA256) or dtf.file_digest != file_digest(data):
        return report
    report["proof_matches_file"] = True
    report["anchors"] = _anchors(dtf)
    report["status"] = _status(report["anchors"])
    return report


def _anchors(dtf: DetachedTimestampFile) -> list[dict]:
    out = []
    for msg, att in sorted(dtf.timestamp.all_attestations(), key=lambda x: repr(x[1])):
        if isinstance(att, BitcoinBlockHeaderAttestation):
            out.append({"type": "bitcoin", "height": att.height,
                        "merkle_root_should_be": msg[::-1].hex()})
        elif isinstance(att, PendingAttestation):
            out.append({"type": "pending", "calendar": att.uri,
                        "test_only": att.uri == LocalTestCalendar.URI})
        else:
            out.append({"type": "other", "detail": repr(att)})
    return out


def _status(anchors: list[dict]) -> str:
    if any(a["type"] == "bitcoin" for a in anchors):
        return "anchored (check block header with a Bitcoin node or `ots verify`)"
    return "pending" if anchors else "invalid"
