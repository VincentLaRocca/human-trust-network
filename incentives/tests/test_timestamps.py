"""OpenTimestamps proofs - all offline, using the local test calendar."""
from htn import timestamps as ots


def test_stamp_and_verify(world):
    e = world.job()
    dtf = ots.from_bytes(ots.to_bytes(ots.stamp(e["id"], [ots.LocalTestCalendar()])))
    report = ots.verify(e, dtf)
    assert report["proof_matches_event"] and report["signature_ok"]
    assert report["status"] == "pending"
    assert report["anchors"] == [{"type": "pending", "calendar": ots.LocalTestCalendar.URI,
                                  "test_only": True}]


def test_proof_for_other_event_fails(world):
    e1, e2 = world.job(), world.job()
    dtf = ots.stamp(e1["id"], [ots.LocalTestCalendar()])
    report = ots.verify(e2, dtf)
    assert not report["proof_matches_event"] and report["status"] == "invalid"


def test_tampered_event_fails(world):
    e = world.job()
    dtf = ots.stamp(e["id"], [ots.LocalTestCalendar()])
    report = ots.verify({**e, "created_at": e["created_at"] + 5}, dtf)
    assert report["status"] == "invalid"


def test_upgrade_to_block_anchor(world):
    e = world.job()
    dtf = ots.stamp(e["id"], [ots.LocalTestCalendar()])
    n = ots.upgrade(dtf, lambda uri: ots.LocalTestCalendar(anchor_height=123))
    assert n == 1
    report = ots.verify(e, ots.from_bytes(ots.to_bytes(dtf)))
    assert report["status"].startswith("anchored")
    assert report["anchors"][0]["height"] == 123


def test_upgrade_skips_untrusted_calendars(world):
    e = world.job()
    dtf = ots.stamp(e["id"], [ots.LocalTestCalendar()])
    assert ots.upgrade(dtf, lambda uri: None) == 0
    assert ots.default_calendar_for_uri("https://evil.example") is None


def test_stamp_fails_if_no_calendar_answers(world):
    class Down:
        def submit(self, digest):
            raise OSError("offline")
    import pytest
    with pytest.raises(ots.TimestampError):
        ots.stamp(world.job()["id"], [Down()])


def test_nonce_hides_event_id_from_calendar(world):
    seen = []

    class Spy(ots.LocalTestCalendar):
        def submit(self, digest):
            seen.append(digest)
            return super().submit(digest)
    e = world.job()
    ots.stamp(e["id"], [Spy()])
    assert seen and seen[0].hex() != e["id"]


def test_stamp_and_verify_file(tmp_path, capsys):
    from htn.cli import main
    doc = tmp_path / "NUCLEUS.txt"
    doc.write_bytes("Nucleus\n“quotes” and placeholders [D]\n".encode())
    base = ["--home", str(tmp_path / "d"), "--keys-dir", str(tmp_path / "k")]
    assert main(base + ["stamp-file", str(doc)]) == 0
    assert (tmp_path / "NUCLEUS.txt.ots").exists()
    assert main(base + ["verify-file", str(doc)]) == 0
    # Changing even one character breaks the proof.
    doc.write_bytes(doc.read_bytes().replace(b"[D]", b"[E]"))
    assert main(base + ["verify-file", str(doc)]) == 1
    capsys.readouterr()


def test_file_proof_digest_is_plain_sha256(tmp_path):
    import hashlib
    data = b"any document"
    dtf = ots.stamp_digest(ots.file_digest(data), [ots.LocalTestCalendar()])
    assert dtf.file_digest == hashlib.sha256(data).digest()  # same as the standard ots tool
    assert ots.verify_file(data, dtf)["status"] == "pending"


def test_real_calendar_servers_are_trusted_for_upgrade():
    for uri in ots.TRUSTED_CALENDAR_SERVERS:
        assert ots.default_calendar_for_uri(uri) is not None
