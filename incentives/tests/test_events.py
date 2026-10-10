"""Signatures and ids."""
from coincurve import PrivateKey

from htn import events as ev
from htn import keys


def test_bip340_test_vector_0():
    # Official BIP340 test vector #0 - proves we produce standard Schnorr signatures.
    sk = PrivateKey(bytes.fromhex("00" * 31 + "03"))
    assert sk.public_key.format()[1:].hex().upper() == \
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    sig = sk.sign_schnorr(bytes(32), bytes(32))
    assert sig.hex().upper() == (
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")


def test_sign_and_verify(world):
    e = world.job()
    assert ev.verify_signature(e)


def test_any_tampering_breaks_signature(world):
    e = world.job()
    for field, value in [("created_at", e["created_at"] + 1), ("kind", ev.HANDOFF),
                         ("pubkey", world.stranger.pubkey), ("tags", e["tags"][:-1])]:
        assert not ev.verify_signature({**e, field: value}), field


def test_signature_from_other_key_rejected(world):
    e = world.job()
    forged = {**e, "sig": world.stranger.sign(bytes.fromhex(e["id"]))}
    assert not ev.verify_signature(forged)


def test_id_is_nip01_hash(world):
    import hashlib, json
    e = world.job()
    expected = hashlib.sha256(json.dumps(
        [0, e["pubkey"], e["created_at"], e["kind"], e["tags"], e["content"]],
        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    assert e["id"] == expected


def test_salted_commitment():
    h1, s1 = ev.commit(b"12 Main St")
    h2, _ = ev.commit(b"12 Main St")
    assert h1 != h2  # same secret, different hash: can't be guessed by hashing candidates
    assert ev.check_commitment(h1, s1, b"12 Main St")
    assert not ev.check_commitment(h1, s1, b"13 Main St")


def test_job_id_commits_to_terms_with_secret_nonce():
    terms = b"pickup 9am, 1 sealed case"
    job_id, nonce = ev.make_job_id(terms)
    assert ev.check_commitment(job_id, nonce, terms)          # parties can prove it
    assert not ev.check_commitment(job_id, nonce, b"other terms")
    assert ev.make_job_id(terms)[0] != job_id                 # same terms, new nonce, new id


def test_keys_saved_and_never_overwritten(tmp_path):
    k = keys.generate("alice")
    keys.save(k, tmp_path)
    assert keys.load("alice", tmp_path).pubkey == k.pubkey
    import pytest
    with pytest.raises(FileExistsError):
        keys.save(keys.generate("alice"), tmp_path)
