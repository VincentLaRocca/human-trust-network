#!/usr/bin/env python3
"""Custody handoff commitments.

One title. No mint. Witness signatures are BIP-340 Schnorr over the operation id.
A seal may be closed once. Copyright and agent schemas are not in this file.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from embit.ec import PrivateKey, PublicKey, SchnorrSig


def tagged_hash(tag: str, payload: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + payload).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def u8(n: int) -> bytes:
    return struct.pack("B", n)


def u32(n: int) -> bytes:
    return struct.pack(">I", n)


def lp(data: bytes) -> bytes:
    return u32(len(data)) + data


class Reject(Exception):
    pass


def seal_commit(blinding: bytes, txid: bytes, vout: int) -> bytes:
    if len(blinding) != 32 or len(txid) != 32 or blinding == bytes(32):
        raise Reject("blinding must be 32 nonzero bytes")
    return tagged_hash("urn:htn:seal:v1", blinding + txid + u32(vout))


def xonly(pubkey: bytes) -> bytes:
    if len(pubkey) == 33 and pubkey[0] in (2, 3):
        return pubkey[1:]
    if len(pubkey) == 32:
        return pubkey
    raise Reject("witness key must be x-only or compressed")


@dataclass(frozen=True)
class WitnessSet:
    threshold: int
    keys: tuple[bytes, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "keys", tuple(xonly(key) for key in self.keys))
        if self.threshold < 1 or self.threshold > len(self.keys):
            raise Reject("threshold exceeds witness set")
        if len(set(self.keys)) != len(self.keys):
            raise Reject("duplicate witness key")

    def canonical(self) -> bytes:
        return u8(self.threshold) + u8(len(self.keys)) + b"".join(self.keys)

    def require(self, op_id: bytes, sigs: dict[bytes, bytes]) -> None:
        seen = set()
        good = 0
        for key, sig in sigs.items():
            key = xonly(key)
            if key not in self.keys or key in seen:
                raise Reject("witness key")
            seen.add(key)
            if len(sig) != 64 or not PublicKey.from_xonly(key).schnorr_verify(SchnorrSig(sig), op_id):
                raise Reject("bad witness")
            good += 1
        if good < self.threshold:
            raise Reject(f"threshold {self.threshold} not met ({good})")


@dataclass(frozen=True)
class Schema:
    name: str
    witnesses: WitnessSet

    @property
    def schema_id(self) -> bytes:
        body = lp(self.name.encode()) + u8(1) + self.witnesses.canonical()
        return tagged_hash("urn:htn:schema:custody:v1", body)


def custody_schema(witnesses: WitnessSet) -> Schema:
    return Schema("CustodyHandoff_v1", witnesses)


@dataclass
class Genesis:
    schema: Schema
    fields: bytes
    seal: bytes

    @property
    def genesis_id(self) -> bytes:
        return tagged_hash("urn:htn:genesis:v1", self.schema.schema_id + lp(self.fields) + self.seal)

    @property
    def contract_id(self) -> bytes:
        return self.genesis_id


@dataclass
class Transition:
    genesis_id: bytes
    spent_seal: bytes
    new_seal: bytes
    metadata: bytes

    @property
    def transition_id(self) -> bytes:
        body = self.genesis_id + self.spent_seal + self.new_seal + lp(self.metadata)
        return tagged_hash("urn:htn:transition:v1", body)


def bundle_id(genesis_id: bytes, transition_id: bytes | None = None) -> bytes:
    body = genesis_id if transition_id is None else genesis_id + transition_id
    return tagged_hash("urn:htn:bundle:v1", body)


@dataclass
class Consignment:
    schema: Schema
    genesis: Genesis
    transitions: list[Transition] = field(default_factory=list)
    current_seal: bytes = b""

    def __post_init__(self) -> None:
        if self.genesis.schema.schema_id != self.schema.schema_id:
            raise Reject("genesis schema mismatch")
        self.current_seal = self.genesis.seal

    def transfer(self, spent_seal: bytes, new_seal: bytes, metadata: bytes, witnesses: dict[bytes, bytes]) -> Transition:
        if spent_seal != self.current_seal:
            raise Reject("spend is not the current seal")
        if new_seal == spent_seal:
            raise Reject("reopen must be a new seal")
        if len(metadata) > 65535:
            raise Reject("metadata too long")
        transition = Transition(self.genesis.genesis_id, spent_seal, new_seal, metadata)
        self.schema.witnesses.require(transition.transition_id, witnesses)
        self.transitions.append(transition)
        self.current_seal = new_seal
        return transition


def sign(secret: bytes, op_id: bytes) -> tuple[bytes, bytes]:
    key = PrivateKey(secret)
    return key.xonly(), key.schnorr_sign(op_id).serialize()


def demo() -> None:
    a = PrivateKey(hashlib.sha256(b"courier").digest())
    b = PrivateKey(hashlib.sha256(b"clerk").digest())
    witnesses = WitnessSet(2, (a.sec(), b.sec()))
    schema = custody_schema(witnesses)
    genesis_seal = seal_commit(sha256(b"blind-genesis"), sha256(b"pouch"), 0)
    book = Consignment(schema, Genesis(schema, sha256(b"pouch-VA-00421"), genesis_seal))
    nxt = seal_commit(sha256(b"blind-next"), sha256(b"desk"), 1)
    pending = Transition(book.genesis.genesis_id, genesis_seal, nxt, sha256(b"received"))
    sigs = dict(sign(secret, pending.transition_id) for secret in (a.secret, b.secret))
    book.transfer(genesis_seal, nxt, sha256(b"received"), sigs)
    try:
        book.transfer(genesis_seal, seal_commit(sha256(b"blind-other"), sha256(b"x"), 0), b"", sigs)
    except Reject as exc:
        print("double spend", exc)
    else:
        raise SystemExit("seal spent twice")
    print("custody", schema.schema_id.hex())
    print("encoder ok")


if __name__ == "__main__":
    demo()
