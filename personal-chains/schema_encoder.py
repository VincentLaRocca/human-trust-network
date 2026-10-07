#!/usr/bin/env python3
"""Canonical commitments for the three Human Trust Network schemas.

This is the profile, not RGB consensus bytes. Every id is a BIP-340 tagged
SHA-256. Concealed fields commit to the 32-byte hash only. The preimage is
carried in the consignment and checked when presented.

A right moves only when its seal closes. License and instance issuance close
the parent seal and reopen it in the same transition.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field


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
    if len(data) > 0xFFFF:
        raise ValueError("field too long")
    return struct.pack(">H", len(data)) + data


def conceal(preimage: bytes) -> bytes:
    return hashlib.sha256(preimage).digest()


class Reject(Exception):
    pass


def seal_commit(blinding: bytes, txid: bytes, vout: int) -> bytes:
    if len(blinding) != 32 or len(txid) != 32:
        raise ValueError("blinding and txid must be 32 bytes")
    return tagged_hash("urn:lagroka:seal:v1", blinding + txid + u32(vout))


ZERO_BLIND = bytes(32)


@dataclass(frozen=True)
class WitnessSet:
    threshold: int
    keys: tuple[bytes, ...]

    def canonical(self) -> bytes:
        if self.threshold < 1 or self.threshold > len(self.keys):
            raise Reject("threshold exceeds witness set")
        return u8(self.threshold) + u8(len(self.keys)) + b"".join(self.keys)

    def require(self, op_id: bytes, sigs: dict[bytes, bytes]) -> None:
        seen = set()
        good = 0
        for key, sig in sigs.items():
            if key not in self.keys or key in seen:
                raise Reject("witness key")
            seen.add(key)
            if sig != sha256(key + op_id):
                raise Reject("bad witness")
            good += 1
        if good < self.threshold:
            raise Reject(f"threshold {self.threshold} not met ({good})")


@dataclass
class Schema:
    name: str
    tag: str
    body: bytes

    @property
    def schema_id(self) -> bytes:
        return tagged_hash(self.tag, self.body)


def hardware_schema(witnesses: WitnessSet) -> Schema:
    return Schema("HardwareTitleDeed_v1", "urn:lagroka:schema:hardware-deed:v1", u8(1) + witnesses.canonical())


def copyright_schema(witnesses: WitnessSet, license_cap: int) -> Schema:
    if license_cap < 1:
        raise Reject("license cap")
    return Schema("CopyrightMaster_v1", "urn:lagroka:schema:copyright:v1", u8(3) + u32(license_cap) + witnesses.canonical())


def agent_schema(witnesses: WitnessSet, instance_cap: int, cold_leaf: bytes) -> Schema:
    if instance_cap < 0 or len(cold_leaf) != 32:
        raise Reject("agent schema")
    return Schema("SovereignAgent_v1", "urn:lagroka:schema:sovereign-agent:v1", u8(2) + u32(instance_cap) + cold_leaf + witnesses.canonical())


@dataclass
class Genesis:
    schema: Schema
    fields: bytes
    seal: bytes

    @property
    def genesis_id(self) -> bytes:
        return tagged_hash(self.schema.tag + ":genesis", self.schema.schema_id + self.fields + self.seal)

    @property
    def contract_id(self) -> bytes:
        return self.genesis_id


@dataclass
class Transition:
    schema: Schema
    genesis_id: bytes
    spent_seal: bytes
    new_parent_seal: bytes
    issued: tuple[bytes, ...] = ()
    metadata: bytes = b""
    kind: str = "transfer"

    @property
    def transition_id(self) -> bytes:
        body = b"".join([
            self.genesis_id,
            self.spent_seal,
            self.new_parent_seal,
            u8(len(self.issued)),
            b"".join(self.issued),
            u8(len(self.metadata)),
            self.metadata,
            lp(self.kind.encode()),
        ])
        return tagged_hash(self.schema.tag + ":transition", body)


def bundle_id(genesis_id: bytes, transition_id: bytes | None = None) -> bytes:
    body = genesis_id if transition_id is None else genesis_id + transition_id
    return tagged_hash("urn:lagroka:bundle:v1", body)


@dataclass
class Consignment:
    schema: Schema
    genesis: Genesis
    transitions: list[Transition] = field(default_factory=list)
    issued_count: int = 0
    cap: int | None = None

    def issue(self, spent_seal: bytes, new_parent_seal: bytes, new_seals: tuple[bytes, ...], metadata: bytes, kind: str) -> Transition:
        if self.cap is not None and self.issued_count + len(new_seals) > self.cap:
            raise Reject("cap exceeded")
        if kind in {"license", "instance"} and not new_seals:
            raise Reject("issuance assigns no right")
        if kind == "rotate" and (new_seals or metadata):
            raise Reject("pure rotation carries no mint and no version")
        transition = Transition(self.schema, self.genesis.genesis_id, spent_seal, new_parent_seal, new_seals, metadata, kind)
        self.transitions.append(transition)
        self.issued_count += len(new_seals)
        return transition


def demo() -> None:
    notary = bytes.fromhex("02" + "aa" * 32)
    inspector = bytes.fromhex("02" + "bb" * 32)
    witnesses = WitnessSet(2, (notary, inspector))
    deed = hardware_schema(witnesses)
    genesis = Genesis(deed, conceal(b"SN-VA-00421") + conceal(b"deed"), seal_commit(ZERO_BLIND, sha256(b"seal"), 0))
    book = Consignment(deed, genesis)
    op = book.issue(genesis.seal, seal_commit(sha256(b"blind"), sha256(b"buyer"), 0), (), conceal(b"inspection-v2"), "transfer")
    witnesses.require(op.transition_id, {notary: sha256(notary + op.transition_id), inspector: sha256(inspector + op.transition_id)})
    print("deed", deed.schema_id.hex())
    print("contract", genesis.contract_id.hex())
    print("bundle", bundle_id(genesis.genesis_id, op.transition_id).hex())
    copy = copyright_schema(witnesses, license_cap=2)
    copy_genesis = Genesis(copy, conceal(b"master-file"), seal_commit(ZERO_BLIND, sha256(b"master"), 1))
    copy_book = Consignment(copy, copy_genesis, cap=2)
    copy_book.issue(copy_genesis.seal, seal_commit(ZERO_BLIND, sha256(b"master-2"), 0), (seal_commit(sha256(b"l1"), sha256(b"lic"), 0),), b"", "license")
    copy_book.issue(seal_commit(ZERO_BLIND, sha256(b"master-2"), 0), seal_commit(ZERO_BLIND, sha256(b"master-3"), 0), (seal_commit(sha256(b"l2"), sha256(b"lic2"), 0),), b"", "license")
    try:
        copy_book.issue(seal_commit(ZERO_BLIND, sha256(b"master-3"), 0), seal_commit(ZERO_BLIND, sha256(b"master-4"), 0), (seal_commit(sha256(b"l3"), sha256(b"lic3"), 0),), b"", "license")
    except Reject as exc:
        print("license cap", exc)
    else:
        raise SystemExit("cap not enforced")
    agent = agent_schema(witnesses, instance_cap=1, cold_leaf=conceal(b"cold-script"))
    agent_genesis = Genesis(agent, conceal(b"weights-v1"), seal_commit(ZERO_BLIND, sha256(b"control"), 0))
    agent_book = Consignment(agent, agent_genesis, cap=1)
    agent_book.issue(agent_genesis.seal, seal_commit(ZERO_BLIND, sha256(b"control-2"), 0), (), b"", "rotate")
    try:
        agent_book.issue(seal_commit(ZERO_BLIND, sha256(b"control-2"), 0), seal_commit(ZERO_BLIND, sha256(b"control-3"), 0), (seal_commit(sha256(b"i1"), sha256(b"inst"), 0), seal_commit(sha256(b"i2"), sha256(b"inst2"), 0)), conceal(b"weights-v2"), "instance")
    except Reject as exc:
        print("instance cap", exc)
    else:
        raise SystemExit("instance cap not enforced")
    print("agent", agent.schema_id.hex())
    print("encoder ok")


if __name__ == "__main__":
    demo()
