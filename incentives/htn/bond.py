"""Taproot vouch bond (Nucleus section 2, brief Phase 3). Test networks only.

The voucher locks `amount` sats in a Taproot output with two spending paths
and NO key path (the internal key is the BIP341 "nothing up my sleeve" point,
which nobody can sign for):

  leaf A  2-of-3:  client, voucher, arbiter
          <client> CHECKSIG <voucher> CHECKSIGADD <arbiter> CHECKSIGADD 2 NUMEQUAL
  leaf B  voucher alone, once the bond output is T blocks old:
          <voucher> CHECKSIGVERIFY <T> CHECKSEQUENCEVERIFY

Both leaves are standard miniscript, so the output is also the Bitcoin Core
descriptor `tr(NUMS,{multi_a(2,C,V,A),and_v(v:pk(V),older(T))})`; the tests
check that Core derives the same address independently.

The arbiter is the founder, unless the founder is a party to the job (client,
worker, recipient or this voucher); then it is the backup arbiter. That is
decided when the bond is made, so the recusal is written into the script.

Script cannot force where forfeited sats go (no covenants). The rule "forfeit
pays the harmed client" lives in `arbiter_sign_forfeit`, which signs only a
spend the client has already signed, and only when the public record shows an
upheld dispute that forfeited this vouch.

Everything here is plain Python (hashing + coincurve for the curve maths);
Bitcoin Core in the regtest sandbox is the judge of whether it is correct.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from coincurve import PublicKey

from . import keys
from .config import Config

# BIP341's provably unspendable internal key (no one knows its private key).
NUMS = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
LEAF_VERSION = 0xC0
SEQUENCE_FINAL_RBF = 0xFFFFFFFD
DEFAULT_FEE_SATS = 1_000
HRP = {"regtest": "bcrt", "signet": "tb"}  # no mainnet entry, on purpose

OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD = 0xAC, 0xAD, 0xBA
OP_NUMEQUAL, OP_CSV, OP_2 = 0x9C, 0xB2, 0x52


class BondError(Exception):
    pass


# -- hashing and encoding helpers ---------------------------------------------

def tagged_hash(tag: str, data: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def ser_bytes(b: bytes) -> bytes:
    return compact_size(len(b)) + b


def script_num(n: int) -> bytes:
    """Minimal push of a small positive number (as used by CHECKSEQUENCEVERIFY)."""
    if not 0 < n <= 0xFFFF:
        raise BondError("timelock must be 1..65535 blocks")
    if n <= 16:
        return bytes([0x50 + n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "little")
    if body[-1] & 0x80:
        body += b"\x00"
    return bytes([len(body)]) + body


def push32(b: bytes) -> bytes:
    assert len(b) == 32
    return b"\x20" + b


# -- bech32m addresses (BIP350), test networks only ------------------------------

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M = 0x2BC830A3


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc = bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (tobits - bits)) & maxv)
    elif not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
        raise BondError("invalid address padding")
    return out


def hrp_for(config: Config) -> str:
    return HRP[config.bitcoin_network]


def encode_address(hrp: str, version: int, program: bytes) -> str:
    data = [version] + _convertbits(program, 8, 5)
    if version == 0:
        raise BondError("only Taproot (v1) addresses are produced here")
    values = _hrp_expand(hrp) + data
    pm = _polymod(values + [0] * 6) ^ _BECH32M
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


def address_to_script(address: str, config: Config) -> bytes:
    """scriptPubKey for a segwit address on the configured TEST network.

    Refuses any other network's address, so a mainnet address can never be
    used as a payout destination.
    """
    addr = address.lower()
    hrp = hrp_for(config)
    if not addr.startswith(hrp + "1") or addr.rfind("1") != len(hrp):
        raise BondError(f"not a {config.bitcoin_network} address (expected prefix {hrp}1)")
    try:
        data = [_CHARSET.index(c) for c in addr[len(hrp) + 1:]]
    except ValueError:
        raise BondError("invalid address characters") from None
    const = _polymod(_hrp_expand(hrp) + data)
    version = data[0] if data else -1
    if version == 0 and const != 1 or version > 0 and const != _BECH32M or version < 0:
        raise BondError("invalid address checksum")
    program = bytes(_convertbits(data[1:-6], 5, 8, pad=False))
    if version > 16 or not 2 <= len(program) <= 40 or version == 0 and len(program) not in (20, 32):
        raise BondError("invalid witness program")
    return bytes([0x50 + version if version else 0, len(program)]) + program


# -- the bond output ---------------------------------------------------------

@dataclass(frozen=True)
class BondTerms:
    client: str       # x-only pubkeys, hex
    voucher: str      # the voucher's dedicated BOND key, not their operational key
    arbiter: str
    timelock_blocks: int

    def __post_init__(self):
        ks = (self.client, self.voucher, self.arbiter)
        if len(set(ks)) != 3:
            raise BondError("client, voucher and arbiter keys must all be different")
        for k in ks:
            try:
                PublicKey(b"\x02" + bytes.fromhex(k))
            except Exception:
                raise BondError(f"not a valid public key: {k[:16]}...") from None
        script_num(self.timelock_blocks)

    @property
    def multisig_script(self) -> bytes:
        c, v, a = (bytes.fromhex(k) for k in (self.client, self.voucher, self.arbiter))
        return (push32(c) + bytes([OP_CHECKSIG]) + push32(v) + bytes([OP_CHECKSIGADD])
                + push32(a) + bytes([OP_CHECKSIGADD, OP_2, OP_NUMEQUAL]))

    @property
    def reclaim_script(self) -> bytes:
        return (push32(bytes.fromhex(self.voucher)) + bytes([OP_CHECKSIGVERIFY])
                + script_num(self.timelock_blocks) + bytes([OP_CSV]))

    @staticmethod
    def leaf_hash(script: bytes) -> bytes:
        return tagged_hash("TapLeaf", bytes([LEAF_VERSION]) + ser_bytes(script))

    @property
    def merkle_root(self) -> bytes:
        a, b = sorted([self.leaf_hash(self.multisig_script), self.leaf_hash(self.reclaim_script)])
        return tagged_hash("TapBranch", a + b)

    def _tweaked(self) -> bytes:
        tweak = tagged_hash("TapTweak", NUMS + self.merkle_root)
        return PublicKey(b"\x02" + NUMS).add(tweak).format(compressed=True)

    @property
    def output_key(self) -> str:
        return self._tweaked()[1:].hex()

    @property
    def script_pubkey(self) -> bytes:
        return b"\x51\x20" + bytes.fromhex(self.output_key)

    def address(self, config: Config) -> str:
        return encode_address(hrp_for(config), 1, bytes.fromhex(self.output_key))

    def control_block(self, script: bytes) -> bytes:
        other = self.reclaim_script if script == self.multisig_script else self.multisig_script
        parity = self._tweaked()[0] & 1
        return bytes([LEAF_VERSION | parity]) + NUMS + self.leaf_hash(other)

    def descriptor(self) -> str:
        """The same output as a Bitcoin Core descriptor (used to cross-check the address)."""
        return (f"tr({NUMS.hex()},{{multi_a(2,{self.client},{self.voucher},{self.arbiter}),"
                f"and_v(v:pk({self.voucher}),older({self.timelock_blocks}))}})")

    def to_dict(self) -> dict:
        return {"client": self.client, "voucher": self.voucher, "arbiter": self.arbiter,
                "timelock_blocks": self.timelock_blocks}


def terms_for(ledger, job_id: str, voucher_pubkey: str, bond_key: str) -> BondTerms:
    """Bond terms for a voucher on a job, with the recusal rule applied.

    `voucher_pubkey` is the voucher's operational key (it decides recusal);
    `bond_key` is the fresh key that actually goes into the script.
    """
    job = ledger.jobs.get(job_id)
    if job is None:
        raise BondError("unknown job")
    if bond_key in ledger.known_keys or bond_key in (
            voucher_pubkey, ledger.config.founder_arbiter, ledger.config.backup_arbiter):
        raise BondError("bond key must be a fresh key, not an operational key")
    arbiter = ledger.acting_arbiter(job, extra_voucher=voucher_pubkey)
    if arbiter is None:
        raise BondError("no eligible arbiter: configure [arbiters] founder and backup")
    return BondTerms(job.client, bond_key, arbiter, ledger.config.bond_timelock_blocks)


def terms_for_vouch(ledger, vouch_event_id: str) -> BondTerms:
    v = ledger.vouches.get(vouch_event_id)
    if v is None:
        raise BondError("unknown vouch")
    if v.arbiter is None or v.bond_key is None:
        raise BondError("this vouch has no bond")
    return BondTerms(ledger.jobs[v.job_id].client, v.bond_key, v.arbiter,
                     ledger.config.bond_timelock_blocks)


# -- spending ------------------------------------------------------------------

@dataclass
class Spend:
    """A one-input, one-output spend of a bond output."""
    terms: BondTerms
    txid: str            # funding transaction (display order hex)
    vout: int
    amount: int          # sats in the bond output
    dest_script: bytes
    fee: int
    path: str            # "multisig" or "reclaim"
    sigs: dict[str, str] = field(default_factory=dict)  # pubkey -> signature hex

    @property
    def script(self) -> bytes:
        return self.terms.multisig_script if self.path == "multisig" else self.terms.reclaim_script

    @property
    def sequence(self) -> int:
        return self.terms.timelock_blocks if self.path == "reclaim" else SEQUENCE_FINAL_RBF

    @property
    def out_value(self) -> int:
        return self.amount - self.fee

    def _outpoint(self) -> bytes:
        return bytes.fromhex(self.txid)[::-1] + struct.pack("<I", self.vout)

    def _output(self) -> bytes:
        return struct.pack("<q", self.out_value) + ser_bytes(self.dest_script)

    def sighash(self) -> bytes:
        """BIP341 signature hash, script path, SIGHASH_DEFAULT."""
        msg = (b"\x00" + b"\x00" + struct.pack("<i", 2) + struct.pack("<I", 0)
               + sha256(self._outpoint())
               + sha256(struct.pack("<q", self.amount))
               + sha256(ser_bytes(self.terms.script_pubkey))
               + sha256(struct.pack("<I", self.sequence))
               + sha256(self._output())
               + b"\x02"                                   # script path, no annex
               + struct.pack("<I", 0)                      # input index
               + self.terms.leaf_hash(self.script) + b"\x00" + b"\xff\xff\xff\xff")
        return tagged_hash("TapSighash", msg)

    def allowed_signers(self) -> list[str]:
        t = self.terms
        return [t.client, t.voucher, t.arbiter] if self.path == "multisig" else [t.voucher]

    def add_signature(self, pubkey: str, sig: str) -> None:
        if pubkey not in self.allowed_signers():
            raise BondError("this key cannot sign on this path")
        if not keys.verify(pubkey, sig, self.sighash()):
            raise BondError("signature does not match this transaction")
        self.sigs[pubkey] = sig

    def sign(self, key: keys.Key) -> str:
        sig = key.sign(self.sighash())
        self.add_signature(key.pubkey, sig)
        return sig

    def _tx(self, witness: bytes | None) -> bytes:
        body = (compact_size(1) + self._outpoint() + b"\x00" + struct.pack("<I", self.sequence)
                + compact_size(1) + self._output())
        if witness is None:
            return struct.pack("<i", 2) + body + struct.pack("<I", 0)
        return struct.pack("<i", 2) + b"\x00\x01" + body + witness + struct.pack("<I", 0)

    def finalize(self) -> str:
        """Raw signed transaction (hex), ready to broadcast."""
        t = self.terms
        if self.path == "multisig":
            present = [k for k in (t.client, t.voucher, t.arbiter) if k in self.sigs]
            if len(present) < 2:
                raise BondError("need 2 of the 3 signatures (client, voucher, arbiter)")
            present = present[:2]
            # The script checks client, voucher, arbiter in that order, so the
            # stack lists their signatures in reverse; a missing one is empty.
            stack = [bytes.fromhex(self.sigs[k]) if k in present else b""
                     for k in (t.arbiter, t.voucher, t.client)]
        else:
            if t.voucher not in self.sigs:
                raise BondError("need the voucher's signature")
            stack = [bytes.fromhex(self.sigs[t.voucher])]
        return self.raw_with_stack(stack)

    def raw_with_stack(self, stack: list[bytes]) -> str:
        items = stack + [self.script, self.terms.control_block(self.script)]
        witness = compact_size(len(items)) + b"".join(ser_bytes(i) for i in items)
        return self._tx(witness).hex()

    @property
    def spend_txid(self) -> str:
        return hashlib.sha256(sha256(self._tx(None))).digest()[::-1].hex()

    def to_dict(self) -> dict:
        return {"terms": self.terms.to_dict(), "txid": self.txid, "vout": self.vout,
                "amount": self.amount, "dest_script": self.dest_script.hex(), "fee": self.fee,
                "path": self.path, "sigs": self.sigs}

    @classmethod
    def from_dict(cls, d: dict) -> "Spend":
        s = cls(BondTerms(**d["terms"]), d["txid"], d["vout"], d["amount"],
                bytes.fromhex(d["dest_script"]), d["fee"], d["path"])
        for pk, sig in d["sigs"].items():
            s.add_signature(pk, sig)  # re-verified, never trusted from the file
        return s


def _spend(terms: BondTerms, txid: str, vout: int, amount: int, dest_address: str,
           config: Config, fee: int, path: str) -> Spend:
    if not 0 < fee < amount:
        raise BondError("fee must be positive and smaller than the bond")
    return Spend(terms, txid, vout, amount, address_to_script(dest_address, config), fee, path)


def forfeit_to_client(terms: BondTerms, txid: str, vout: int, amount: int,
                      client_address: str, config: Config, fee: int = DEFAULT_FEE_SATS) -> Spend:
    """Unsigned spend of the whole bond (minus fee) to the client's address."""
    return _spend(terms, txid, vout, amount, client_address, config, fee, "multisig")


def reclaim(terms: BondTerms, txid: str, vout: int, amount: int, dest_address: str,
            config: Config, fee: int = DEFAULT_FEE_SATS) -> Spend:
    """Unsigned voucher-alone spend; valid once the bond output is T blocks old."""
    return _spend(terms, txid, vout, amount, dest_address, config, fee, "reclaim")


def arbiter_sign_forfeit(ledger, vouch_event_id: str, spend: Spend, arbiter: keys.Key) -> str:
    """The arbiter's rule, in code: sign a 2-of-3 spend ONLY if

    - the public record shows this vouch was forfeited by an upheld dispute,
    - the spend uses exactly this vouch's bond terms and the 2-of-3 path,
    - the arbiter is the bond's arbiter, and
    - the client has already signed this exact transaction (so the client
      chose the destination; the voucher cannot redirect the sats).
    """
    v = ledger.vouches.get(vouch_event_id)
    if v is None:
        raise BondError("unknown vouch")
    if v.status != "forfeited":
        raise BondError(f"vouch is {v.status}, not forfeited: no upheld dispute on record")
    if spend.terms != terms_for_vouch(ledger, vouch_event_id) or spend.path != "multisig":
        raise BondError("spend does not match this vouch's bond")
    if arbiter.pubkey != spend.terms.arbiter:
        raise BondError("you are not this bond's arbiter")
    if spend.terms.client not in spend.sigs:
        raise BondError("the client must sign first (forfeited sats go to the harmed client)")
    return spend.sign(arbiter)


# -- checking a bond on chain (sandbox) --------------------------------------------

def find_output(tx: dict, terms: BondTerms) -> tuple[int, int]:
    """(vout, sats) of the bond output in a decoded transaction (getrawtransaction verbose)."""
    want = terms.script_pubkey.hex()
    for out in tx["vout"]:
        if out["scriptPubKey"]["hex"] == want:
            return out["n"], round(out["value"] * 100_000_000)
    raise BondError("transaction has no output for this bond")


def check_bond(ledger, vouch_event_id: str, chain) -> dict:
    """Anyone can check a published vouch's bond against the chain (DECISIONS #43).

    `chain` answers three questions (see sandbox.SandboxChain):
      get_tx(txid)      -> decoded transaction with "confirmations", or None
      utxo(txid, vout)  -> the output if it is still unspent, else None
      tip()             -> {"height", "hash"} of the chain being asked
      spending_tx(txid, vout) -> the transaction that spent it, or None
    The expected output is rebuilt from public facts only (job client, the
    vouch's bond key, the arbiter by the recusal rule, T), so nothing is taken
    on trust. A bond is LIVE only if it exists, is confirmed, is unspent, holds
    the vouched amount, meets the configured minimum, and wasn't locked before
    the job (which would start its timelock early).

    It COUNTS (for scoring) if it is live, or if it passed all the same checks
    and was then spent by an honest reclaim: the voucher-alone path after T
    (Vinny's choice, following the Nucleus "long clean history"; DECISIONS #47).
    Any other spend, e.g. a 2-of-3 forfeit, stops it counting.
    """
    v = ledger.vouches.get(vouch_event_id)
    if v is None:
        raise BondError("unknown vouch")
    report = {"vouch": vouch_event_id, "txid": v.bond, "vout": None, "sats": 0,
              "arbiter": v.arbiter, "confirmations": 0, "live": False, "reclaimed_by": None,
              "counts": False, "problems": []}
    problems = report["problems"]
    if not v.bond:
        problems.append("this vouch names no bond")
        return report
    terms = terms_for_vouch(ledger, vouch_event_id)
    tx = chain.get_tx(v.bond)
    if tx is None:
        problems.append("bond transaction not found on chain")
        return report
    try:
        vout, sats = find_output(tx, terms)
    except BondError as e:
        problems.append(str(e))
        return report
    report.update(vout=vout, sats=sats, confirmations=tx.get("confirmations", 0))
    if sats != v.amount:
        problems.append(f"bond holds {sats} sats, vouch says {v.amount}")
    if sats < ledger.config.bond_min_sats:
        problems.append(f"bond is below the {ledger.config.bond_min_sats}-sat minimum")
    if not tx.get("confirmations"):
        problems.append("bond transaction is not confirmed yet")
    elif tx["blocktime"] < ledger.jobs[v.job_id].created_at - 7200:
        problems.append("bond was created before the job (its timelock would start early)")
    spent = chain.utxo(v.bond, vout) is None
    if spent:
        spender = chain.spending_tx(v.bond, vout)
        if spender is not None and is_honest_reclaim(spender, v.bond, vout, terms):
            report["reclaimed_by"] = spender["txid"]
        else:
            problems.append("bond has been spent (not by the voucher's timelock reclaim)")
    report["live"] = not problems and not spent
    report["counts"] = not problems
    return report


def is_honest_reclaim(tx: dict, txid: str, vout: int, terms: BondTerms) -> bool:
    """Did `tx` spend the bond through the voucher-alone timelock path?"""
    for i in tx.get("vin", []):
        if i.get("txid") == txid and i.get("vout") == vout:
            w = i.get("txinwitness", [])
            return (len(w) == 3 and w[1] == terms.reclaim_script.hex()
                    and i.get("sequence", 0) >= terms.timelock_blocks)
    return False
