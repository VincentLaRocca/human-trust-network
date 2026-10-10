"""Nostr-style keys: secp256k1, 32-byte x-only public keys, BIP340 Schnorr signatures.

Keys are generated at runtime into gitignored folders and carry a role:

  operational  everyday signing key (default folder `.keys/`)
  recovery     generated separately (default folder `.recovery/`), meant to go
               offline; the normal commands refuse to load it
  bond         one fresh key per vouch bond (`.keys/bonds/`), never an
               operational key, so bonds aren't tied to long-lived identity keys
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from coincurve import PrivateKey, PublicKeyXOnly

_NAME = re.compile(r"^[a-z0-9_-]{1,32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


ROLES = ("operational", "recovery", "bond")


class KeyNotFound(LookupError):
    pass


class WrongKeyRole(ValueError):
    pass


@dataclass(frozen=True)
class Key:
    name: str
    secret: bytes

    @property
    def pubkey(self) -> str:
        return PrivateKey(self.secret).public_key.format(compressed=True)[1:].hex()

    def sign(self, msg32: bytes) -> str:
        return PrivateKey(self.secret).sign_schnorr(msg32).hex()


def generate(name: str) -> Key:
    if not _NAME.match(name):
        raise ValueError("key name: 1-32 chars of a-z, 0-9, _ or -")
    return Key(name, PrivateKey().secret)


def verify(pubkey_hex: str, sig_hex: str, msg32: bytes) -> bool:
    try:
        return PublicKeyXOnly(bytes.fromhex(pubkey_hex)).verify(bytes.fromhex(sig_hex), msg32)
    except Exception:
        return False


def save(key: Key, keys_dir: Path, role: str = "operational") -> Path:
    if role not in ROLES:
        raise ValueError(f"unknown key role {role!r}")
    keys_dir.mkdir(parents=True, exist_ok=True)
    path = keys_dir / f"{key.name}.json"
    if path.exists():
        raise FileExistsError(f"key {key.name!r} already exists; refusing to overwrite")
    path.write_text(json.dumps({"name": key.name, "role": role, "pubkey": key.pubkey,
                                "secret": key.secret.hex()}, indent=2), encoding="utf-8")
    return path


def load_file(path: Path, role: str = "operational") -> Key:
    path = Path(path)
    if not path.exists():
        raise KeyNotFound(f"no key file {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    found = data.get("role", "operational")
    if found != role:
        if found == "recovery":
            raise WrongKeyRole(f"{path.name} is a RECOVERY key; normal commands never load it "
                               "(use --recovery-file, offline, only to recover)")
        raise WrongKeyRole(f"{path.name} is a {found} key, not a {role} key")
    return Key(data["name"], bytes.fromhex(data["secret"]))


def load(name: str, keys_dir: Path, role: str = "operational") -> Key:
    path = keys_dir / f"{name}.json"
    if not path.exists():
        raise KeyNotFound(f"no key named {name!r} in {keys_dir}")
    return load_file(path, role)


def list_keys(keys_dir: Path) -> list[Key]:
    """Operational keys only."""
    if not keys_dir.exists():
        return []
    out = []
    for p in sorted(keys_dir.glob("*.json")):
        try:
            out.append(load_file(p))
        except WrongKeyRole:
            continue
    return out


# -- bond keys (one per bond) ------------------------------------------------

def new_bond_key(keys_dir: Path) -> Key:
    secret = PrivateKey().secret
    key = Key(Key("bond", secret).pubkey[:32], secret)
    save(key, keys_dir / "bonds", role="bond")
    return key


def load_bond_key(pubkey: str, keys_dir: Path) -> Key:
    key = load(pubkey[:32], keys_dir / "bonds", role="bond")
    if key.pubkey != pubkey:
        raise KeyNotFound(f"no bond key {pubkey}")
    return key


def resolve_pubkey(name_or_hex: str, keys_dir: Path) -> str:
    """Accept either a local key name or a 64-hex public key."""
    if _HEX64.match(name_or_hex):
        return name_or_hex
    return load(name_or_hex, keys_dir).pubkey
