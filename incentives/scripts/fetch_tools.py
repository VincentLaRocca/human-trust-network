"""Download Bitcoin Core and LND for the regtest sandbox, and verify them.

Run from the repo root:   .venv\\Scripts\\python scripts\\fetch_tools.py

Checks, in order (any failure stops everything):
1. SHA-256 of each download matches the release's checksum file.
2. The checksum files are signed: Bitcoin Core's by at least MIN_BUILDER_SIGS
   independent builders, LND's by its lead maintainer (roasbeef). Signing keys
   come from GitHub, a different source from the downloads themselves.
Only then are the programs unpacked into tools/bin/.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

BITCOIN_VERSION = "31.1"
LND_VERSION = "v0.21.4-beta"
MIN_BUILDER_SIGS = 5

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
DL = TOOLS / "downloads"
KEYS = TOOLS / "keys"
GNUPG = TOOLS / "gnupg"  # private keyring; never touches the user's own GPG setup
BIN = TOOLS / "bin"

BTC_BASE = f"https://bitcoincore.org/bin/bitcoin-core-{BITCOIN_VERSION}"
BTC_ZIP = f"bitcoin-{BITCOIN_VERSION}-win64.zip"
LND_BASE = f"https://github.com/lightningnetwork/lnd/releases/download/{LND_VERSION}"
LND_ZIP = f"lnd-windows-amd64-{LND_VERSION}.zip"
LND_MANIFEST = f"manifest-{LND_VERSION}.txt"
LND_SIG = f"manifest-roasbeef-{LND_VERSION}.sig"
ROASBEEF_KEY = "https://raw.githubusercontent.com/lightningnetwork/lnd/master/scripts/keys/roasbeef.asc"
BUILDER_KEYS_API = "https://api.github.com/repos/bitcoin-core/guix.sigs/contents/builder-keys"


def fail(msg: str) -> None:
    print(f"FAILED: {msg}")
    sys.exit(1)


def fetch(url: str, dest: Path) -> Path:
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as r:
        dest.write_bytes(r.read())
    return dest


def check_sha256(file: Path, sums: Path) -> None:
    want = None
    for line in sums.read_text().splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == file.name:
            want = parts[0]
    if want is None:
        fail(f"{file.name} not listed in {sums.name}")
    got = hashlib.sha256(file.read_bytes()).hexdigest()
    if got != want:
        fail(f"checksum mismatch for {file.name}")
    print(f"checksum OK  {file.name}")


def gpg(*files: Path, cmd: str) -> str:
    """Run gpg with our private keyring. Paths are passed relative to tools/,
    because Git for Windows' gpg can't read Windows-style absolute paths."""
    GNUPG.mkdir(parents=True, exist_ok=True)
    rel = [p.relative_to(TOOLS).as_posix() for p in files]
    proc = subprocess.run(["gpg", "--batch", "--homedir", GNUPG.name, cmd, *rel],
                          capture_output=True, text=True, cwd=TOOLS)
    return proc.stdout + proc.stderr


def main() -> None:
    # Downloads (each project in its own folder).
    btc_zip = fetch(f"{BTC_BASE}/{BTC_ZIP}", DL / "bitcoin" / BTC_ZIP)
    btc_sums = fetch(f"{BTC_BASE}/SHA256SUMS", DL / "bitcoin" / "SHA256SUMS")
    btc_asc = fetch(f"{BTC_BASE}/SHA256SUMS.asc", DL / "bitcoin" / "SHA256SUMS.asc")
    lnd_zip = fetch(f"{LND_BASE}/{LND_ZIP}", DL / "lnd" / LND_ZIP)
    lnd_manifest = fetch(f"{LND_BASE}/{LND_MANIFEST}", DL / "lnd" / LND_MANIFEST)
    lnd_sig = fetch(f"{LND_BASE}/{LND_SIG}", DL / "lnd" / LND_SIG)

    # 1. Checksums.
    check_sha256(btc_zip, btc_sums)
    check_sha256(lnd_zip, lnd_manifest)

    # 2. Signatures, with keys from GitHub.
    fetch(ROASBEEF_KEY, KEYS / "roasbeef.asc")
    with urllib.request.urlopen(BUILDER_KEYS_API, timeout=60) as r:
        for item in json.load(r):
            if item["name"].endswith(".gpg"):
                fetch(item["download_url"], KEYS / item["name"])
    gpg(*[p for p in KEYS.glob("*") if p.suffix in (".gpg", ".asc")], cmd="--import")

    out = gpg(lnd_sig, lnd_manifest, cmd="--verify")
    if "Good signature" not in out or "BAD signature" in out:
        fail("LND manifest signature")
    print("signature OK  LND manifest (roasbeef)")

    out = gpg(btc_asc, btc_sums, cmd="--verify")
    good = len(re.findall("Good signature", out))
    if "BAD signature" in out or good < MIN_BUILDER_SIGS:
        fail(f"Bitcoin Core SHA256SUMS: {good} good signatures (need {MIN_BUILDER_SIGS}), or a bad one")
    print(f"signature OK  Bitcoin Core SHA256SUMS ({good} builders)")

    # 3. Unpack only the four programs we need.
    BIN.mkdir(parents=True, exist_ok=True)
    for zpath, wanted in ((btc_zip, ("bitcoind.exe", "bitcoin-cli.exe")),
                          (lnd_zip, ("lnd.exe", "lncli.exe"))):
        with zipfile.ZipFile(zpath) as z:
            for info in z.infolist():
                name = info.filename.rsplit("/", 1)[-1]
                if name in wanted and ("/bin/" in info.filename or zpath == lnd_zip):
                    data, dest = z.read(info), BIN / name
                    if not dest.exists() or dest.read_bytes() != data:  # skip if identical
                        dest.write_bytes(data)
    print(f"installed to {BIN}: {sorted(p.name for p in BIN.iterdir())}")


if __name__ == "__main__":
    main()
