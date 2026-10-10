"""The brief's hard rules, checked automatically."""
import re
from pathlib import Path

import pytest

from htn.config import Config, ConfigError, load_config

REPO = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".venv", ".git", ".keys", "data", "tools", "__pycache__", ".pytest_cache"}

# Built from pieces so this file doesn't match its own patterns.
MAINNET_PATTERNS = [
    re.compile(r"\b" + "bc" + r"1[qp][02-9ac-hj-np-z]{20,}\b"),      # mainnet segwit/taproot address
    re.compile(r"\b" + "x" + r"prv[1-9A-HJ-NP-Za-km-z]{20,}"),        # mainnet extended private key
    re.compile(r"\b" + "nsec" + r"1[02-9ac-hj-np-z]{20,}"),           # nostr secret key
    re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"),               # mainnet WIF private key
]


def repo_files():
    for p in REPO.rglob("*"):
        if p.is_file() and not (SKIP_DIRS & set(p.relative_to(REPO).parts)):
            if p.suffix in {".py", ".toml", ".md", ".txt", ".ini", ".json", ".cfg"} or p.name == ".gitignore":
                yield p


def test_no_mainnet_material_or_secrets_in_repo():
    hits = []
    for p in repo_files():
        text = p.read_text(encoding="utf-8", errors="ignore")
        for pat in MAINNET_PATTERNS:
            hits += [f"{p.name}: {m.group()[:12]}..." for m in pat.finditer(text)]
    assert not hits, hits


def test_secret_folders_are_gitignored():
    ignored = (REPO / ".gitignore").read_text().split()
    assert ".keys/" in ignored and "data/" in ignored


def test_shipped_config_is_test_network():
    assert load_config().bitcoin_network in ("regtest", "signet")


def test_mainnet_config_refused():
    with pytest.raises(ConfigError):
        Config(bitcoin_network="mainnet")


def test_timelock_must_exceed_dispute_window():
    with pytest.raises(ConfigError):
        Config(dispute_window_blocks=2016, bond_timelock_blocks=2016)
    with pytest.raises(ConfigError):
        Config(dispute_window_seconds=20 * 24 * 3600)


def test_fee_split_must_total_100():
    with pytest.raises(ConfigError):
        Config(fee_worker_pct=90)


def test_shipped_config_matches_test_defaults():
    c = load_config()
    assert (c.dispute_window_seconds, c.bond_timelock_blocks) == (7 * 24 * 3600, 2016)
    assert (c.fee_worker_pct, c.fee_network_pct, c.fee_voucher_pct) == (85, 10, 5)
    assert (c.max_active_vouches, c.bond_min_sats, c.bond_max_sats) == (5, 10_000, 1_000_000)
    assert c.max_hold_seconds == 6 * 3600
    assert c.timestamp_mode == "local-test"  # public calendars only when asked


def test_unknown_config_setting_refused(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[network]\nbitcoin = "regtest"\n[fees]\nworkr = 85\n')
    with pytest.raises(ConfigError):
        load_config(p)
