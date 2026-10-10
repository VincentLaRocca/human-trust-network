"""Loads and checks the single parameter file (config.toml).

All placeholder numbers live in config.toml so the Founding Blueprint can set
the real values later without touching code.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, fields
from pathlib import Path

ALLOWED_NETWORKS = ("regtest", "signet")
TIMESTAMP_MODES = ("local-test", "public")
FEE_PAYOUTS = ("lightning", "sweep")
UNVOUCHED_SHARE = ("worker", "network")
TEST_ADDRESS_PREFIX = {"regtest": "bcrt1", "signet": "tb1"}
SECONDS_PER_BLOCK = 600  # Bitcoin's target block interval
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.toml"


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Config:
    bitcoin_network: str = "regtest"
    dispute_window_seconds: int = 7 * 24 * 3600
    dispute_window_blocks: int = 1008
    bond_timelock_blocks: int = 2016
    bond_min_sats: int = 10_000
    bond_max_sats: int = 1_000_000
    max_active_vouches: int = 5
    fee_worker_pct: int = 85
    fee_network_pct: int = 10
    fee_voucher_pct: int = 5
    fee_payout: str = "lightning"
    fee_sweep_address: str = ""
    fee_unvouched_share: str = "worker"
    max_hold_seconds: int = 6 * 3600
    founder_arbiter: str = ""
    backup_arbiter: str = ""
    timestamp_mode: str = "local-test"
    score_clean_completion: int = 1
    score_clean_vouch: int = 2
    score_lost_dispute: int = -5

    def __post_init__(self) -> None:
        if self.bitcoin_network not in ALLOWED_NETWORKS:
            raise ConfigError(
                f"bitcoin network must be one of {ALLOWED_NETWORKS}, got {self.bitcoin_network!r}"
            )
        if self.timestamp_mode not in TIMESTAMP_MODES:
            raise ConfigError(f"timestamps.mode must be one of {TIMESTAMP_MODES}")
        for f in fields(self):
            v = getattr(self, f.name)
            if f.type == "int" and (not isinstance(v, int) or isinstance(v, bool)):
                raise ConfigError(f"{f.name} must be a whole number")
        for name in ("dispute_window_seconds", "dispute_window_blocks", "bond_timelock_blocks",
                     "bond_min_sats", "max_active_vouches", "max_hold_seconds"):
            if getattr(self, name) <= 0:
                raise ConfigError(f"{name} must be positive")
        # T > D, checked both in blocks and in wall-clock terms.
        if self.bond_timelock_blocks <= self.dispute_window_blocks:
            raise ConfigError("bond timelock T must be longer than dispute window D (blocks)")
        if self.bond_timelock_blocks * SECONDS_PER_BLOCK <= self.dispute_window_seconds:
            raise ConfigError("bond timelock T must be longer than dispute window D (time)")
        if self.bond_min_sats > self.bond_max_sats:
            raise ConfigError("bond min must not exceed bond max")
        pcts = (self.fee_worker_pct, self.fee_network_pct, self.fee_voucher_pct)
        if any(p < 0 for p in pcts) or sum(pcts) != 100:
            raise ConfigError("fee split must be non-negative and add up to 100")
        for name in ("founder_arbiter", "backup_arbiter"):
            v = getattr(self, name)
            if v and not _HEX64.match(v):
                raise ConfigError(f"{name} must be empty or a 64-char lowercase hex public key")
        if self.fee_payout not in FEE_PAYOUTS:
            raise ConfigError(f"fees.payout must be one of {FEE_PAYOUTS}")
        if self.fee_unvouched_share not in UNVOUCHED_SHARE:
            raise ConfigError(f"fees.unvouched_share must be one of {UNVOUCHED_SHARE}")
        if self.fee_sweep_address and not self.fee_sweep_address.lower().startswith(
                TEST_ADDRESS_PREFIX[self.bitcoin_network]):
            raise ConfigError(f"fees.sweep_address must be a {self.bitcoin_network} address")
        if self.score_lost_dispute > 0 or self.score_clean_completion < 0 or self.score_clean_vouch < 0:
            raise ConfigError("scoring: rewards must be >= 0 and the lost-dispute weight <= 0")
        if self.founder_arbiter and self.founder_arbiter == self.backup_arbiter:
            raise ConfigError("founder and backup arbiter must be different keys")


# (toml section, toml key) -> Config field
_MAPPING = {
    ("network", "bitcoin"): "bitcoin_network",
    ("disputes", "window_seconds"): "dispute_window_seconds",
    ("disputes", "window_blocks"): "dispute_window_blocks",
    ("bond", "timelock_blocks"): "bond_timelock_blocks",
    ("bond", "min_sats"): "bond_min_sats",
    ("bond", "max_sats"): "bond_max_sats",
    ("vouching", "max_active_per_key"): "max_active_vouches",
    ("fees", "worker"): "fee_worker_pct",
    ("fees", "network"): "fee_network_pct",
    ("fees", "voucher"): "fee_voucher_pct",
    ("fees", "payout"): "fee_payout",
    ("fees", "sweep_address"): "fee_sweep_address",
    ("fees", "unvouched_share"): "fee_unvouched_share",
    ("lightning", "max_hold_seconds"): "max_hold_seconds",
    ("arbiters", "founder"): "founder_arbiter",
    ("arbiters", "backup"): "backup_arbiter",
    ("timestamps", "mode"): "timestamp_mode",
    ("scoring", "clean_completion"): "score_clean_completion",
    ("scoring", "clean_vouch"): "score_clean_vouch",
    ("scoring", "lost_dispute"): "score_lost_dispute",
}


def load_config(path: Path | str | None = None) -> Config:
    path = Path(path) if path else DEFAULT_CONFIG_PATH
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)
    values = {}
    for section, table in raw.items():
        if not isinstance(table, dict):
            raise ConfigError(f"unexpected top-level value {section!r}")
        for key, value in table.items():
            field = _MAPPING.get((section, key))
            if field is None:
                raise ConfigError(f"unknown setting [{section}] {key}")
            values[field] = value
    return Config(**values)
