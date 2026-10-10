"""Local on-disk store (default ./data, gitignored).

    data/events/<event_id>.json   public events (safe to publish)
    data/proofs/<event_id>.ots    OpenTimestamps proofs
    data/private/<job_id>.json    salts for hash commitments - NEVER publish
"""
from __future__ import annotations

import json
from pathlib import Path

from . import schema


class Store:
    def __init__(self, home: Path):
        self.home = Path(home)
        self.events_dir = self.home / "events"
        self.proofs_dir = self.home / "proofs"
        self.private_dir = self.home / "private"

    def save_event(self, event: dict) -> Path:
        schema.validate(event)  # never write anything outside the public schema
        self.events_dir.mkdir(parents=True, exist_ok=True)
        path = self.events_dir / f"{event['id']}.json"
        path.write_text(json.dumps(event, indent=2), encoding="utf-8")
        return path

    def load_events(self) -> list[dict]:
        if not self.events_dir.exists():
            return []
        return [json.loads(p.read_text(encoding="utf-8"))
                for p in sorted(self.events_dir.glob("*.json"))]

    def get_event(self, event_id: str) -> dict:
        path = self.events_dir / f"{event_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"no event {event_id}")
        return json.loads(path.read_text(encoding="utf-8"))

    def proof_path(self, event_id: str) -> Path:
        return self.proofs_dir / f"{event_id}.ots"

    def save_proof(self, event_id: str, data: bytes) -> Path:
        self.proofs_dir.mkdir(parents=True, exist_ok=True)
        path = self.proof_path(event_id)
        path.write_bytes(data)
        return path

    def save_salt(self, job_id: str, label: str, hash_hex: str, salt_hex: str) -> None:
        """Keep the salt so the party can later prove what a hash committed to."""
        self.private_dir.mkdir(parents=True, exist_ok=True)
        path = self.private_dir / f"{job_id}.json"
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        data.setdefault(label, []).append({"hash": hash_hex, "salt": salt_hex})
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
