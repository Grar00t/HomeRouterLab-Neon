"""Deterministic JSON report writer with SHA-256 of the payload."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .models import utc_now


def build_payload(
    result: dict, started_utc: str, notes: str = "Read-only probe. No configuration change."
) -> dict:
    body = {
        "schema": "homerouterlab.wan-probe/2",
        "started_utc": started_utc,
        "finished_utc": utc_now(),
        "result": result,
        "notes": notes,
    }
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    body["payload_sha256"] = hashlib.sha256(canonical).hexdigest()
    return body


def write(payload: dict, out_dir: Path, stamp: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"wan-probe-{stamp}.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path