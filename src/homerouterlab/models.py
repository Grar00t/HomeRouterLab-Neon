"""Typed result objects for the HomeRouterLab WAN probe."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(slots=True)
class ProbeResult:
    layer: str
    status: str
    wan_ip: str | None = None
    host: str | None = None
    error: str | None = None
    notes: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)