"""External public-IP lookup (not the router WAN IP)."""
from __future__ import annotations

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

from ..models import ProbeResult

ENDPOINTS = (
    ("https://api.ipify.org?format=json", "json", "ip"),
    ("https://ifconfig.me/ip", "text", None),
    ("https://api64.ipify.org?format=json", "json", "ip"),
)


def probe(timeout: float = 5.0) -> ProbeResult:
    if requests is None:
        return ProbeResult(layer="external", status="SKIP", error="requests not installed")
    for url, kind, key in ENDPOINTS:
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code != 200:
                continue
            ip = r.json().get(key) if kind == "json" else r.text.strip()
        except Exception:
            continue
        if ip:
            return ProbeResult(
                layer="external",
                status="OBSERVED",
                wan_ip=ip,
                notes="public egress IP, not necessarily the router WAN IP",
            )
    return ProbeResult(layer="external", status="NO_ACCESS", notes="all endpoints failed")