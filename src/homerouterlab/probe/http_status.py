"""HTTP status-page scraper with strict IPv4 validation."""
from __future__ import annotations

import ipaddress
import re

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

from ..models import ProbeResult

PATHS = (
    "/", "/status", "/wan", "/cgi-bin/luci", "/html/status.asp",
    "/userRpm/StatusRpm.htm", "/cgi-bin/webproc", "/api/wan", "/status/wan",
)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
WAN_HINTS = ("wan", "internet", "external", "public", "wide area")
SHARED = ipaddress.IPv4Network("100.64.0.0/10")


def is_public_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return False
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return False
    if addr in SHARED:
        return False
    return True


def probe(hosts: list[str], timeout: float = 3.0) -> ProbeResult:
    if requests is None:
        return ProbeResult(layer="http", status="SKIP", error="requests not installed")
    hits: list[dict] = []
    for host in hosts:
        for path in PATHS:
            try:
                r = requests.get(f"http://{host}{path}", timeout=timeout, allow_redirects=True)
            except Exception:
                continue
            if r.status_code != 200 or len(r.text) < 128:
                continue
            low = r.text.lower()
            near_wan = any(h in low for h in WAN_HINTS)
            for ip in IPV4.findall(r.text):
                if not is_public_ipv4(ip):
                    continue
                hits.append(
                    {"host": host, "path": path, "ip": ip, "near_wan_hint": near_wan, "status": r.status_code}
                )
    if not hits:
        return ProbeResult(layer="http", status="NO_PUBLIC_IP", notes="no public IPv4 found in status pages")
    hits.sort(key=lambda h: (h["near_wan_hint"], h["ip"]), reverse=True)
    best = hits[0]
    return ProbeResult(
        layer="http",
        status="OBSERVED",
        wan_ip=best["ip"],
        host=best["host"],
        evidence={"path": best["path"], "candidates": hits[:10]},
        notes="public IPv4 found on an unauthenticated page; verify against router WAN UI",
    )