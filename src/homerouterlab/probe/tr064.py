"""TR-064 / UPnP IGD SOAP probe (read-only)."""
from __future__ import annotations

import re
import socket
from typing import Iterable

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

from ..models import ProbeResult

SERVICE_URNS = (
    "urn:dslforum-org:service:WANIPConnection:1",
    "urn:dslforum-org:service:WANPPPConnection:1",
)
DESC_PATHS = ("/rootDesc.xml", "/tr64desc.xml", "/igd.xml")
CONTROL_HINTS = ("WANIPConnection", "WANPPPConnection")
DEFAULT_PORTS = (49000, 5000)


def _soap_get_external_ip(host: str, port: int, control_path: str, urn: str, timeout: float) -> str | None:
    body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
        f'<s:Body><u:GetExternalIPAddress xmlns:u="{urn}"/></s:Body>'
        "</s:Envelope>"
    )
    headers = {
        "SOAPAction": f"{urn}#GetExternalIPAddress",
        "Content-Type": 'text/xml; charset="utf-8"',
    }
    r = requests.post(
        f"http://{host}:{port}{control_path}",
        data=body.encode("utf-8"),
        headers=headers,
        timeout=timeout,
    )
    if r.status_code != 200:
        return None
    header_ip = r.headers.get("X-External-IP-Address") or r.headers.get("x-external-ip-address")
    if header_ip:
        return header_ip.strip()
    match = re.search(r"<NewExternalIPAddress>([^<]+)</NewExternalIPAddress>", r.text)
    return match.group(1).strip() if match else None


def _discover_control_paths(host: str, port: int, timeout: float) -> Iterable[str]:
    for path in DESC_PATHS:
        try:
            r = requests.get(f"http://{host}:{port}{path}", timeout=timeout)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        for hint in CONTROL_HINTS:
            for m in re.finditer(r"<controlURL>([^<]*" + hint + r"[^<]*)</controlURL>", r.text, re.I):
                yield m.group(1).strip()


def probe(hosts: list[str], timeout: float = 3.0, ports: tuple[int, ...] = DEFAULT_PORTS) -> ProbeResult:
    if requests is None:
        return ProbeResult(layer="tr064", status="SKIP", error="requests not installed")
    reachable: list[tuple[str, int]] = []
    for host in hosts:
        for port in ports:
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    reachable.append((host, port))
            except OSError:
                continue
    if not reachable:
        return ProbeResult(layer="tr064", status="NO_ACCESS", notes="SOAP ports closed on all hosts")
    for host, port in reachable:
        candidates = list(_discover_control_paths(host, port, timeout)) or [
            "/upnp/control/WANIPConnection1",
            "/upnp/control/WANPPPConnection1",
        ]
        for path in candidates:
            for urn in SERVICE_URNS:
                try:
                    ip = _soap_get_external_ip(host, port, path, urn, timeout)
                except Exception:
                    continue
                if ip and ip not in ("0.0.0.0", "255.255.255.255"):
                    return ProbeResult(
                        layer="tr064",
                        status="OBSERVED",
                        wan_ip=ip,
                        host=host,
                        evidence={"port": port, "control": path, "urn": urn},
                    )
    return ProbeResult(layer="tr064", status="NO_WAN_SERVICE", notes="SOAP reachable but no external IP")