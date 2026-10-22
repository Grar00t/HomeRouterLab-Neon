"""Read-only home network observations and conservative publication planning.

No router writes, discovery scans, credential access, proxy use, or public probes.
All WAN addresses passed to analysis remain explicitly supplied evidence.
"""
from __future__ import annotations

import datetime as dt
import html
import http.client
import ipaddress
import json
import platform
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.parse import urlsplit, urlunsplit


SCHEMA = "homerouterlab.snapshot/1"
RFC1918 = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
SHARED = ipaddress.ip_network("100.64.0.0/10")
PROTOCOL_ASSIGNMENTS = ipaddress.ip_network("192.0.0.0/24")
PROTOCOL_GLOBAL_EXCEPTIONS = {
    ipaddress.IPv4Address("192.0.0.9"), ipaddress.IPv4Address("192.0.0.10")}
MAX_BODY = 65536

# Fixed script, never combined with user-provided shell text.
WINDOWS_SCRIPT = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$adapters=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
 Select-Object InterfaceIndex,Description,IPAddress,IPSubnet,DefaultIPGateway,DNSServerSearchOrder)
$routes=@();$routeError=$null
try {
 $metrics=@{}
 Get-NetIPInterface -AddressFamily IPv4 | ForEach-Object {$metrics[[int]$_.InterfaceIndex]=[int]$_.InterfaceMetric}
 $routes=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | ForEach-Object {
   [pscustomobject]@{InterfaceIndex=[int]$_.InterfaceIndex;InterfaceAlias=$_.InterfaceAlias;
    NextHop=$_.NextHop;RouteMetric=[int]$_.RouteMetric;InterfaceMetric=$metrics[[int]$_.InterfaceIndex]}
  })
} catch {$routeError=$_.Exception.GetType().Name}
[pscustomobject]@{Adapters=$adapters;Routes=$routes;RouteError=$routeError} |
 ConvertTo-Json -Depth 6 -Compress
"""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _rfc1918(address: ipaddress._BaseAddress) -> bool:
    return address.version == 4 and any(address in block for block in RFC1918)


def _global_candidate(address: ipaddress._BaseAddress) -> bool:
    # Keep special-purpose IPv4 classification consistent on Python versions
    # preceding the ipaddress fixes, and reject reserved IPv6 address space.
    if (address.version == 4 and address in PROTOCOL_ASSIGNMENTS
            and address not in PROTOCOL_GLOBAL_EXCEPTIONS):
        return False
    return address.is_global and not address.is_multicast and not address.is_reserved


def _kind(name: str) -> str:
    value = name.lower()
    if any(s in value for s in ("tailscale", "wireguard", "openvpn", "zerotier", "vpn")):
        return "overlay"
    if any(s in value for s in ("vethernet", "hyper-v", "virtual", "docker", "loopback", "wsl")):
        return "virtual"
    return "physical"


def _prefix(address: str, mask: str | int | None) -> int | None:
    try:
        if mask is None:
            return None
        return ipaddress.ip_network(f"{address}/{mask}", strict=False).prefixlen
    except (ValueError, TypeError):
        return None


def _normalize_windows(payload: dict) -> tuple[list, list, list]:
    interfaces, routes, errors = [], [], []
    route_by_index = {int(r["InterfaceIndex"]): r for r in _list(payload.get("Routes"))}
    for row in _list(payload.get("Adapters")):
        index = int(row.get("InterfaceIndex", 0))
        description = str(row.get("Description") or "Unknown interface")
        route = route_by_index.get(index, {})
        name = str(route.get("InterfaceAlias") or description)
        item = {"index": index, "name": name, "description": description,
                "ipv4": [], "ipv6": [], "gateways": [],
                "dns_servers": _list(row.get("DNSServerSearchOrder")),
                "kind": _kind(description + " " + name)}
        masks = _list(row.get("IPSubnet"))
        for i, raw in enumerate(_list(row.get("IPAddress"))):
            try:
                address = ipaddress.ip_address(str(raw).split("%", 1)[0])
            except ValueError:
                continue
            mask = masks[i] if i < len(masks) else None
            item[f"ipv{address.version}"].append({
                "address": str(address), "prefix_length": _prefix(str(address), mask)})
        for raw in _list(row.get("DefaultIPGateway")):
            try:
                address = ipaddress.ip_address(raw)
                if address.version == 4 and not address.is_unspecified:
                    item["gateways"].append(str(address))
            except ValueError:
                continue
        interfaces.append(item)
    for row in _list(payload.get("Routes")):
        try:
            next_hop = str(ipaddress.IPv4Address(row["NextHop"]))
            route_metric = int(row.get("RouteMetric", 0))
            interface_metric = row.get("InterfaceMetric")
            interface_metric = int(interface_metric) if interface_metric is not None else None
            routes.append({"interface_index": int(row["InterfaceIndex"]),
                           "interface_name": str(row.get("InterfaceAlias") or ""),
                           "next_hop": next_hop, "route_metric": route_metric,
                           "interface_metric": interface_metric,
                           "total_metric": route_metric + interface_metric
                           if interface_metric is not None else None})
        except (KeyError, ValueError, TypeError):
            errors.append({"stage": "routes", "error": "Malformed route omitted"})
    if payload.get("RouteError"):
        errors.append({"stage": "routes", "error": str(payload["RouteError"])})
    return interfaces, routes, errors


def _run_json(argv: list[str], timeout: float = 15) -> Any:
    result = subprocess.run(argv, capture_output=True, timeout=timeout, check=False,
                            shell=False)
    if result.returncode:
        raise RuntimeError(f"Collector exit {result.returncode}")
    return json.loads(result.stdout.decode("utf-8-sig", errors="strict").strip())


def _collect_windows() -> tuple[list, list, list]:
    return _normalize_windows(_run_json([
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_SCRIPT]))


def _collect_linux() -> tuple[list, list, list]:
    rows = _run_json(["ip", "-j", "address", "show"], timeout=5)
    route_rows = _run_json(["ip", "-j", "-4", "route", "show", "default"], timeout=5)
    interfaces, routes = [], []
    for row in rows:
        item = {"index": row["ifindex"], "name": row["ifname"],
                "description": row.get("link_type", ""), "ipv4": [], "ipv6": [],
                "gateways": [], "dns_servers": [], "kind": _kind(row["ifname"])}
        for a in row.get("addr_info", []):
            key = "ipv4" if a.get("family") == "inet" else "ipv6"
            if a.get("local"):
                item[key].append({"address": a["local"], "prefix_length": a.get("prefixlen")})
        interfaces.append(item)
    by_name = {i["name"]: i for i in interfaces}
    for row in route_rows:
        interface = by_name.get(row.get("dev"), {})
        metric = int(row.get("metric", 0))
        routes.append({"interface_index": interface.get("index"),
                       "interface_name": row.get("dev", ""), "next_hop": row.get("gateway", "0.0.0.0"),
                       "route_metric": metric, "interface_metric": 0, "total_metric": metric})
        if interface and row.get("gateway"):
            interface["gateways"].append(row["gateway"])
    return interfaces, routes, []


def collect_snapshot(probe_gateway: bool = True) -> dict:
    """Collect local network state. Collection failures are explicit, never fabricated."""
    snapshot = {"schema": SCHEMA, "collected_utc": utc_now(),
                "host": {"name": socket.gethostname(), "platform": platform.system(),
                         "python": platform.python_version()},
                "interfaces": [], "default_route": None, "primary_ipv4": None,
                "gateway_probe": None, "observations": [], "errors": [],
                "read_only": True}
    try:
        if sys.platform == "win32":
            interfaces, routes, errors = _collect_windows()
        elif sys.platform.startswith("linux"):
            interfaces, routes, errors = _collect_linux()
        else:
            raise RuntimeError("This version collects interfaces on Windows and Linux only")
        snapshot["interfaces"] = interfaces
        snapshot["errors"] = errors
        # Unknown interface metrics cannot safely outrank fully observed metrics.
        routes.sort(key=lambda r: (r["total_metric"] is None,
                                   r["total_metric"] if r["total_metric"] is not None else 0))
        if any(r["total_metric"] is None for r in routes):
            snapshot["observations"].append("Some route metrics are unavailable; selected default route is provisional")
        if routes:
            snapshot["default_route"] = routes[0]
            if len(routes) > 1 and routes[0]["total_metric"] == routes[1]["total_metric"]:
                snapshot["observations"].append("Equal-cost default routes observed; selected first listed route")
            interface = next((i for i in interfaces if i["index"] == routes[0]["interface_index"]), None)
            if interface:
                snapshot["primary_ipv4"] = next((a["address"] for a in interface["ipv4"]
                                                  if not ipaddress.ip_address(a["address"]).is_loopback), None)
            if probe_gateway:
                address = ipaddress.ip_address(routes[0]["next_hop"])
                if _rfc1918(address):
                    snapshot["gateway_probe"] = probe_gateway_address(str(address))
                else:
                    snapshot["observations"].append("Gateway probing skipped: next hop is not RFC1918 IPv4")
        else:
            snapshot["observations"].append("No IPv4 default route observed")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        snapshot["errors"].append({"stage": "collector", "error": str(exc)[:180],
                                   "type": type(exc).__name__})
    return snapshot


def _tcp_probe(address: str, port: int, timeout: float = 1.5) -> dict:
    start = time.monotonic()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return {"reachable": True, "latency_ms": round((time.monotonic()-start)*1000, 2), "error": None}
    except OSError as exc:
        return {"reachable": False, "latency_ms": round((time.monotonic()-start)*1000, 2),
                "error": type(exc).__name__}


def _target(url: str) -> tuple[str, str, int, str]:
    if not isinstance(url, str) or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise ValueError("URL contains whitespace or control characters")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid service URL") from exc
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Use an explicit http:// or https:// local service URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in service URLs are not accepted")
    if parsed.fragment or parsed.query:
        raise ValueError("Use a service URL without query or fragment")
    hostname = parsed.hostname.lower()
    if hostname == "localhost":
        address = ipaddress.ip_address("127.0.0.1")
    else:
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as exc:
            raise ValueError("Use localhost, a numeric loopback address, or an RFC1918 address") from exc
    if not (address.is_loopback or _rfc1918(address)):
        raise ValueError("Only loopback and RFC1918 service addresses are accepted")
    port = port if port is not None else (443 if parsed.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    hostpart = f"[{address}]" if address.version == 6 else str(address)
    canonical = urlunsplit((parsed.scheme, f"{hostpart}:{port}", parsed.path or "/", "", ""))
    return canonical, str(address), port, "loopback" if address.is_loopback else "private_lan"


def _http_probe(url: str, timeout: float = 3) -> dict:
    """Bounded GET without proxies or redirects; no response headers/cookies retained."""
    canonical, address, port, _ = _target(url)
    parsed = urlsplit(canonical)
    start = time.monotonic()
    connection = (http.client.HTTPSConnection(address, port, timeout=timeout,
                                             context=ssl.create_default_context())
                  if parsed.scheme == "https" else
                  http.client.HTTPConnection(address, port, timeout=timeout))
    expired = threading.Event()
    socket_holder: list[socket.socket] = []

    def abort() -> None:
        expired.set()
        sock = socket_holder[0] if socket_holder else connection.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    timer = threading.Timer(timeout, abort)
    timer.daemon = True
    timer.start()
    response = None
    result = {"status": None, "title": None, "vendor_hints": [], "bytes_read": 0,
              "truncated": False, "redirect_blocked": False, "latency_ms": None, "error": None}
    try:
        connection.connect()
        if connection.sock is not None:
            socket_holder.append(connection.sock)
            connection.sock.settimeout(max(0.001, timeout - (time.monotonic() - start)))
        connection.request("GET", parsed.path or "/", headers={
            "User-Agent": "HomeRouterLab/0.1 (local read-only diagnostic)",
            "Accept": "text/html,application/json;q=0.8,*/*;q=0.1", "Connection": "close"})
        response = connection.getresponse()
        result["status"] = response.status
        if 300 <= response.status < 400:
            result["redirect_blocked"] = True
            result["error"] = "Redirect not followed"
            return result
        chunks, size = [], 0
        while size < MAX_BODY:
            if response.isclosed() or response.length == 0:
                break
            remaining = timeout - (time.monotonic() - start)
            if remaining <= 0 or expired.is_set():
                raise TimeoutError("HTTP probe deadline reached")
            if socket_holder:
                socket_holder[0].settimeout(remaining)
            chunk = response.read1(min(8192, MAX_BODY - size))
            if not chunk:
                if expired.is_set():
                    raise TimeoutError("HTTP probe deadline reached")
                if response.length not in (None, 0):
                    raise http.client.IncompleteRead(b"".join(chunks), response.length)
                break
            chunks.append(chunk)
            size += len(chunk)
        result["bytes_read"] = size
        result["truncated"] = size >= MAX_BODY
        text = b"".join(chunks).decode("utf-8", errors="replace")
        match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        if match:
            result["title"] = re.sub(r"[\x00-\x1f\x7f]", " ", html.unescape(match.group(1))).strip()[:120]
        result["vendor_hints"] = [name for name, pattern in (
            ("TP-Link", r"tp[- ]?link|tplinkwifi"), ("Huawei", r"huawei|hilink"))
            if re.search(pattern, text, re.I)]
    except (OSError, ValueError, http.client.HTTPException) as exc:
        result["error"] = "TimeoutError" if expired.is_set() else type(exc).__name__
    finally:
        timer.cancel()
        if response is not None:
            response.close()
        connection.close()
        result["latency_ms"] = round((time.monotonic() - start) * 1000, 2)
    return result


def probe_gateway_address(address: str) -> dict:
    """Probe only a private gateway already discovered from the local default route."""
    parsed = ipaddress.ip_address(address)
    if not _rfc1918(parsed):
        raise ValueError("Gateway probe requires an RFC1918 IPv4 next hop")
    ports = [{"port": port, **_tcp_probe(address, port)} for port in (80, 443)]
    http = _http_probe(f"http://{address}/") if ports[0]["reachable"] else None
    return {"address": address, "ports": ports, "http": http,
            "model": "UNKNOWN", "authentication_used": False, "configuration_changed": False}


def probe_service(url: str) -> dict:
    canonical, address, port, scope = _target(url)
    tcp = _tcp_probe(address, port)
    http = _http_probe(canonical) if tcp["reachable"] else None
    return {"url": canonical, "address": address, "port": port, "bind_scope": scope,
            "bind_scope_basis": "Target address only; process listen binding not inspected",
            "tcp": tcp, "http": http, "probed_utc": utc_now(),
            "public_reachability": "NOT_TESTED", "configuration_changed": False}


def analyze_snapshot(snapshot: dict, wan_ip: str | None = None,
                     wan_source: str | None = None) -> dict:
    findings = []

    def add(code: str, status: str, message: str, evidence: Any = None) -> None:
        findings.append({"code": code, "status": status, "message": message, "evidence": evidence})

    route = snapshot.get("default_route")
    if route:
        add("DEFAULT_ROUTE", "OBSERVED", "An IPv4 default route is present", route.get("next_hop"))
    else:
        add("DEFAULT_ROUTE", "UNKNOWN", "No IPv4 default route was established")
    local = snapshot.get("primary_ipv4")
    if local:
        try:
            if _rfc1918(ipaddress.ip_address(local)):
                add("PRIVATE_LAN", "OBSERVED", "Private PC address; this does not establish ISP CGNAT", local)
        except ValueError:
            add("LOCAL_ADDRESS", "UNKNOWN", "Malformed snapshot address")
    overlay = [i.get("name") for i in snapshot.get("interfaces", []) if i.get("kind") == "overlay"]
    if overlay:
        add("OVERLAY_INTERFACES", "OBSERVED", "Overlay interface addresses do not establish ISP WAN addressing", overlay)
    ipv4 = {"status": "UNKNOWN", "wan_ip": None, "wan_source": None,
            "public_reachability": "NOT_TESTED"}
    if wan_ip is not None:
        try:
            address = ipaddress.IPv4Address(wan_ip)
        except ValueError as exc:
            raise ValueError("WAN address must be a numeric IPv4 address") from exc
        ipv4.update(wan_ip=str(address), wan_source=wan_source or "user-supplied; not independently verified")
        if address in SHARED:
            ipv4["status"] = "SHARED_ADDRESS_SPACE"
            add("WAN_SHARED", "SUPPLIED", "Supplied WAN address is RFC6598 shared space; ISP topology and inbound mapping support remain unverified", str(address))
        elif _rfc1918(address):
            ipv4["status"] = "UPSTREAM_NAT_EVIDENCE"
            add("WAN_PRIVATE", "SUPPLIED", "Supplied WAN address is private: an upstream private segment is indicated; device count and ISP CGNAT are not established", str(address))
        elif _global_candidate(address):
            ipv4["status"] = "GLOBAL_IPV4_CANDIDATE"
            add("WAN_GLOBAL", "SUPPLIED", "Supplied WAN address is globally scoped; firewall, forwarding, and off-LAN reachability remain unverified", str(address))
        else:
            ipv4["status"] = "NON_GLOBAL_WAN_ADDRESS"
            add("WAN_NON_GLOBAL", "SUPPLIED", "Supplied address is not a public unicast IPv4 candidate", str(address))
    else:
        add("WAN_UNKNOWN", "UNKNOWN", "Router WAN IPv4 has not been observed; do not infer NAT layers from PC addresses")
    global_v6 = []
    for interface in snapshot.get("interfaces", []):
        if interface.get("kind") in ("overlay", "virtual"):
            continue
        for item in interface.get("ipv6", []):
            try:
                address = ipaddress.IPv6Address(item["address"])
                if _global_candidate(address):
                    global_v6.append({"interface": interface.get("name"), "address": str(address)})
            except (ValueError, KeyError):
                continue
    ipv6 = {"status": "GLOBAL_IPV6_CANDIDATE" if global_v6 else "NO_GLOBAL_IPV6_OBSERVED",
            "global_addresses": global_v6, "inbound_firewall": "UNKNOWN",
            "public_reachability": "NOT_TESTED"}
    add("IPV6_SCOPE", "OBSERVED", "Global IPv6 presence does not establish inbound firewall permission"
        if global_v6 else "No global IPv6 address observed on non-overlay physical interfaces", global_v6)
    for error in snapshot.get("errors", []):
        add("COLLECTOR_ERROR", "UNKNOWN", "A collection step failed", error)
    return {"schema": "homerouterlab.analysis/1", "findings": findings,
            "ipv4_publication": ipv4, "ipv6_publication": ipv6,
            "public_reachability": "NOT_TESTED"}


def build_plan(snapshot: dict, service: dict | str | None = None,
               wan_ip: str | None = None) -> dict:
    """Return a complete non-executing decision checklist; no configuration commands."""
    analysis = analyze_snapshot(snapshot, wan_ip=wan_ip)
    if isinstance(service, str):
        canonical, address, port, scope = _target(service)
        service = {"url": canonical, "address": address, "port": port, "bind_scope": scope,
                   "tcp": None, "http": None, "public_reachability": "NOT_TESTED"}
    steps = [
        {"number": 1, "action": "Identify the exact TP-Link and Huawei model, firmware, and router/AP roles", "status": "REQUIRED"},
        {"number": 2, "action": "Read each routing device's WAN address and upstream gateway from its supported management interface", "status": "REQUIRED"},
        {"number": 3, "action": "Check the service's listening address, authentication, and intended audience", "status": "REQUIRED"},
        {"number": 4, "action": "Choose an access method from observed WAN/IPv6 capabilities", "status": "PENDING_EVIDENCE"},
        {"number": 5, "action": "Before any change, record the exact current settings and a device-supported recovery procedure", "status": "REQUIRED_BEFORE_CHANGE"},
        {"number": 6, "action": "Validate inbound access from a separate network after separately authorized changes", "status": "NOT_TESTED"}]
    if service and service.get("bind_scope") == "loopback":
        steps.insert(3, {"number": 0, "action": "The supplied target is loopback; direct router forwarding to it is not established. Inspect the actual listener before choosing any binding change", "status": "REQUIRED"})
    for number, step in enumerate(steps, 1):
        step["number"] = number
    choices = [
        {"method": "Direct IPv4", "status": "CANDIDATE" if analysis["ipv4_publication"]["status"] == "GLOBAL_IPV4_CANDIDATE" else "REQUIRES_WAN_EVIDENCE",
         "requirements": ["Reachable public WAN path", "Supported forwarding on every applicable NAT layer", "Explicit firewall policy", "Off-LAN verification"]},
        {"method": "Direct IPv6", "status": "CANDIDATE" if analysis["ipv6_publication"]["global_addresses"] else "NO_GLOBAL_ADDRESS_OBSERVED",
         "requirements": ["Global service IPv6", "Router and host inbound firewall permission", "Client IPv6 connectivity", "Off-LAN verification"]},
        {"method": "ISP-supported PCP", "status": "SUPPORT_UNKNOWN",
         "requirements": ["Explicit ISP and router PCP support", "Mapping lifetime and renewal", "Off-LAN verification"]},
        {"method": "Private overlay", "status": "EXISTING_INTERFACE" if any(i.get("kind") == "overlay" for i in snapshot.get("interfaces", [])) else "OPTION_ONLY",
         "requirements": ["Authorized participating clients", "Reviewed access policy", "Private service verification"]}]
    return {"schema": "homerouterlab.plan/1", "created_utc": utc_now(),
            "execute": False, "public_reachability": "NOT_TESTED",
            "analysis": analysis, "service": service, "choices": choices, "steps": steps,
            "limits": ["No router or firewall changes are performed", "No atomic multi-device rollback is claimed", "Local success does not establish public reachability", "PCP and NAT mapping leases can expire and require renewal"]}
