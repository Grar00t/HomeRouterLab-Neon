"""A fixed, bounded IPv4 route observation; never a NAT diagnosis.

The only active command probes at most four hops on the route to 1.1.1.1.
No installation, router configuration, DNS lookup, or arbitrary target is used.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import re
import subprocess
import sys
from typing import Any


SCHEMA = "homerouterlab.trace/1"
TARGET = "1.1.1.1"
MAX_HOPS = 4
TIMEOUT_SECONDS = 12
MAX_RAW_CHARS = 8192
LIMITATION = "Router hops do not prove number of NAT layers or WAN assignment"
TRACE_ARGV = ["tracert", "-4", "-d", "-h", "4", "-w", "500", TARGET]

_RFC1918 = tuple(ipaddress.IPv4Network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_SHARED = ipaddress.IPv4Network("100.64.0.0/10")
_PROTOCOL_ASSIGNMENTS = ipaddress.IPv4Network("192.0.0.0/24")
_PROTOCOL_GLOBAL_EXCEPTIONS = {
    ipaddress.IPv4Address("192.0.0.9"), ipaddress.IPv4Address("192.0.0.10")}
_HOP_LINE = re.compile(r"^\s*(\d+)\s+(.+?)\s*$")
_LATENCY = re.compile(r"(?<!\S)(<)?\s*(\d+(?:[.,]\d+)?)\s*ms\b", re.IGNORECASE)
_IP_TOKEN = re.compile(r"^\[?(?:\d{1,3}\.){3}\d{1,3}\]?$")


def _scope(address: ipaddress.IPv4Address) -> str:
    if any(address in block for block in _RFC1918):
        return "rfc1918"
    if address in _SHARED:
        return "shared"
    # Python < 3.13 classified some protocol-assignment addresses differently.
    if address in _PROTOCOL_ASSIGNMENTS and address not in _PROTOCOL_GLOBAL_EXCEPTIONS:
        return "other"
    if (address.is_global and not address.is_multicast and not address.is_reserved
            and not address.is_unspecified and not address.is_loopback
            and not address.is_link_local):
        return "global"
    return "other"


def parse_trace(text: str) -> list[dict[str, Any]]:
    """Parse numeric IPv4 hop rows from the fixed four-hop Windows command.

    Headers and malformed rows are ignored. Entirely timed-out rows remain as
    observations with a null address. For ``<1 ms``, the numeric value is an
    upper bound, identified by the parallel ``latency_upper_bounds`` list.
    A hop address describes an ICMP reply, not a router's WAN assignment.
    """
    hops: list[dict[str, Any]] = []
    seen: set[int] = set()
    for line in text[:MAX_RAW_CHARS].splitlines():
        match = _HOP_LINE.match(line)
        if not match:
            continue
        ttl, body = int(match.group(1)), match.group(2)
        if not 1 <= ttl <= MAX_HOPS or ttl in seen:
            continue
        tokens = body.split()
        candidates = [token for token in tokens if _IP_TOKEN.fullmatch(token)]
        latencies = _LATENCY.findall(body)
        # A valid -d hop has a single address, never a header's destination.
        if len(candidates) == 1:
            try:
                address = ipaddress.IPv4Address(candidates[0].strip("[]"))
            except ipaddress.AddressValueError:
                continue
            # Do not accept arbitrary numbered prose containing an IP address.
            if not latencies and "*" not in tokens:
                continue
            hops.append({
                "ttl": ttl, "address": str(address), "scope": _scope(address),
                "latency_ms": [float(value.replace(",", ".")) for _, value in latencies],
                "latency_upper_bounds": [bool(bound) for bound, _ in latencies],
                "timeout": False,
            })
        elif not candidates and tokens[:3] == ["*", "*", "*"]:
            hops.append({"ttl": ttl, "address": None, "scope": "other",
                         "latency_ms": [], "latency_upper_bounds": [], "timeout": True})
        else:
            continue
        seen.add(ttl)
    return sorted(hops, key=lambda hop: hop["ttl"])


def _decode_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return value.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        try:
            # Windows' oem codec follows the system OEM code page, including
            # localized tracert output. It is unavailable on Unix runtimes.
            return value.decode("oem", errors="replace")
        except LookupError:
            return value.decode("cp437", errors="replace")


def _record_output(result: dict, stdout: bytes | str | None,
                   stderr: bytes | str | None = None) -> None:
    output = _decode_output(stdout)
    error_output = _decode_output(stderr)
    if error_output:
        output += ("\n" if output else "") + error_output
    result["raw_output"] = output[:MAX_RAW_CHARS]
    result["raw_output_truncated"] = len(output) > MAX_RAW_CHARS
    result["hops"] = parse_trace(result["raw_output"])


def trace_route() -> dict:
    """Observe at most four hops on Windows with a strict twelve-second bound.

    COMPLETE means the fixed destination replied, not that inbound access is
    available. Successful execution without a destination reply is PARTIAL.
    Other platforms explicitly return UNAVAILABLE without running a process.
    """
    result = {
        "schema": SCHEMA, "target": TARGET,
        "observed_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "status": "UNAVAILABLE", "max_hops": MAX_HOPS, "hops": [],
        "raw_output": "", "raw_output_truncated": False, "error": None,
        "limitation": LIMITATION,
    }
    if sys.platform != "win32":
        result["error"] = "Bounded route tracing is available on Windows only; no command was run"
        return result
    try:
        process = subprocess.run(list(TRACE_ARGV), capture_output=True,
                                 timeout=TIMEOUT_SECONDS, check=False, shell=False)
        _record_output(result, process.stdout, process.stderr)
        if process.returncode:
            result["status"] = "PARTIAL" if result["hops"] else "ERROR"
            result["error"] = f"tracert exited with code {process.returncode}"
        elif not result["hops"]:
            result["status"] = "ERROR"
            result["error"] = "tracert returned no parseable IPv4 hop observations"
        elif any(hop["address"] == TARGET for hop in result["hops"]):
            result["status"] = "COMPLETE"
        else:
            result["status"] = "PARTIAL"
    except subprocess.TimeoutExpired as exc:
        _record_output(result, exc.stdout, exc.stderr)
        result["status"] = "PARTIAL" if result["hops"] else "ERROR"
        result["error"] = f"tracert exceeded the {TIMEOUT_SECONDS}-second command timeout"
    except FileNotFoundError:
        result["error"] = "Windows tracert executable was not found"
    except OSError as exc:
        result["status"] = "ERROR"
        result["error"] = f"tracert could not run: {type(exc).__name__}"
    return result
