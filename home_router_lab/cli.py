"""Argument interface; argv data never becomes shell command text."""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path

from . import __version__
from .core import SCHEMA, analyze_snapshot, build_plan, collect_snapshot, probe_service, utc_now
from .reports import diff_snapshots, export_report, verify_receipt
from .render import render_result
from .selftest import run_selftest
from .trace import trace_route

MAX_INPUT_BYTES = 5 * 1024 * 1024


def load_snapshot(path: str) -> dict:
    source = Path(path)
    if source.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("Snapshot exceeds the 5 MiB input limit")
    data = json.loads(source.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ValueError(f"Expected a {SCHEMA} snapshot JSON file")
    if not isinstance(data.get("interfaces"), list):
        raise ValueError("Snapshot interfaces must be an array")
    return data


def _wan(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("WAN must be a numeric IPv4 address") from exc


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="home-router", description=(
        "HomeRouterLab Neon — inspect your network, test a local service, and keep verifiable evidence.\n"
        "تشخيص الشبكة المنزلية وخطة إتاحة مبنية على الأدلة. No router changes."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Global options precede the command. Run 'home-router selftest' for a real temporary local HTTP test.")
    p.add_argument("--version", action="version", version=f"HomeRouterLab Neon {__version__}")
    p.add_argument("--json", action="store_true", help="One JSON object; no color or progress output")
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="Terminal color policy")
    p.add_argument("--lang", choices=("en", "ar"), default="en", help="Summary language (technical fields stay English)")
    sub = p.add_subparsers(dest="command")
    doctor = sub.add_parser("doctor", help="Observe current interfaces, route, gateway, and evidence gaps")
    doctor.add_argument("--trace", action="store_true", help="Observe at most four hops toward 1.1.1.1 (Windows)")
    doctor.add_argument("--no-probe", action="store_true", help="Collect interface/route data without gateway TCP/HTTP probes")
    doctor.add_argument("--wan-ip", type=_wan, help="Actual router WAN IPv4, explicitly recorded as supplied evidence")
    doctor.add_argument("--output", metavar="DIR", help="Write snapshot, HTML, evidence and receipt into a fresh directory")
    probe = sub.add_parser("probe", help="Test one localhost or numeric RFC1918 HTTP(S) service")
    probe.add_argument("url", metavar="URL")
    plan = sub.add_parser("plan", help="Prepare a non-executing publication checklist for a local service")
    plan.add_argument("--service", required=True, metavar="URL")
    plan.add_argument("--snapshot", metavar="FILE", help="Use saved network evidence instead of collecting it")
    plan.add_argument("--wan-ip", type=_wan)
    plan.add_argument("--output", metavar="DIR", help="Export the snapshot, service probe, and plan")
    report = sub.add_parser("report", help="Render an existing snapshot without network requests")
    report.add_argument("snapshot", metavar="SNAPSHOT")
    report.add_argument("--output", metavar="DIR", help="Default: reports/report-<UTC timestamp>")
    report.add_argument("--wan-ip", type=_wan)
    diff = sub.add_parser("diff", help="Compare interface/route state while ignoring timestamps and probe latency")
    diff.add_argument("before", metavar="BEFORE")
    diff.add_argument("after", metavar="AFTER")
    verify = sub.add_parser("verify", help="Verify saved file digests; this is not a signature or external attestation")
    verify.add_argument("receipt", metavar="RECEIPT")
    sub.add_parser("selftest", help="Actually start, probe, report, tamper-check and stop a temporary loopback HTTP server")
    sub.add_parser("demo", help="Show an explicitly synthetic example; performs no network requests")
    return p


def synthetic_snapshot() -> dict:
    return {"schema": SCHEMA, "synthetic": True,
            "synthetic_reason": "Demonstration fixture; no network was inspected",
            "collected_utc": utc_now(), "host": {"name": "DEMO-ONLY", "platform": "Synthetic"},
            "interfaces": [{"index": 1, "name": "Demo LAN", "description": "Synthetic adapter",
                            "kind": "physical", "ipv4": [{"address": "192.168.50.10", "prefix_length": 24}],
                            "ipv6": [], "gateways": ["192.168.50.1"], "dns_servers": []}],
            "default_route": {"interface_index": 1, "interface_name": "Demo LAN",
                              "next_hop": "192.168.50.1", "route_metric": 0, "interface_metric": 25, "total_metric": 25},
            "primary_ipv4": "192.168.50.10", "gateway_probe": None,
            "errors": [], "observations": ["SYNTHETIC: no live gateway probe"], "read_only": True}


def _default_output() -> Path:
    import datetime
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return Path("reports") / f"report-{stamp}"


def execute(args) -> tuple[dict, int]:
    command = args.command or "doctor"
    if command == "doctor":
        snapshot = collect_snapshot(probe_gateway=not getattr(args, "no_probe", False))
        if getattr(args, "trace", False):
            snapshot["trace"] = trace_route()
        analysis = analyze_snapshot(snapshot, wan_ip=getattr(args, "wan_ip", None))
        data = {"snapshot": snapshot, "analysis": analysis}
        if getattr(args, "output", None):
            data["artifacts"] = export_report(snapshot, args.output, analysis=analysis)
        return data, 1 if snapshot.get("errors") else 0
    if command == "probe":
        data = probe_service(args.url)
        http = data.get("http") or {}
        responded = data["tcp"]["reachable"] and isinstance(http.get("status"), int) and http["status"] < 400
        return data, 0 if responded and (not http.get("error") or http.get("redirect_blocked")) else 1
    if command == "plan":
        # Validate the service target before any network collection or probe.
        build_plan({"interfaces": []}, args.service, args.wan_ip)
        snapshot = load_snapshot(args.snapshot) if args.snapshot else collect_snapshot(probe_gateway=False)
        service = probe_service(args.service)
        data = build_plan(snapshot, service, args.wan_ip)
        data["snapshot_utc"] = snapshot.get("collected_utc")
        if args.output:
            data["artifacts"] = export_report(snapshot, args.output, analysis=data["analysis"], service=service, plan=data)
        return data, 0
    if command == "report":
        snapshot = load_snapshot(args.snapshot)
        analysis = analyze_snapshot(snapshot, wan_ip=args.wan_ip)
        return {"snapshot": snapshot, "analysis": analysis,
                "artifacts": export_report(snapshot, args.output or _default_output(), analysis=analysis)}, 0
    if command == "diff":
        return diff_snapshots(load_snapshot(args.before), load_snapshot(args.after)), 0
    if command == "verify":
        result = verify_receipt(args.receipt)
        return result, 0 if result["status"] == "PASS" else 1
    if command == "selftest":
        result = run_selftest()
        return result, 0 if result["status"] == "PASS" else 1
    if command == "demo":
        snapshot = synthetic_snapshot()
        return {"snapshot": snapshot, "analysis": analyze_snapshot(snapshot)}, 0
    raise ValueError(f"Unknown command: {command}")


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = parser().parse_args(argv)
    try:
        result, code = execute(args)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        result = {"schema": "homerouterlab.error/1", "status": "ERROR", "error": str(exc)[:400],
                  "type": type(exc).__name__}
        if args.json:
            print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        else:
            print(f"HomeRouterLab: {result['type']}: {result['error']}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2))
    else:
        render_result(args.command or "doctor", result, color=args.color, lang=args.lang)
    return code
