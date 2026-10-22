"""Command-line entry point."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .models import utc_now
from .probe.dispatcher import build_layers, run
from .report import build_payload, write

DEFAULT_HOSTS = ("192.168.0.1", "192.168.100.1")
DEFAULT_OUT = Path("reports")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="homerouterlab", description="Read-only WAN probe for home routers."
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--hosts", default=",".join(DEFAULT_HOSTS), help="comma-separated router IPs")
    p.add_argument("--timeout", type=float, default=3.0, help="per-socket timeout in seconds")
    p.add_argument("--output", type=Path, default=DEFAULT_OUT, help="directory for JSON reports")
    p.add_argument("--include-external", action="store_true", help="append public egress IP lookup")
    p.add_argument("--json", action="store_true", help="print the full payload as JSON")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    started = utc_now()
    layers = build_layers(hosts, args.timeout, include_external=args.include_external)
    outcome = run(layers)
    payload = build_payload(outcome, started)
    stamp = started.replace(":", "").replace("-", "").replace(".", "")[:15]
    path = write(payload, args.output, stamp)
    summary = {
        "path": str(path),
        "layer": outcome["final"]["layer"],
        "status": outcome["final"]["status"],
        "wan_ip": outcome["final"]["wan_ip"],
        "payload_sha256": payload["payload_sha256"],
    }
    print(json.dumps(payload if args.json else summary, ensure_ascii=False))
    return 0 if outcome["final"]["status"] == "OBSERVED" else 1