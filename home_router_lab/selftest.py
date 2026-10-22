"""A real, temporary, loopback-only end-to-end exercise."""
from __future__ import annotations

import http.server
import json
import platform
import tempfile
import threading
import time
from pathlib import Path

from .core import SCHEMA, analyze_snapshot, build_plan, probe_service, utc_now
from .reports import export_report, verify_receipt


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<!doctype html><title>HomeRouterLab selftest</title><p>loopback fixture</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def run_selftest() -> dict:
    """Start HTTP, probe it, export/verify/tamper-check evidence, stop and probe.

    The network snapshot in this exercise is explicitly synthetic; the HTTP
    interaction and integrity checks are actually executed on this machine.
    """
    started = time.monotonic()
    checks = []
    server = None
    worker = None
    service = None
    closed = None
    url = None

    def check(name, passed, detail):
        checks.append({"name": name, "status": "PASS" if passed else "FAIL", "detail": detail})

    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.daemon_threads = True
        url = f"http://127.0.0.1:{server.server_port}/"
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        worker.start()
        check("temporary_listener", worker.is_alive(), f"Temporary loopback listener: {url}")
        service = probe_service(url)
        check("http_roundtrip", service["tcp"]["reachable"] and service.get("http", {}).get("status") == 200
              and service["http"].get("title") == "HomeRouterLab selftest",
              f"TCP and HTTP response from the running temporary service: {service.get('http', {}).get('status')}")
        fixture = {"schema": SCHEMA, "collected_utc": utc_now(),
                   "synthetic": True, "synthetic_reason": "Selftest fixture; not a network observation",
                   "host": {"name": "SELFTEST-FIXTURE", "platform": platform.system()},
                   "interfaces": [], "default_route": None, "primary_ipv4": None,
                   "gateway_probe": None, "observations": [], "errors": [], "read_only": True}
        plan = build_plan(fixture, service)
        check("publication_evidence", plan["execute"] is False and plan["public_reachability"] == "NOT_TESTED"
              and plan["analysis"]["ipv4_publication"]["status"] == "UNKNOWN",
              "A real local response leaves external reachability untested and WAN unknown")
        with tempfile.TemporaryDirectory(prefix="homerouterlab-selftest-") as root:
            artifacts = export_report(fixture, Path(root) / "report", service=service, plan=plan)
            result = verify_receipt(artifacts["receipt"])
            check("report_receipt", result["status"] == "PASS", "JSON + HTML artifacts match their receipt")
            target = Path(artifacts["snapshot"])
            original = target.read_bytes()
            target.write_bytes(original + b"\n")
            result = verify_receipt(artifacts["receipt"])
            check("tamper_detection", result["status"] == "FAIL", "One added byte invalidates the original digest")
            target.write_bytes(original)
            check("restored_receipt", verify_receipt(artifacts["receipt"])["status"] == "PASS",
                  "Restored bytes match the original receipt again")
    except Exception as exc:
        check("selftest_execution", False, f"{type(exc).__name__}: {str(exc)[:240]}")
    finally:
        if server is not None:
            if worker is not None and worker.is_alive():
                server.shutdown()
            server.server_close()
            if worker is not None:
                worker.join(timeout=2)
        if url is not None:
            closed = probe_service(url)
            check("listener_closed", not closed["tcp"]["reachable"],
                  "A new TCP connection after shutdown is refused or otherwise unavailable")
    return {"schema": "homerouterlab.selftest/1", "created_utc": utc_now(),
            "status": "PASS" if checks and all(c["status"] == "PASS" for c in checks) else "FAIL",
            "duration_seconds": round(time.monotonic() - started, 3), "checks": checks,
            "service_probe": service, "after_shutdown": closed,
            "snapshot_is_synthetic": True, "http_interaction_is_real": True,
            "public_reachability": "NOT_TESTED", "configuration_changed": False}
