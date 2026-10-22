"""Run reproducible CLI acceptance checks on the computer hosting this project.

Creates a fresh evidence directory. The only temporary service binds 127.0.0.1.
No router or firewall writes, dependency installation, or cloud uploads.
"""
from __future__ import annotations

import argparse
import datetime
import http.server
import json
import os
import platform
import re
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from home_router_lab.selftest import _Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    commands = []
    checks = []

    def run(name, argv, *, expected=0, timeout=60, parse=True):
        proc = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True,
                              encoding="utf-8", errors="replace", timeout=timeout, shell=False)
        (out / (name + (".json" if parse else ".stdout.txt"))).write_text(proc.stdout, encoding="utf-8")
        (out / (name + ".stderr.txt")).write_text(proc.stderr, encoding="utf-8")
        commands.append({"name": name, "argv": argv, "exit_code": proc.returncode,
                         "expected_exit_code": expected})
        data = None
        if parse:
            try:
                data = json.loads(proc.stdout)
            except json.JSONDecodeError:
                pass
        passed = proc.returncode == expected and (not parse or isinstance(data, dict))
        checks.append({"name": name, "status": "PASS" if passed else "FAIL",
                       "detail": f"exit={proc.returncode}; expected={expected}; structured_output={isinstance(data, dict)}"})
        return data, proc

    cli = [sys.executable, "-m", "home_router_lab", "--json"]
    _, tests = run("unit-tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], parse=False)
    doctor, _ = run("doctor", cli + ["doctor", "--trace", "--output", str(out / "network")])
    selftest, _ = run("selftest", cli + ["selftest"])
    if selftest:
        checks.append({"name": "selftest-result", "status": selftest.get("status", "FAIL"),
                       "detail": f"{len(selftest.get('checks', []))} actual selftest checks"})
    snapshot_path = str(out / "network" / "snapshot.json")
    run("verify-network", cli + ["verify", str(out / "network" / "receipt.json")])
    run("offline-report", cli + ["report", snapshot_path, "--output", str(out / "offline-report")])
    unchanged, _ = run("diff-same", cli + ["diff", snapshot_path, snapshot_path])
    checks.append({"name": "unchanged-diff", "status": "PASS" if unchanged and unchanged.get("changed") is False else "FAIL",
                   "detail": "Identical network evidence produces no semantic change"})
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler) as server:
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        worker.start()
        url = f"http://127.0.0.1:{server.server_port}/"
        try:
            probe, _ = run("probe-live-loopback", cli + ["probe", url])
            checks.append({"name": "http-200", "status": "PASS" if probe and (probe.get("http") or {}).get("status") == 200 else "FAIL",
                           "detail": "The actual CLI received HTTP 200 from the temporary test service"})
            plan, _ = run("plan", cli + ["plan", "--snapshot", snapshot_path, "--service", url,
                                        "--output", str(out / "service-plan")])
            checks.append({"name": "non-executing-plan", "status": "PASS" if plan and plan.get("execute") is False
                           and plan.get("public_reachability") == "NOT_TESTED" else "FAIL",
                           "detail": "Actual network snapshot + actual temporary service probe; no publication claim"})
        finally:
            server.shutdown()
            worker.join(timeout=2)
    closed, _ = run("probe-after-stop", cli + ["probe", url], expected=1)
    checks.append({"name": "closed-loopback-port", "status": "PASS" if closed and closed.get("tcp", {}).get("reachable") is False else "FAIL",
                   "detail": "The listener is closed after the test; no permanent agent remains"})
    run("verify-service-plan", cli + ["verify", str(out / "service-plan" / "receipt.json")])
    run("rejected-public-target", cli + ["probe", "http://example.com/"], expected=2)
    match = re.search(r"Ran (\d+) tests in ([\d.]+)s", tests.stderr)
    skipped = re.search(r"skipped=(\d+)", tests.stderr)
    summary = {"schema": "homerouterlab.acceptance/1",
               "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
               "host": platform.node(), "platform": platform.platform(), "python": platform.python_version(),
               "status": "PASS" if all(c["status"] == "PASS" for c in checks) else "FAIL",
               "checks": checks, "commands": commands,
               "unit_tests": {"run": int(match[1]) if match else None,
                              "seconds": float(match[2]) if match else None,
                              "skipped": int(skipped[1]) if skipped else 0,
                              "exit_code": tests.returncode},
               "selftest_status": selftest.get("status") if selftest else None,
               "observed_primary_ipv4": (doctor or {}).get("snapshot", {}).get("primary_ipv4"),
               "report_directory": str(out), "temporary_test_service": url,
               "temporary_test_service_stopped": bool(closed and not closed.get("tcp", {}).get("reachable")),
               "public_reachability": "NOT_TESTED", "router_configuration_changed": False}
    (out / "acceptance.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
