import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from home_router_lab.reports import diff_snapshots, export_report, verify_receipt


def sample():
    return {"schema": "homerouterlab.snapshot/1", "collected_utc": "2026-10-22T00:00:00Z",
            "host": {"name": "test-host", "platform": "Windows"}, "primary_ipv4": "192.168.0.139",
            "default_route": {"next_hop": "192.168.0.1", "interface_index": 14, "total_metric": 25},
            "interfaces": [{"index": 14, "name": "Wi-Fi", "kind": "physical", "ipv4": [{"address": "192.168.0.139", "prefix_length": 24}],
                            "ipv6": [], "gateways": ["192.168.0.1"], "dns_servers": ["192.168.0.1"]}],
            "errors": [], "observations": []}


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_export_and_verify_all_artifacts_roundtrip(self):
        paths = export_report(sample(), self.base / "report")
        self.assertEqual(set(paths), {"directory", "snapshot", "evidence", "html", "receipt"})
        result = verify_receipt(paths["receipt"])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(len(result["checks"]), 3)
        evidence = json.loads(Path(paths["evidence"]).read_text())
        self.assertEqual(evidence["analysis"]["public_reachability"], "NOT_TESTED")

    def test_same_length_tamper_fails_hash(self):
        paths = export_report(sample(), self.base / "report")
        path = Path(paths["snapshot"])
        content = path.read_bytes()
        path.write_bytes(content.replace(b"test-host", b"evil-host"))
        result = verify_receipt(paths["receipt"])
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any("SHA-256" in message for message in result["errors"]))

    def test_traversal_and_duplicate_entries_rejected(self):
        paths = export_report(sample(), self.base / "report")
        path = Path(paths["receipt"])
        original = json.loads(path.read_text())
        for bad in ("../outside", "..\\outside", "/absolute", "C:stream", "NUL", "x."):
            receipt = copy.deepcopy(original)
            receipt["files"][0]["path"] = bad
            path.write_text(json.dumps(receipt))
            self.assertEqual(verify_receipt(path)["status"], "FAIL", bad)
        original["files"].append(original["files"][0])
        path.write_text(json.dumps(original))
        self.assertEqual(verify_receipt(path)["status"], "FAIL")
        original["files"][-1] = dict(original["files"][0], path="SNAPSHOT.JSON")
        path.write_text(json.dumps(original))
        self.assertEqual(verify_receipt(path)["status"], "FAIL")

    def test_symlink_target_rejected(self):
        paths = export_report(sample(), self.base / "report")
        target = Path(paths["snapshot"])
        other = self.base / "copied.json"
        other.write_bytes(target.read_bytes())
        target.unlink()
        try:
            target.symlink_to(other)
        except (OSError, NotImplementedError):
            self.skipTest("This environment cannot create symlinks")
        self.assertEqual(verify_receipt(paths["receipt"])["status"], "FAIL")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Named pipes are unavailable")
    def test_fifo_target_rejected_without_opening(self):
        paths = export_report(sample(), self.base / "report")
        target = Path(paths["snapshot"])
        target.unlink()
        os.mkfifo(target)
        result = verify_receipt(paths["receipt"])
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any("normal file" in message for message in result["errors"]))

    def test_html_escapes_untrusted_values(self):
        value = sample()
        attack = '<script>alert("x")</script><img src="https://remote.test/x">'
        value["host"]["name"] = attack
        value["interfaces"][0]["name"] = attack
        paths = export_report(value, self.base / "report", service={"url": attack})
        page = Path(paths["html"]).read_text(encoding="utf-8")
        self.assertNotIn("<script", page)
        self.assertNotIn("<img", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("Content-Security-Policy", page)
        self.assertIn('dir="auto"', page)

    def test_synthetic_report_is_prominently_labeled(self):
        snapshot = sample()
        live = export_report(snapshot, self.base / "live")
        self.assertNotIn('class="synthetic-banner"', Path(live["html"]).read_text(encoding="utf-8"))
        snapshot["synthetic"] = True
        paths = export_report(snapshot, self.base / "synthetic")
        page = Path(paths["html"]).read_text(encoding="utf-8")
        self.assertIn('class="synthetic-banner"', page)
        self.assertIn("SYNTHETIC — DEMONSTRATION DATA", page)
        self.assertIn("not an observed network", page)
        self.assertLess(page.index('class="synthetic-banner"'), page.index('class="metrics"'))

    def test_trace_and_gateway_have_compact_tables_and_collapsed_details(self):
        snapshot = sample()
        snapshot["trace"] = {"status": "PARTIAL", "limitation": "Hops < NAT boundaries",
                             "hops": [{"ttl": 1, "address": "192.168.0.1", "scope": "private",
                                       "latency_ms": [1.0, 2.0], "latency_upper_bounds": [True, False]},
                                      {"ttl": 2, "address": None, "scope": "other", "timeout": True,
                                       "latency_ms": [], "latency_upper_bounds": []}]}
        snapshot["gateway_probe"] = {"address": "192.168.0.1", "ports": [
            {"port": 80, "reachable": True, "latency_ms": 3},
            {"port": 443, "reachable": False, "latency_ms": 4}],
            "http": {"status": 302, "redirect_blocked": True, "latency_ms": 5}}
        paths = export_report(snapshot, self.base / "report")
        page = Path(paths["html"]).read_text(encoding="utf-8")
        self.assertIn('<th>TTL</th><th>Address</th><th>Scope</th><th>ms</th>', page)
        self.assertIn("&lt;1.0, 2.0", page)
        self.assertIn("TIMEOUT", page)
        self.assertIn("PARTIAL", page)
        self.assertIn("Hops &lt; NAT boundaries", page)
        self.assertIn("TCP 80", page)
        self.assertIn("TCP 443", page)
        self.assertIn('>302</td>', page)
        self.assertIn("HTTP redirect observed; not followed.", page)
        self.assertIn('<details><summary>Full trace evidence</summary>', page)
        self.assertIn('<details><summary>Full gateway evidence</summary>', page)
        self.assertNotIn("<details open", page)

    def test_existing_artifact_never_overwritten(self):
        directory = self.base / "report"
        directory.mkdir()
        existing = directory / "evidence.json"
        existing.write_text("keep me")
        with self.assertRaises(FileExistsError):
            export_report(sample(), directory)
        self.assertEqual(existing.read_text(), "keep me")
        self.assertEqual(len(list(directory.iterdir())), 1)

    def test_nan_rejected_before_artifact_creation(self):
        value = sample()
        value["invalid"] = float("nan")
        with self.assertRaises(ValueError):
            export_report(value, self.base / "report")
        self.assertFalse((self.base / "report").exists())

    def test_diff_ignores_timing_and_detects_address_change(self):
        a = sample()
        a["gateway_probe"] = {"address": "192.168.0.1", "ports": [{"port": 80, "reachable": True, "latency_ms": 1}],
                              "http": {"status": 302, "latency_ms": 2}}
        b = copy.deepcopy(a)
        b["collected_utc"] = "later"
        b["gateway_probe"]["ports"][0]["latency_ms"] = 500
        b["gateway_probe"]["http"]["latency_ms"] = 1000
        self.assertFalse(diff_snapshots(a, b)["changed"])
        b["interfaces"][0]["ipv4"][0]["address"] = "192.168.0.140"
        result = diff_snapshots(a, b)
        self.assertTrue(result["changed"])
        self.assertEqual(result["changes"][0]["field"], "interfaces")


if __name__ == "__main__":
    unittest.main()
