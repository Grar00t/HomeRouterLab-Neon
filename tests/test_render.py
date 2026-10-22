import contextlib
import io
import json
import os
import unittest
from unittest.mock import patch

from home_router_lab import render
from home_router_lab.core import analyze_snapshot, build_plan


def fixture():
    return {
        "schema": "homerouterlab.snapshot/1",
        "collected_utc": "2026-10-22T00:00:00Z",
        "host": {"name": "TEST-PC", "platform": "Windows"},
        "primary_ipv4": "192.168.50.10",
        "interfaces": [
            {"index": 2, "name": "Wi-Fi", "kind": "physical",
             "ipv4": [{"address": "192.168.50.10", "prefix_length": 24}], "ipv6": []},
            {"index": 8, "name": "Tailscale", "kind": "overlay",
             "ipv4": [{"address": "100.100.1.5", "prefix_length": 32}], "ipv6": []},
        ],
        "default_route": {"interface_index": 2, "next_hop": "192.168.50.1"},
        "gateway_probe": {"model": "UNKNOWN", "http": {"vendor_hints": ["TP-Link"]}},
        "trace": {"status": "PARTIAL", "hops": [
            {"ttl": 1, "address": "192.168.50.1", "scope": "rfc1918", "latency_ms": [1]},
            {"ttl": 2, "address": "192.168.100.1", "scope": "rfc1918", "latency_ms": [2]},
            {"ttl": 3, "address": "100.64.1.1", "scope": "shared", "latency_ms": [3]},
            {"ttl": 4, "address": None, "scope": "other", "latency_ms": []},
        ]},
        "errors": [], "read_only": True,
    }


class PlainRenderTests(unittest.TestCase):
    def test_optional_dependency_falls_back_to_readable_plain_json(self):
        data = {"status": "FAIL", "detail": "[bold]literal[/bold]\x1b[31m"}
        stream = io.StringIO()
        with patch.object(render, "RICH_AVAILABLE", False), contextlib.redirect_stdout(stream):
            console = render.render_result("verify", data, color="always", record=True)
        output = stream.getvalue()
        self.assertIsNone(console)
        self.assertTrue(output.startswith("HomeRouterLab Neon"))
        self.assertNotIn("\x1b", output)
        self.assertEqual(json.loads(output.split("\n", 1)[1]), data)


@unittest.skipUnless(render.RICH_AVAILABLE, "Rich is optional")
class RichRenderTests(unittest.TestCase):
    def capture(self, command, data, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            console = render.render_result(command, data, record=True, **kwargs)
        return console, output.getvalue(), console.export_text(clear=False)

    def test_color_policies_and_environment_suppression(self):
        data = {"changed": False, "changes": []}
        for color, environment, expect_ansi in [
            ("always", {"TERM": "xterm-256color"}, True),
            ("never", {"TERM": "xterm-256color"}, False),
            ("auto", {"TERM": "xterm-256color"}, False),
            ("always", {"TERM": "xterm-256color", "NO_COLOR": ""}, False),
            ("always", {"TERM": "dumb"}, False),
        ]:
            with self.subTest(color=color, environment=environment):
                with patch.dict(os.environ, environment, clear=True):
                    _, output, text = self.capture("diff", data, color=color)
                self.assertEqual("\x1b[" in output, expect_ansi)
                self.assertIn("UNCHANGED", text)

    def test_observed_markup_and_terminal_controls_remain_inert(self):
        snapshot = fixture()
        snapshot["host"]["name"] = "[bold red]host[/bold red]\x1b[2J\x07"
        with patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True):
            _, output, text = self.capture("doctor", {"snapshot": snapshot,
                "analysis": analyze_snapshot(snapshot)}, color="never", width=100)
        self.assertIn("[bold red]host[/bold red]", text)
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\x07", output)
        self.assertIn("page hint: TP-Link", text)
        self.assertIn("UNKNOWN", text)

    def test_narrow_screen_has_complete_labeled_evidence(self):
        from rich.cells import cell_len
        snapshot = fixture()
        _, _, text = self.capture("doctor", {"snapshot": snapshot,
            "analysis": analyze_snapshot(snapshot)}, color="never", width=40)
        self.assertTrue(all(cell_len(line) <= 40 for line in text.splitlines()))
        self.assertIn("NOT_TESTED", text)
        self.assertIn("UNKNOWN", text)
        self.assertIn("Tailscale", text)
        self.assertIn("192.168.50.10/24", text)
        self.assertIn("100.64.1.1", text)

    def test_demo_is_clearly_synthetic_and_record_can_export(self):
        snapshot = fixture()
        snapshot["synthetic"] = True
        console, _, text = self.capture("demo", {"snapshot": snapshot,
            "analysis": analyze_snapshot(snapshot)}, color="never", width=80)
        self.assertIn("SYNTHETIC SAMPLE", text)
        self.assertIn("not a live network observation", text)
        self.assertIn("2026-10-22T00:00:00Z", text)
        self.assertIn("<svg", console.export_svg(title="HomeRouterLab Neon", clear=False))

    def test_failed_receipt_never_claims_verified_or_report_truth(self):
        _, _, text = self.capture("verify", {"status": "FAIL",
            "checks": [{"path": "snapshot.json", "matched": False}],
            "errors": ["SHA-256 mismatch"]}, color="never", width=100)
        self.assertIn("FAIL", text)
        self.assertIn("snapshot.json", text)
        self.assertIn("SHA-256 mismatch", text)
        self.assertNotIn("VERIFIED", text)
        self.assertIn("do not independently establish report accuracy", text)

    def test_plan_and_selftest_preserve_non_publication_status(self):
        plan = build_plan(fixture(), "http://127.0.0.1:8080/")
        _, _, plan_text = self.capture("plan", plan, color="never", width=80)
        self.assertIn("PLAN_ONLY", plan_text)
        self.assertIn("NOT_TESTED", plan_text)
        _, _, test_text = self.capture("selftest", {"status": "PASS", "checks": [
            {"name": "HTTP probe", "status": "PASS", "detail": "HTTP 200"},
            {"name": "Service shutdown", "status": "PASS", "detail": "socket closed"},
        ]}, color="never", width=80)
        self.assertIn("HTTP 200", test_text)
        self.assertIn("Service shutdown", test_text)
        self.assertIn("NOT_TESTED", test_text)


if __name__ == "__main__":
    unittest.main()
