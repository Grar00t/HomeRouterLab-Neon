import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from home_router_lab.cli import main, synthetic_snapshot


class CliTests(unittest.TestCase):
    def run_cli(self, argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(argv)
        return code, output.getvalue()

    def test_json_never_has_ansi_and_demo_is_explicit(self):
        code, output = self.run_cli(["--json", "--color", "always", "demo"])
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", output)
        self.assertTrue(json.loads(output)["snapshot"]["synthetic"])

    def test_invalid_target_rejected_before_collection(self):
        with patch("home_router_lab.cli.collect_snapshot") as collect:
            code, output = self.run_cli(["--json", "plan", "--service", "http://example.com"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output)["status"], "ERROR")
        collect.assert_not_called()

    def test_report_uses_saved_evidence_without_network(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "input.json"
            path.write_text(json.dumps(synthetic_snapshot()), encoding="utf-8")
            with patch("home_router_lab.cli.collect_snapshot") as collect:
                code, output = self.run_cli(["--json", "report", str(path), "--output", str(Path(root)/"report")])
            self.assertEqual(code, 0)
            collect.assert_not_called()
            receipt = json.loads(output)["artifacts"]["receipt"]
            code, output = self.run_cli(["--json", "verify", receipt])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)["status"], "PASS")

    def test_bad_snapshot_is_a_structured_error(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "input.json"
            path.write_text('{"schema":"unrelated"}', encoding="utf-8")
            code, output = self.run_cli(["--json", "report", str(path)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output)["type"], "ValueError")


if __name__ == "__main__":
    unittest.main()
