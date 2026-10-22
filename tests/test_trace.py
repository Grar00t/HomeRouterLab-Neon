import subprocess
import unittest
from unittest.mock import patch

from home_router_lab import trace


HOME_TRACE = """
Tracing route to 1.1.1.1 over a maximum of 4 hops:

  1    <1 ms     2 ms     1 ms  192.168.0.1
  2     3 ms     4 ms     3 ms  192.168.100.1
  3    10 ms     9 ms    11 ms  100.69.3.254
  4    12 ms    11 ms    10 ms  10.0.30.162

Trace complete.
"""


def completed(stdout=HOME_TRACE.encode(), returncode=0, stderr=b""):
    return subprocess.CompletedProcess(trace.TRACE_ARGV, returncode, stdout, stderr)


class ParseTests(unittest.TestCase):
    def test_observed_home_path_has_scopes_without_nat_claim(self):
        hops = trace.parse_trace(HOME_TRACE)
        self.assertEqual([h["address"] for h in hops], [
            "192.168.0.1", "192.168.100.1", "100.69.3.254", "10.0.30.162"])
        self.assertEqual([h["scope"] for h in hops], ["rfc1918", "rfc1918", "shared", "rfc1918"])
        self.assertEqual(hops[0]["latency_ms"], [1.0, 2.0, 1.0])
        self.assertEqual(hops[0]["latency_upper_bounds"], [True, False, False])
        self.assertNotIn("cgnat", str(hops).lower())

    def test_timeouts_are_retained_and_partial_latency_is_supported(self):
        hops = trace.parse_trace(" 1 * * * Request timed out.\n 2 * 3 ms 4 ms 192.168.0.1")
        self.assertIsNone(hops[0]["address"])
        self.assertTrue(hops[0]["timeout"])
        self.assertEqual(hops[0]["latency_ms"], [])
        self.assertEqual(hops[1]["latency_ms"], [3.0, 4.0])

    def test_header_invalid_ip_and_numbered_prose_are_ignored(self):
        text = "Tracing route to 1.1.1.1\n1 1 ms 999.168.0.1\n2 Destination 8.8.8.8\n5 1 ms 8.8.8.8"
        self.assertEqual(trace.parse_trace(text), [])

    def test_special_ranges_are_not_global(self):
        for ip in ("127.0.0.1", "169.254.1.2", "203.0.113.1", "198.18.0.1",
                   "224.0.0.1", "255.255.255.255", "0.0.0.0", "192.0.0.8"):
            with self.subTest(ip=ip):
                self.assertEqual(trace.parse_trace(f"1 1 ms 1 ms 1 ms {ip}")[0]["scope"], "other")

    def test_shared_boundaries_and_global_destination(self):
        for ip, expected in (("100.64.0.0", "shared"), ("100.127.255.255", "shared"),
                             ("100.63.255.255", "global"), ("100.128.0.0", "global"),
                             ("1.1.1.1", "global")):
            with self.subTest(ip=ip):
                self.assertEqual(trace.parse_trace(f"1 1 ms {ip}")[0]["scope"], expected)

    def test_only_one_row_per_ttl_and_one_address_per_row(self):
        hops = trace.parse_trace("1 1 ms 192.168.0.1\n1 2 ms 192.168.0.2\n2 1 ms 8.8.8.8 1.1.1.1")
        self.assertEqual(len(hops), 1)
        self.assertEqual(hops[0]["address"], "192.168.0.1")


class TraceTests(unittest.TestCase):
    @patch.object(trace.sys, "platform", "win32")
    def test_fixed_argv_bounded_and_max_hops_is_partial(self):
        with patch.object(trace.subprocess, "run", return_value=completed()) as run:
            result = trace.trace_route()
        self.assertEqual(run.call_args.args[0], ["tracert", "-4", "-d", "-h", "4", "-w", "500", "1.1.1.1"])
        self.assertEqual(run.call_args.kwargs["timeout"], 12)
        self.assertIs(run.call_args.kwargs["shell"], False)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["max_hops"], 4)
        self.assertEqual(result["limitation"], trace.LIMITATION)
        self.assertIsNone(result["error"])

    @patch.object(trace.sys, "platform", "win32")
    def test_destination_reply_is_complete(self):
        with patch.object(trace.subprocess, "run", return_value=completed(b"1 12 ms 1.1.1.1")):
            self.assertEqual(trace.trace_route()["status"], "COMPLETE")

    @patch.object(trace.sys, "platform", "linux")
    def test_linux_unavailable_without_process_or_install(self):
        with patch.object(trace.subprocess, "run") as run:
            result = trace.trace_route()
        run.assert_not_called()
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(result["hops"], [])
        self.assertIn("no command", result["error"])

    @patch.object(trace.sys, "platform", "win32")
    def test_missing_executable_unavailable(self):
        with patch.object(trace.subprocess, "run", side_effect=FileNotFoundError):
            self.assertEqual(trace.trace_route()["status"], "UNAVAILABLE")

    @patch.object(trace.sys, "platform", "win32")
    def test_timeout_preserves_partial_output(self):
        error = subprocess.TimeoutExpired(trace.TRACE_ARGV, 12, output=b"1 1 ms 192.168.0.1")
        with patch.object(trace.subprocess, "run", side_effect=error):
            result = trace.trace_route()
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(len(result["hops"]), 1)
        self.assertIn("timeout", result["error"])

    @patch.object(trace.sys, "platform", "win32")
    def test_failed_command_and_no_hops_are_errors(self):
        for process in (completed(b"error", returncode=1), completed(b"No observations")):
            with patch.object(trace.subprocess, "run", return_value=process):
                result = trace.trace_route()
            self.assertEqual(result["status"], "ERROR")
            self.assertTrue(result["error"])

    @patch.object(trace.sys, "platform", "win32")
    def test_oem_fallback_and_raw_output_bound(self):
        output = b"\x82 localized header\n1 1 ms 192.168.0.1\n" + b"x" * 10000
        with patch.object(trace.subprocess, "run", return_value=completed(output)):
            result = trace.trace_route()
        self.assertEqual(result["hops"][0]["address"], "192.168.0.1")
        self.assertEqual(len(result["raw_output"]), trace.MAX_RAW_CHARS)
        self.assertTrue(result["raw_output_truncated"])


if __name__ == "__main__":
    unittest.main()
