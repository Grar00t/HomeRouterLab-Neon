import copy
import json
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import PropertyMock, patch

from home_router_lab import core


def snapshot():
    return {"schema": core.SCHEMA, "primary_ipv4": "192.168.0.139", "errors": [],
            "default_route": {"next_hop": "192.168.0.1"},
            "interfaces": [
                {"name": "Wi-Fi", "kind": "physical", "ipv4": [{"address": "192.168.0.139", "prefix_length": 24}],
                 "ipv6": [{"address": "fe80::123", "prefix_length": 64}]},
                {"name": "Tailscale", "kind": "overlay", "ipv4": [{"address": "100.118.102.126", "prefix_length": 32}],
                 "ipv6": [{"address": "fd7a:115c:a1e0::123", "prefix_length": 128}]}]}


class AnalysisTests(unittest.TestCase):
    def test_private_pc_and_overlay_do_not_prove_cgnat(self):
        result = core.analyze_snapshot(snapshot())
        self.assertEqual(result["ipv4_publication"]["status"], "UNKNOWN")
        self.assertEqual(result["public_reachability"], "NOT_TESTED")
        self.assertIn("OVERLAY_INTERFACES", [f["code"] for f in result["findings"]])

    def test_wan_address_scopes_are_evidence_not_inbound_success(self):
        cases = {"192.168.8.2": "UPSTREAM_NAT_EVIDENCE", "100.64.2.3": "SHARED_ADDRESS_SPACE",
                 "8.8.8.8": "GLOBAL_IPV4_CANDIDATE", "203.0.113.7": "NON_GLOBAL_WAN_ADDRESS"}
        for address, status in cases.items():
            with self.subTest(address=address):
                value = core.analyze_snapshot(snapshot(), address)["ipv4_publication"]
                self.assertEqual(value["status"], status)
                self.assertEqual(value["public_reachability"], "NOT_TESTED")
                self.assertIn("supplied", value["wan_source"])

    def test_linklocal_and_overlay_ipv6_are_not_global_candidates(self):
        s = snapshot()
        s["interfaces"][1]["ipv6"].append({"address": "2606:4700::1111"})
        self.assertEqual(core.analyze_snapshot(s)["ipv6_publication"]["global_addresses"], [])

    def test_global_ipv6_does_not_establish_firewall_or_reachability(self):
        s = snapshot()
        s["interfaces"][0]["ipv6"].append({"address": "2606:4700::1111"})
        result = core.analyze_snapshot(s)["ipv6_publication"]
        self.assertEqual(result["status"], "GLOBAL_IPV6_CANDIDATE")
        self.assertEqual(result["inbound_firewall"], "UNKNOWN")
        self.assertEqual(result["public_reachability"], "NOT_TESTED")

    def test_reserved_ipv6_is_not_a_global_publication_candidate(self):
        s = snapshot()
        s["interfaces"][0]["ipv6"].append({"address": "4000::1"})
        result = core.analyze_snapshot(s)["ipv6_publication"]
        self.assertEqual(result["status"], "NO_GLOBAL_IPV6_OBSERVED")
        self.assertEqual(result["global_addresses"], [])
        self.assertEqual(result["public_reachability"], "NOT_TESTED")

    def test_protocol_ipv4_classification_survives_older_python_global_flags(self):
        # Simulate Python releases that called 192.0.0.8 globally reachable.
        with patch.object(core.ipaddress.IPv4Address, "is_global", new_callable=PropertyMock,
                          return_value=True):
            for address in ("192.0.0.8", "192.0.0.11"):
                with self.subTest(address=address):
                    result = core.analyze_snapshot(snapshot(), address)["ipv4_publication"]
                    self.assertEqual(result["status"], "NON_GLOBAL_WAN_ADDRESS")
            for address in ("192.0.0.9", "192.0.0.10"):
                with self.subTest(address=address):
                    result = core.analyze_snapshot(snapshot(), address)["ipv4_publication"]
                    self.assertEqual(result["status"], "GLOBAL_IPV4_CANDIDATE")

    def test_plan_does_not_probe_or_execute(self):
        with patch.object(core, "probe_service", side_effect=AssertionError("must not probe")):
            plan = core.build_plan(snapshot(), "http://localhost:8765/")
        self.assertFalse(plan["execute"])
        self.assertTrue(any("loopback" in s["action"] for s in plan["steps"]))
        self.assertEqual(plan["service"]["tcp"], None)

    def test_invalid_wan_is_rejected(self):
        with self.assertRaises(ValueError):
            core.analyze_snapshot(snapshot(), "not-an-ip")


class CollectorTests(unittest.TestCase):
    def test_default_route_uses_route_plus_interface_metric(self):
        interfaces = [{"index": 1, "ipv4": [{"address": "192.168.1.2"}]},
                      {"index": 2, "ipv4": [{"address": "192.168.0.139"}]}]
        routes = [{"interface_index": 1, "next_hop": "192.168.1.1", "route_metric": 0,
                   "interface_metric": 100, "total_metric": 100},
                  {"interface_index": 2, "next_hop": "192.168.0.1", "route_metric": 15,
                   "interface_metric": 25, "total_metric": 40}]
        with patch.object(core, "_collect_windows", return_value=(interfaces, routes, [])), patch.object(core.sys, "platform", "win32"):
            result = core.collect_snapshot(False)
        self.assertEqual(result["default_route"]["next_hop"], "192.168.0.1")
        self.assertEqual(result["primary_ipv4"], "192.168.0.139")

    def test_windows_fixed_argv_no_shell_and_utf8(self):
        payload = {"Adapters": [{"InterfaceIndex": 14, "Description": "Wi-Fi جهاز", "IPAddress": ["192.168.0.139"],
                                "IPSubnet": ["255.255.255.0"], "DefaultIPGateway": ["192.168.0.1"]}],
                   "Routes": [{"InterfaceIndex": 14, "InterfaceAlias": "Wi-Fi جهاز", "NextHop": "192.168.0.1", "RouteMetric": 0, "InterfaceMetric": 25}]}
        process = type("Result", (), {"returncode": 0, "stdout": json.dumps(payload, ensure_ascii=False).encode("utf-8")})()
        with patch.object(core.subprocess, "run", return_value=process) as run:
            interfaces, routes, errors = core._collect_windows()
        self.assertIs(run.call_args.kwargs["shell"], False)
        self.assertEqual(run.call_args.kwargs["timeout"], 15)
        self.assertEqual(run.call_args.args[0][:4], ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command"])
        self.assertEqual(interfaces[0]["ipv4"][0]["prefix_length"], 24)
        self.assertEqual(routes[0]["total_metric"], 25)
        self.assertEqual(errors, [])

    def test_failure_is_explicit_no_fabricated_adapter(self):
        with patch.object(core, "_collect_windows", side_effect=RuntimeError("failed")), patch.object(core.sys, "platform", "win32"):
            result = core.collect_snapshot(False)
        self.assertEqual(result["interfaces"], [])
        self.assertTrue(result["errors"])
        self.assertIsNone(result["default_route"])


class ProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.external_requests = 0

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:1/never")
                    self.end_headers()
                    return
                if self.path == "/slow":
                    self.send_response(200)
                    self.send_header("Content-Length", "100")
                    self.end_headers()
                    time.sleep(0.8)
                    return
                body = b"<html><title>Local test</title>TP-Link fixture</html>"
                if self.path == "/large":
                    body = b"x" * (core.MAX_BODY + 1000)
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_real_local_service_tcp_and_http(self):
        result = core.probe_service(self.url)
        self.assertTrue(result["tcp"]["reachable"])
        self.assertEqual(result["http"]["status"], 200)
        self.assertEqual(result["http"]["title"], "Local test")
        self.assertEqual(result["public_reachability"], "NOT_TESTED")
        self.assertEqual(result["bind_scope"], "loopback")

    def test_redirect_is_observed_never_followed(self):
        result = core.probe_service(self.url + "/redirect")
        self.assertEqual(result["http"]["status"], 302)
        self.assertTrue(result["http"]["redirect_blocked"])
        self.assertEqual(result["http"]["bytes_read"], 0)

    def test_response_body_limit(self):
        result = core.probe_service(self.url + "/large")
        self.assertEqual(result["http"]["bytes_read"], core.MAX_BODY)
        self.assertTrue(result["http"]["truncated"])

    def test_http_deadline_is_bounded(self):
        started = time.monotonic()
        result = core._http_probe(self.url + "/slow", timeout=0.15)
        self.assertLess(time.monotonic() - started, 0.7)
        self.assertEqual(result["error"], "TimeoutError")

    def test_unsafe_url_rejected_before_network(self):
        targets = ["http://8.8.8.8/", "http://example.com/", "http://user:pass@127.0.0.1/", "file:///etc/passwd",
                   "http://127.0.0.1:0/", "http://127.0.0.1:99999/", "http://127.0.0.1/?token=x", "http://127.0.0.1/#x",
                   "http://127.0.0.1/\r\n", "http://100.64.0.1/", "http://169.254.169.254/"]
        with patch.object(core.socket, "create_connection", side_effect=AssertionError("network should not run")):
            for url in targets:
                with self.subTest(url=url), self.assertRaises(ValueError):
                    core.probe_service(url)


if __name__ == "__main__":
    unittest.main()
