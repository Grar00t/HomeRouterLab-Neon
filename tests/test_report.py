import json

from homerouterlab.report import build_payload


def test_payload_hash_is_stable() -> None:
    a = build_payload({"final": {"layer": "x", "status": "OBSERVED", "wan_ip": "8.8.8.8"}}, "2026-01-01T00:00:00+00:00")
    b = build_payload({"final": {"status": "OBSERVED", "wan_ip": "8.8.8.8", "layer": "x"}}, "2026-01-01T00:00:00+00:00")
    assert a["payload_sha256"] == b["payload_sha256"]
    assert len(a["payload_sha256"]) == 64


def test_payload_serialises() -> None:
    p = build_payload({"final": {"layer": "x", "status": "UNKNOWN"}}, "2026-01-01T00:00:00+00:00")
    json.dumps(p)