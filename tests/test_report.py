import hashlib
import json

from homerouterlab.report import build_payload


def test_payload_hash_is_stable(monkeypatch) -> None:
    # Compare key ordering with every payload value held constant. The real
    # clock could cross a second between calls and legitimately change the hash.
    monkeypatch.setattr("homerouterlab.report.utc_now", lambda: "2026-01-01T00:00:01+00:00")
    a = build_payload({"final": {"layer": "x", "status": "OBSERVED", "wan_ip": "8.8.8.8"}}, "2026-01-01T00:00:00+00:00")
    b = build_payload({"final": {"status": "OBSERVED", "wan_ip": "8.8.8.8", "layer": "x"}}, "2026-01-01T00:00:00+00:00")
    assert a["payload_sha256"] == b["payload_sha256"]
    assert len(a["payload_sha256"]) == 64


def test_payload_hash_includes_finished_utc(monkeypatch) -> None:
    times = iter(("2026-01-01T00:00:01+00:00", "2026-01-01T00:00:02+00:00"))
    monkeypatch.setattr("homerouterlab.report.utc_now", lambda: next(times))
    result = {"final": {"layer": "x", "status": "UNKNOWN"}}
    a = build_payload(result, "2026-01-01T00:00:00+00:00")
    b = build_payload(result, "2026-01-01T00:00:00+00:00")
    assert a["finished_utc"] == "2026-01-01T00:00:01+00:00"
    assert b["finished_utc"] == "2026-01-01T00:00:02+00:00"
    assert a["payload_sha256"] != b["payload_sha256"]


def test_payload_hash_matches_canonical_body(monkeypatch) -> None:
    monkeypatch.setattr("homerouterlab.report.utc_now", lambda: "2026-01-01T00:00:01+00:00")
    payload = build_payload(
        {"final": {"status": "UNKNOWN", "layer": "x"}},
        "2026-01-01T00:00:00+00:00",
        notes="قراءة فقط",
    )
    # An independently specified canonical payload checks UTF-8, sorted keys,
    # compact separators, and exclusion of the digest itself from the hash.
    canonical = (
        '{"finished_utc":"2026-01-01T00:00:01+00:00","notes":"قراءة فقط",'
        '"result":{"final":{"layer":"x","status":"UNKNOWN"}},'
        '"schema":"homerouterlab.wan-probe/2",'
        '"started_utc":"2026-01-01T00:00:00+00:00"}'
    ).encode("utf-8")
    assert payload["payload_sha256"] == hashlib.sha256(canonical).hexdigest()


def test_payload_serialises() -> None:
    p = build_payload({"final": {"layer": "x", "status": "UNKNOWN"}}, "2026-01-01T00:00:00+00:00")
    json.dumps(p)
