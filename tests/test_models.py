from homerouterlab.models import ProbeResult, utc_now


def test_round_trip() -> None:
    r = ProbeResult(layer="http", status="OBSERVED", wan_ip="8.8.8.8", host="192.168.0.1")
    d = r.to_dict()
    assert d["layer"] == "http"
    assert d["wan_ip"] == "8.8.8.8"
    assert d["evidence"] == {}


def test_utc_now_is_parseable() -> None:
    from datetime import datetime

    assert datetime.fromisoformat(utc_now()).tzinfo is not None