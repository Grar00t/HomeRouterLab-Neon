from homerouterlab.models import ProbeResult
from homerouterlab.probe.dispatcher import run


def _layer(name, status, ip=None):
    return (name, lambda: ProbeResult(layer=name, status=status, wan_ip=ip))


def test_stops_on_observed() -> None:
    out = run([_layer("a", "NO_ACCESS"), _layer("b", "OBSERVED", "8.8.8.8"), _layer("c", "OBSERVED", "1.1.1.1")])
    assert out["final"]["layer"] == "b"
    assert len(out["trace"]) == 2


def test_unknown_when_all_fail() -> None:
    out = run([_layer("a", "NO_ACCESS"), _layer("b", "SKIP")])
    assert out["final"]["status"] == "UNKNOWN"
    assert out["final"]["layer"] == "none"
    assert len(out["trace"]) == 2


def test_exception_becomes_error_trace() -> None:
    def boom():
        raise RuntimeError("nope")

    out = run([("bad", boom), _layer("b", "NO_ACCESS")])
    assert out["trace"][0]["status"] == "ERROR"
    assert out["final"]["status"] == "UNKNOWN"