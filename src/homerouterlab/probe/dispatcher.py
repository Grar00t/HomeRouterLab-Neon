"""Ordered probe dispatcher with explicit fallback semantics."""
from __future__ import annotations

from typing import Callable, Iterable

from ..models import ProbeResult
from . import external_api, http_status, telnet_cli, tr064

LayerFn = Callable[[], ProbeResult]


def build_layers(
    hosts: list[str], timeout: float, include_external: bool = False
) -> list[tuple[str, LayerFn]]:
    layers: list[tuple[str, LayerFn]] = [
        ("tr064", lambda: tr064.probe(hosts, timeout)),
        ("http", lambda: http_status.probe(hosts, timeout)),
        ("telnet", lambda: telnet_cli.probe(hosts, timeout)),
    ]
    if include_external:
        layers.append(("external", lambda: external_api.probe(max(timeout, 5.0))))
    return layers


def run(layers: Iterable[tuple[str, LayerFn]]) -> dict:
    trace: list[dict] = []
    observed: ProbeResult | None = None
    candidates: ProbeResult | None = None
    for name, fn in layers:
        try:
            result = fn()
        except Exception as exc:
            result = ProbeResult(layer=name, status="ERROR", error=f"{type(exc).__name__}: {exc}")
        trace.append(result.to_dict())
        if result.status == "OBSERVED":
            observed = result
            break
        if result.status == "CANDIDATES_FOUND" and candidates is None:
            candidates = result
    final = observed or candidates
    if final is None:
        final = ProbeResult(
            layer="none",
            status="UNKNOWN",
            notes="no layer produced an IP; this is a real result, not a failure",
        )
    return {"final": final.to_dict(), "trace": trace}