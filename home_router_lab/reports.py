"""Standalone reports, bounded integrity receipts, and semantic snapshot diffs."""
from __future__ import annotations

import hashlib
import html
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from .core import analyze_snapshot, utc_now


ARTIFACTS = ("snapshot.json", "evidence.json", "report.html", "receipt.json")
RECEIPT_SCHEMA = "homerouterlab.receipt/1"


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, allow_nan=False,
                       sort_keys=True, indent=2) + "\n").encode("utf-8")


def _text(value: Any) -> str:
    if value is None:
        return "UNKNOWN"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True)
    return str(value)


def _escape(value: Any) -> str:
    return html.escape(_text(value), quote=True)


def _table(headers: list[str], rows: list[list]) -> str:
    head = "".join(f"<th>{_escape(value)}</th>" for value in headers)
    body = "".join("<tr>" + "".join(f'<td dir="auto">{_escape(value)}</td>'
                                    for value in row) + "</tr>" for row in rows)
    if not rows:
        body = f'<tr><td colspan="{len(headers)}">No observations available.</td></tr>'
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _section(title: str, content: str, subtitle: str | None = None) -> str:
    intro = f'<p class="muted">{_escape(subtitle)}</p>' if subtitle else ""
    return f'<section><h2>{_escape(title)}</h2>{intro}{content}</section>'


def _details(label: str, value: Any) -> str:
    return f'<details><summary>{_escape(label)}</summary><pre dir="auto">{_escape(value)}</pre></details>'


def _trace_content(trace: Any) -> str:
    data = trace if isinstance(trace, dict) else {}
    hops = data.get("hops", []) if data else trace if isinstance(trace, list) else []
    rows = []
    for hop in hops:
        if not isinstance(hop, dict):
            continue
        latencies = hop.get("latency_ms", [])
        bounds = hop.get("latency_upper_bounds", [])
        if isinstance(latencies, list):
            latency = ", ".join(("<" if i < len(bounds) and bounds[i] else "") + _text(value)
                                for i, value in enumerate(latencies)) or None
        else:
            latency = latencies
        address = hop.get("address", hop.get("ip"))
        if address is None and hop.get("timeout"):
            address = "TIMEOUT"
        rows.append([hop.get("ttl", hop.get("hop")), address, hop.get("scope"), latency])
    status = f'<p class="muted"><strong>Trace status:</strong> {_escape(data.get("status"))}</p>'
    limitation = f'<p class="muted" dir="auto">{_escape(data.get("limitation"))}</p>' if data.get("limitation") else ""
    return (status + '<div class="compact">' + _table(["TTL", "Address", "Scope", "ms"], rows)
            + '</div>' + limitation + _details("Full trace evidence", trace))


def _gateway_content(gateway: dict) -> str:
    rows = []
    for port in gateway.get("ports", []):
        reachable = port.get("reachable")
        result = "CONNECTED" if reachable is True else "FAILED" if reachable is False else None
        rows.append([f'TCP {_text(port.get("port"))}', result, port.get("latency_ms")])
    response = gateway.get("http") or {}
    rows.append(["HTTP", response.get("status"), response.get("latency_ms")])
    address = f'<p class="muted">Address: {_escape(gateway.get("address"))}</p>'
    redirect = '<p class="muted">HTTP redirect observed; not followed.</p>' if response.get("redirect_blocked") else ""
    return (address + '<div class="compact">' + _table(["Check", "Result", "ms"], rows)
            + '</div>' + redirect + _details("Full gateway evidence", gateway))


def _render_html(snapshot: dict, evidence: dict) -> str:
    analysis = evidence["analysis"]
    route = snapshot.get("default_route") or {}
    host = snapshot.get("host") or {}
    ipv4 = analysis.get("ipv4_publication") or {}
    ipv6 = analysis.get("ipv6_publication") or {}
    synthetic_banner = (
        '<aside class="synthetic-banner" role="note"><strong>SYNTHETIC — DEMONSTRATION DATA</strong>'
        '<p>The network snapshot is sample data, not an observed network. Any separate service checks are identified by their own evidence.</p>'
        '<p dir="auto">لقطة الشبكة بيانات محاكاة؛ أي فحوص منفصلة للخدمة موضّحة بأدلتها الخاصة.</p></aside>'
    ) if snapshot.get("synthetic") else ""
    cards = "".join(f'<div class="metric"><span>{_escape(label)}</span><strong dir="auto">{_escape(value)}</strong></div>'
                    for label, value in (("PC IPv4", snapshot.get("primary_ipv4")),
                                         ("Default gateway", route.get("next_hop")),
                                         ("Public reachability", "NOT_TESTED")))
    interfaces = []
    for interface in snapshot.get("interfaces", []):
        addresses = [f'{a.get("address", "?")}/{a.get("prefix_length", "?")}'
                     for a in interface.get("ipv4", []) + interface.get("ipv6", [])]
        interfaces.append([interface.get("name"), interface.get("kind"), addresses,
                           interface.get("gateways", []), interface.get("dns_servers", [])])
    findings = [[f.get("code"), f.get("status"), f.get("message"), f.get("evidence")]
                for f in analysis.get("findings", [])]
    sections = [
        _section("Interfaces", _table(["Interface", "Kind", "Addresses", "Gateway", "DNS"], interfaces)),
        _section("Publication evidence", _table(["Path", "Status", "Basis"], [
            ["IPv4", ipv4.get("status"), {"wan_ip": ipv4.get("wan_ip"), "wan_source": ipv4.get("wan_source")}],
            ["IPv6", ipv6.get("status"), {"global_addresses": ipv6.get("global_addresses", []),
                                         "inbound_firewall": ipv6.get("inbound_firewall", "UNKNOWN")}]]),
                 "A private PC address or an overlay address does not establish ISP CGNAT. A globally scoped address does not establish inbound reachability."),
        _section("Findings", _table(["Finding", "State", "Meaning", "Evidence"], findings))]
    if snapshot.get("trace") is not None:
        sections.append(_section("Observed route trace", _trace_content(snapshot["trace"]),
                                 "Hop addresses are observations. They do not by themselves prove NAT boundaries or the number of routers."))
    if snapshot.get("gateway_probe") is not None:
        sections.append(_section("Gateway response", _gateway_content(snapshot["gateway_probe"]),
                                 "Only the discovered private gateway was probed. Redirects were not followed and authentication was not used."))
    if evidence.get("service") is not None:
        sections.append(_section("Local service probe", f'<pre dir="auto">{_escape(evidence["service"])}</pre>',
                                 "Local TCP/HTTP success is not an off-network test. Target address scope is not proof of the process's listening binding."))
    if evidence.get("plan") is not None:
        plan = evidence["plan"]
        choice_rows = [[c.get("method"), c.get("status"), c.get("requirements", [])]
                       for c in plan.get("choices", [])]
        step_rows = [[s.get("number"), s.get("status"), s.get("action")]
                     for s in plan.get("steps", [])]
        sections.append(_section("Publication plan", _table(["Method", "State", "Requirements"], choice_rows)
                                 + '<h3>Next checks</h3>' + _table(["Step", "State", "Action"], step_rows),
                                 "This plan does not execute router, firewall, or publication changes. No atomic multi-device rollback is claimed."))
    if snapshot.get("observations") or snapshot.get("errors"):
        sections.append(_section("Collection limits", f'<pre dir="auto">{_escape({"observations": snapshot.get("observations", []), "errors": snapshot.get("errors", [])})}</pre>'))
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="color-scheme" content="dark"><title>HomeRouterLab — Local Network Report</title>
<style>
:root{color-scheme:dark;--bg:#07101a;--panel:#101c2c;--text:#e8f2ff;--muted:#a7b9cf;--cyan:#45eadb;--pink:#f087d8;--line:#253c55}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 15% 0%,#142c41 0%,var(--bg) 48%);color:var(--text);font:15px/1.65 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1180px;margin:auto;padding:38px 24px 56px}header{border-top:3px solid var(--cyan);padding:25px 0 27px;border-bottom:1px solid var(--line)}
.eyebrow{color:var(--cyan);font-size:12px;font-weight:750;letter-spacing:.16em}h1{font-size:clamp(30px,5vw,48px);letter-spacing:-.035em;line-height:1.15;margin:12px 0}h1 span{color:var(--pink)}
.sub,.muted{color:var(--muted)}.meta{display:flex;flex-wrap:wrap;gap:10px 28px;font:13px/1.6 ui-monospace,Consolas,monospace;color:var(--muted)}
.synthetic-banner{margin:22px 0;padding:18px 20px;border:2px solid #ffc66d;border-radius:8px;background:#392a18;color:#fff1d9}.synthetic-banner strong{display:block;font-size:18px;letter-spacing:.04em;color:#ffcf85}.synthetic-banner p{margin:7px 0 0}details{margin-top:17px;border-top:1px solid var(--line);padding-top:12px}summary{color:var(--cyan);cursor:pointer;font-size:13px}.compact td{min-width:0}.compact th:first-child,.compact td:first-child{width:1%;white-space:nowrap}
.metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin:24px 0}.metric{border:1px solid var(--line);background:linear-gradient(125deg,#112236,#101a29);padding:20px;border-radius:10px}.metric span{display:block;color:var(--muted);font-size:13px}.metric strong{display:block;color:var(--cyan);font:600 clamp(16px,2vw,22px)/1.5 ui-monospace,Consolas,monospace;overflow-wrap:anywhere;margin-top:7px}
section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:22px;margin:19px 0}h2{font-size:20px;letter-spacing:-.02em;line-height:1.3;margin:0 0 14px}h3{font-size:16px;margin:22px 0 12px}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--cyan);font-size:11px;letter-spacing:.04em;text-transform:uppercase;padding:11px 12px;border-bottom:1px solid #3a586d}td{padding:13px 12px;vertical-align:top;border-bottom:1px solid var(--line);overflow-wrap:anywhere;min-width:105px}tr:last-child td{border-bottom:none}td:nth-child(2){color:#f1c48d}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.7 ui-monospace,Consolas,monospace;padding:16px;background:#091420;border:1px solid var(--line);border-radius:6px;color:#d3e4f5}footer{margin-top:26px;border-top:1px solid var(--line);padding-top:20px;color:var(--muted);font-size:12px}.note{border-inline-start:3px solid var(--pink);padding-inline-start:15px;color:var(--muted)}
@media(max-width:720px){main{padding:20px 14px 36px}.metrics{grid-template-columns:1fr;gap:9px}.metric{padding:15px}section{padding:17px 13px}.meta{display:block}td,th{padding:10px 8px}}
@media print{body{background:#fff;color:#111}main{max-width:none;padding:0}section,.metric{background:#fff;border-color:#bbb;break-inside:avoid}.sub,.muted,.meta,footer,.note{color:#333}th,.metric strong{color:#075a62}td:nth-child(2){color:#333}pre{background:#f5f5f5;color:#111;border-color:#bbb}}
</style></head><body><main><header><div class="eyebrow">HOME NETWORK OBSERVATIONS</div>
<h1>HomeRouterLab <span>Neon</span></h1><p class="sub">Local topology, service checks, and an evidence-based publication plan.</p>
""" + synthetic_banner + f'<div class="meta"><span dir="auto">Host: {_escape(host.get("name"))}</span><span>Collected: {_escape(snapshot.get("collected_utc"))}</span><span>Platform: {_escape(host.get("platform"))}</span></div></header><div class="metrics">{cards}</div>' + \
        '<p class="note" dir="auto">تقرير فحص محلي. الحالة UNKNOWN تعني أن الدليل غير متوفر. الوصول من الإنترنت لم يُختبر؛ لم تُغيّر إعدادات الموجّه أو الجدار الناري.</p>' + \
        "".join(sections) + \
        '<footer>Companion files: snapshot.json, evidence.json, receipt.json. SHA-256 and byte counts detect changes relative to this receipt; they do not establish authenticity, content accuracy, or public reachability. An attacker who replaces both files and receipt can recompute them. This page uses no remote assets or JavaScript.</footer></main></body></html>\n'


def export_report(snapshot: dict, output: str | Path, analysis: dict | None = None,
                  service: dict | None = None, plan: dict | None = None) -> dict:
    """Create four new report files. Existing named artifacts are never replaced."""
    directory = Path(output).expanduser().absolute()
    if directory.exists() and not directory.is_dir():
        raise NotADirectoryError(str(directory))
    for name in ARTIFACTS:
        path = directory / name
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"Refusing to overwrite existing artifact: {path}")
    evidence = {"schema": "homerouterlab.evidence/1", "created_utc": utc_now(),
                "analysis": analysis if analysis is not None else analyze_snapshot(snapshot),
                "service": service, "plan": plan}
    # Serialize all content before creating artifacts: NaN and invalid data fail early.
    contents = {"snapshot.json": _json_bytes(snapshot), "evidence.json": _json_bytes(evidence),
                "report.html": _render_html(snapshot, evidence).encode("utf-8")}
    receipt = {"schema": RECEIPT_SCHEMA, "created_utc": utc_now(),
               "files": [{"path": name, "sha256": hashlib.sha256(content).hexdigest(),
                          "size_bytes": len(content)} for name, content in contents.items()],
               "scope": "Byte integrity relative to this receipt; not authenticity or semantic correctness"}
    contents["receipt.json"] = _json_bytes(receipt)
    directory.mkdir(parents=True, exist_ok=True)
    for name, content in contents.items():
        with (directory / name).open("xb") as stream:
            stream.write(content)
    return {"directory": str(directory), "snapshot": str(directory / "snapshot.json"),
            "evidence": str(directory / "evidence.json"), "html": str(directory / "report.html"),
            "receipt": str(directory / "receipt.json")}


def _safe_basename(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 200 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
        return False
    if value.endswith("."):
        return False
    stem = value.split(".", 1)[0].upper()
    return not re.fullmatch(r"CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]", stem)


def verify_receipt(path: str | Path) -> dict:
    result = {"schema": "homerouterlab.verification/1", "status": "FAIL", "checks": [], "errors": []}
    receipt_path = Path(path)
    try:
        if receipt_path.is_symlink() or not receipt_path.is_file():
            raise ValueError("Receipt must be a normal file, not a symlink")
        if receipt_path.stat().st_size > 1048576:
            raise ValueError("Receipt exceeds 1 MiB")
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"),
                             parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Non-finite JSON number")))
        if not isinstance(receipt, dict) or receipt.get("schema") != RECEIPT_SCHEMA:
            raise ValueError("Unsupported receipt schema")
        files = receipt.get("files")
        if not isinstance(files, list) or not files or len(files) > 128:
            raise ValueError("Receipt must list between 1 and 128 files")
        seen = set()
        # Validate every entry before opening any referenced file.
        for entry in files:
            if not isinstance(entry, dict) or not _safe_basename(entry.get("path")):
                raise ValueError("Receipt file path must be a safe basename")
            name = entry["path"]
            # Conservative across platforms: Windows normally ignores case.
            canonical_name = name.casefold()
            if canonical_name in seen or canonical_name == receipt_path.name.casefold():
                raise ValueError("Duplicate or self-referencing receipt entry")
            seen.add(canonical_name)
            if not isinstance(entry.get("sha256"), str) or not re.fullmatch(r"[0-9a-fA-F]{64}", entry["sha256"]):
                raise ValueError("Invalid SHA-256 value")
            if type(entry.get("size_bytes")) is not int or entry["size_bytes"] < 0:
                raise ValueError("Invalid file byte count")
        for entry in files:
            check = {"path": entry["path"], "status": "FAIL", "expected_size_bytes": entry["size_bytes"],
                     "expected_sha256": entry["sha256"].lower()}
            target = receipt_path.parent / entry["path"]
            try:
                if not stat.S_ISREG(target.lstat().st_mode):
                    raise ValueError("Target must be a normal file, not a symlink or special file")
                flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
                         | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
                descriptor = os.open(target, flags)
                with os.fdopen(descriptor, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode):
                        raise ValueError("Target is not a normal file")
                    check["actual_size_bytes"] = info.st_size
                    if info.st_size != entry["size_bytes"]:
                        raise ValueError("Byte count mismatch")
                    digest = hashlib.sha256()
                    for chunk in iter(lambda: stream.read(1048576), b""):
                        digest.update(chunk)
                    check["actual_sha256"] = digest.hexdigest()
                    if digest.hexdigest() != entry["sha256"].lower():
                        raise ValueError("SHA-256 mismatch")
                check["status"] = "PASS"
            except (OSError, ValueError) as exc:
                check["error"] = str(exc)
                result["errors"].append(f"{entry['path']}: {exc}")
            result["checks"].append(check)
        if not result["errors"]:
            result["status"] = "PASS"
    except (OSError, ValueError, TypeError) as exc:
        result["errors"].append(str(exc))
    return result


def _normalized_snapshot(snapshot: dict) -> dict:
    interfaces = []
    for value in snapshot.get("interfaces", []):
        interface = {key: value.get(key) for key in ("index", "name", "description", "kind")}
        for key in ("ipv4", "ipv6"):
            interface[key] = sorted([{"address": a.get("address"), "prefix_length": a.get("prefix_length")}
                                     for a in value.get(key, [])], key=lambda a: _text(a))
        interface["gateways"] = sorted(value.get("gateways", []))
        # DNS order is meaningful; retain resolver preference order.
        interface["dns_servers"] = value.get("dns_servers", [])
        interfaces.append(interface)
    route = snapshot.get("default_route")
    route = {key: route.get(key) for key in ("interface_index", "interface_name", "next_hop",
                                            "route_metric", "interface_metric", "total_metric")} if route else None
    probe = snapshot.get("gateway_probe")
    gateway = None
    if probe:
        response = probe.get("http") or {}
        gateway = {"address": probe.get("address"),
                   "ports": sorted([{"port": p.get("port"), "reachable": p.get("reachable")}
                                    for p in probe.get("ports", [])], key=lambda p: _text(p)),
                   "http_status": response.get("status"), "vendor_hints": sorted(response.get("vendor_hints", []))}
    trace = snapshot.get("trace")
    hops = trace.get("hops", []) if isinstance(trace, dict) else trace if isinstance(trace, list) else []
    trace_values = [{key: hop.get(key) for key in ("ttl", "hop", "address", "ip", "status") if key in hop}
                    for hop in hops if isinstance(hop, dict)]
    return {"primary_ipv4": snapshot.get("primary_ipv4"), "default_route": route,
            "interfaces": sorted(interfaces, key=lambda i: _text(i)), "gateway_probe": gateway,
            "trace_hops": trace_values}


def diff_snapshots(before: dict, after: dict) -> dict:
    a, b = _normalized_snapshot(before), _normalized_snapshot(after)
    changes = [{"field": key, "before": a[key], "after": b[key]} for key in a if a[key] != b[key]]
    return {"schema": "homerouterlab.diff/1", "changed": bool(changes), "changes": changes}
