"""Compact terminal presentation. Rendering never collects or changes network state."""
from __future__ import annotations

import datetime as dt
import json
import os
import re
from typing import Any

try:
    from rich import box
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:  # The diagnostic core has no third-party dependency.
    Console = None  # type: ignore[assignment,misc]
    RICH_AVAILABLE = False

try:
    from . import __version__ as VERSION
except ImportError:
    VERSION = "0.1.0"


CYAN = "#31e7ef"
MAGENTA = "#f46fda"
VIOLET = "#aa8dff"
MUTED = "#99a9bd"
GREEN = "#83e8b2"
AMBER = "#f4cb75"
RED = "#ff8599"
_CONTROLS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _safe(value: Any, limit: int = 400) -> str:
    if value is None or value == "":
        return "UNKNOWN"
    if isinstance(value, (dict, list, tuple)):
        raw = json.dumps(value, ensure_ascii=False, default=str)
    else:
        raw = str(value)
    raw = _CONTROLS.sub(" ", raw)
    return raw if len(raw) <= limit else raw[:limit - 1] + "…"


def _t(value: Any, style: str = "", limit: int = 400):
    # All observed strings enter Rich through Text, never markup or ANSI parsers.
    return Text(_safe(value, limit), style=style, overflow="fold")


def _label(lang: str, en: str, ar: str) -> str:
    return ar if lang == "ar" else en


def _state_style(value: Any) -> str:
    status = str(value or "UNKNOWN").upper()
    if status in {"PASS", "OK", "VERIFIED", "REACHABLE", "COMPLETE", "MATCH", "UNCHANGED"}:
        return GREEN
    if status in {"FAIL", "FAILED", "ERROR", "MISMATCH", "UNREACHABLE"}:
        return RED
    if status in {"OBSERVED", "SUPPLIED", "PLAN_ONLY", "CANDIDATE", "CHANGED"}:
        return CYAN
    if status in {"SYNTHETIC", "SYNTHETIC SAMPLE"}:
        return MAGENTA
    return AMBER


def _state(value: Any):
    return _t(value or "UNKNOWN", "bold " + _state_style(value))


def _grid(rows: list[tuple[Any, Any]], *, value_style: str = ""):
    table = Table.grid(padding=(0, 2), expand=True)
    table.add_column(style=MUTED, no_wrap=True)
    table.add_column(ratio=1, overflow="fold")
    for label, value in rows:
        table.add_row(_t(label, MUTED), value if isinstance(value, Text) else _t(value, value_style))
    return table


def _table(*headers: str, narrow: bool = False):
    table = Table(box=box.SIMPLE, header_style="bold " + VIOLET,
                  border_style="#423752", padding=(0, 1), expand=True,
                  collapse_padding=True, show_edge=False)
    for header in headers:
        table.add_column(_t(header), overflow="fold")
    return table


def _panel(content, title: str, *, border: str = VIOLET):
    return Panel(content, title=_t(title, "bold " + border), title_align="left",
                 border_style=border, box=box.ROUNDED, padding=(0, 1))


def _address_rows(interface: dict) -> str:
    values = []
    for item in interface.get("ipv4", [])[:2]:
        if isinstance(item, dict):
            address = _safe(item.get("address"))
            prefix = item.get("prefix_length")
            values.append(address + (f"/{prefix}" if isinstance(prefix, int) else ""))
        else:
            values.append(_safe(item))
    return ", ".join(values) if values else "No IPv4 observed"


def _header(console, command: str, data: dict, lang: str):
    snapshot = data.get("snapshot") if isinstance(data.get("snapshot"), dict) else {}
    synthetic = bool(snapshot.get("synthetic") or data.get("synthetic"))
    title = Text("HomeRouterLab", style="bold " + CYAN)
    title.append("  NEON", style="bold " + MAGENTA)
    title.append("  v" + _safe(VERSION, 30), style=MUTED)
    console.print(title)
    timestamp = (snapshot.get("collected_utc") or data.get("probed_utc")
                 or data.get("created_utc") or data.get("checked_utc"))
    line = Text(_safe(command.upper(), 30), style=VIOLET)
    if timestamp:
        line.append("   " + _safe(timestamp, 50), style=MUTED)
    else:
        line.append("   rendered " + dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), style=MUTED)
    console.print(line)
    if synthetic:
        console.print(_t(_label(lang, "SYNTHETIC SAMPLE · not a live network observation",
                               "SYNTHETIC · مثال توضيحي، وليس فحص الشبكة الحالية"), "bold " + MAGENTA))
    console.print(Rule(style="#423752"))


def _render_doctor(console, data: dict, lang: str):
    snapshot = data.get("snapshot") or {}
    analysis = data.get("analysis") or {}
    host = snapshot.get("host") or {}
    route = snapshot.get("default_route") or {}
    gateway = snapshot.get("gateway_probe") or {}
    source = "SYNTHETIC" if snapshot.get("synthetic") else "RECORDED OBSERVATIONS"
    summary = [
        (_label(lang, "Computer", "الجهاز"), host.get("name")),
        (_label(lang, "LAN IPv4", "عنوان الجهاز"), snapshot.get("primary_ipv4")),
        (_label(lang, "Gateway", "البوابة"), route.get("next_hop")),
        (_label(lang, "Source", "المصدر"), source),
    ]
    http = gateway.get("http") or {}
    hints = http.get("vendor_hints") or []
    identity = _safe(gateway.get("model") or "UNKNOWN")
    if hints:
        identity += " · page hint: " + ", ".join(_safe(v, 35) for v in hints[:2])
    if gateway:
        summary.append((_label(lang, "Gateway model", "طراز البوابة"), identity))
    console.print(_panel(_grid(summary), _label(lang, "Network snapshot", "لقطة الشبكة"), border=CYAN))

    interfaces = list(snapshot.get("interfaces") or [])
    if interfaces:
        interfaces.sort(key=lambda item: item.get("index") != route.get("interface_index"))
        narrow = console.width < 64
        table = (_table(_label(lang, "Interface / role", "الواجهة / الدور"), "IPv4") if narrow else
                 _table(_label(lang, "Interface", "الواجهة"), "IPv4", _label(lang, "Role", "الدور")))
        if narrow and console.width >= 34:
            # Keep a full IPv4/CIDR address readable on a phone-width terminal.
            table.columns[1].min_width = 18
        for interface in interfaces[:5]:
            role = str(interface.get("kind") or "unknown")
            if interface.get("index") is not None and interface.get("index") == route.get("interface_index"):
                role += " / default"
            name = _t(interface.get("name"), limit=70)
            if narrow:
                name.append("\n" + _safe(role), style=MUTED)
                table.add_row(name, _t(_address_rows(interface), CYAN))
            else:
                table.add_row(name, _t(_address_rows(interface), CYAN), _t(role, MUTED))
        console.print(table)
        if len(interfaces) > 5:
            console.print(_t(f"+ {len(interfaces)-5} interfaces in the JSON snapshot", MUTED))

    trace = snapshot.get("trace") or data.get("trace")
    if isinstance(trace, dict):
        hops = trace.get("hops") or []
        console.print(_grid([(_label(lang, "Route trace", "تتبع المسار"), _state(trace.get("status")))]))
        if hops:
            table = _table("Hop", "IPv4", "Scope", "ms")
            for hop in hops[:4]:
                delays = hop.get("latency_ms") or []
                upper = hop.get("latency_upper_bounds") or []
                latency = " / ".join(("<" if i < len(upper) and upper[i] else "") + f"{float(value):g}"
                                     for i, value in enumerate(delays[:3]) if isinstance(value, (int, float)))
                table.add_row(_t(hop.get("ttl")), _t(hop.get("address") or "No reply", CYAN),
                              _t(hop.get("scope"), MUTED), _t(latency or "—", MUTED))
            console.print(table)
            console.print(_t(_label(lang, "Hop replies do not identify NAT layers or router WAN assignments.",
                                   "ردود المسار لا تثبت عدد طبقات NAT أو عنوان WAN."), MUTED))
        elif trace.get("error"):
            console.print(_t(trace["error"], AMBER))

    publication = analysis.get("ipv4_publication") or {}
    v6 = analysis.get("ipv6_publication") or {}
    rows = [
        ("WAN IPv4", _state(publication.get("status"))),
        ("IPv6", _state(v6.get("status"))),
        (_label(lang, "Internet access", "الوصول من الإنترنت"), _state(analysis.get("public_reachability") or "NOT_TESTED")),
    ]
    pieces = [_grid(rows)]
    priorities = {"WAN_UNKNOWN", "OVERLAY_INTERFACES", "COLLECTOR_ERROR", "WAN_SHARED", "WAN_PRIVATE", "WAN_GLOBAL"}
    findings = [item for item in analysis.get("findings", []) if item.get("code") in priorities]
    for finding in findings[:2]:
        line = _state(finding.get("status"))
        line.append("  " + _safe(finding.get("message"), 260), style=MUTED)
        pieces.append(line)
    console.print(_panel(Group(*pieces), _label(lang, "Publication evidence", "أدلة إتاحة الخدمة"), border=MAGENTA))

    errors = snapshot.get("errors") or []
    for error in errors[:2]:
        if isinstance(error, dict):
            console.print(_t("COLLECTION ERROR · " + _safe(error.get("stage")) + ": " + _safe(error.get("error")), RED))
        else:
            console.print(_t(error, RED))
    _render_artifacts(console, data.get("artifacts"), lang)


def _render_artifacts(console, artifacts: Any, lang: str):
    if not artifacts:
        return
    rows = []
    if isinstance(artifacts, dict):
        for key, value in list(artifacts.items())[:5]:
            if isinstance(value, dict):
                value = value.get("path") or value.get("file") or value
            rows.append((_safe(key, 40), value))
    elif isinstance(artifacts, list):
        rows = [("File", value) for value in artifacts[:5]]
    else:
        rows = [("File", artifacts)]
    console.print(_panel(_grid(rows), _label(lang, "Saved files", "الملفات المحفوظة"), border=VIOLET))


def _render_probe(console, data: dict, lang: str):
    service = data.get("service") if isinstance(data.get("service"), dict) else data
    tcp = service.get("tcp") or {}
    http = service.get("http") or {}
    reachable = tcp.get("reachable")
    tcp_state = "REACHABLE" if reachable is True else "UNREACHABLE" if reachable is False else "UNKNOWN"
    rows = [("URL", service.get("url")), ("TCP", _state(tcp_state)),
            ("HTTP status", http.get("status") if http.get("status") is not None else "NO RESPONSE"),
            ("HTTP detail", http.get("error") or ("Response received" if http.get("status") is not None else "NOT_TESTED")),
            ("Target scope", service.get("bind_scope")),
            ("Internet access", _state(service.get("public_reachability") or "NOT_TESTED"))]
    if http.get("title"):
        rows.insert(4, ("Page title", http["title"]))
    if http.get("latency_ms") is not None:
        rows.insert(4, ("HTTP time", _safe(http["latency_ms"]) + " ms"))
    console.print(_panel(_grid(rows), _label(lang, "Service observation", "نتيجة فحص الخدمة"), border=CYAN))
    console.print(_t(_label(lang, "A response here does not establish off-network reachability.",
                           "الاستجابة هنا لا تثبت الوصول من شبكة خارجية."), MUTED))
    _render_artifacts(console, data.get("artifacts"), lang)


def _render_plan(console, data: dict, lang: str):
    plan = data.get("plan") if isinstance(data.get("plan"), dict) else data
    analysis = plan.get("analysis") or {}
    ipv4 = analysis.get("ipv4_publication") or {}
    service = plan.get("service") or {}
    console.print(_panel(_grid([
        ("Mode", _state("PLAN_ONLY" if plan.get("execute") is False else "UNKNOWN")),
        ("Service", service.get("url")),
        ("WAN evidence", _state(ipv4.get("status"))),
        ("WAN source", ipv4.get("wan_source") or "NOT_OBSERVED"),
        ("Internet access", _state(plan.get("public_reachability") or "NOT_TESTED")),
    ]), _label(lang, "Publication plan", "خطة إتاحة الخدمة"), border=MAGENTA))
    choices = _table(_label(lang, "Access method", "طريقة الوصول"), _label(lang, "Evidence", "حالة الأدلة"))
    for choice in plan.get("choices", []):
        choices.add_row(_t(choice.get("method")), _state(choice.get("status")))
    console.print(choices)
    console.print(_t(_label(lang, "Next evidence to collect", "الأدلة المطلوبة تاليًا"), "bold " + CYAN))
    for step in plan.get("steps", [])[:10]:
        line = _t(str(step.get("number", "·")) + ". ", VIOLET)
        line.append(_safe(step.get("action"), 400))
        console.print(line)
    for item in plan.get("limits", [])[:2]:
        console.print(_t(item, MUTED))
    _render_artifacts(console, data.get("artifacts"), lang)


def _checks(data: dict) -> list[dict]:
    checks = data.get("checks") or []
    if isinstance(checks, dict):
        checks = [{"name": name, **value} if isinstance(value, dict)
                  else {"name": name, "status": "PASS" if value is True else "FAIL" if value is False else "UNKNOWN", "detail": value}
                  for name, value in checks.items()]
    return [item if isinstance(item, dict) else {"name": item, "status": "UNKNOWN"} for item in checks]


def _render_checks(console, command: str, data: dict, lang: str):
    title = _label(lang, "Receipt integrity", "سلامة ملفات الإيصال") if command == "verify" else _label(lang, "Loopback self-test", "اختبار loopback")
    console.print(_panel(_grid([("Result", _state(data.get("status")))]), title, border=CYAN))
    table = _table("Check", "State", "Detail")
    for check in _checks(data)[:16]:
        status = check.get("status")
        if status is None:
            match = check.get("matched", check.get("ok"))
            status = "PASS" if match is True else "FAIL" if match is False else "UNKNOWN"
        name = check.get("name") or check.get("path") or check.get("file") or "Check"
        detail = check.get("detail") or check.get("error") or check.get("message") or "—"
        table.add_row(_t(name, limit=180), _state(status), _t(detail, MUTED, limit=240))
    if table.row_count:
        console.print(table)
    for error in (data.get("errors") or [])[:5]:
        console.print(_t(error, RED))
    note = ("Receipt checks compare file digests; they do not independently establish report accuracy."
            if command == "verify" else
            "This test covers a temporary loopback service; Internet access remains NOT_TESTED.")
    console.print(_t(note, MUTED))
    _render_artifacts(console, data.get("artifacts"), lang)


def _render_diff(console, data: dict, lang: str):
    changed = data.get("changed")
    result = "CHANGED" if changed is True else "UNCHANGED" if changed is False else "UNKNOWN"
    console.print(_panel(_grid([("Result", _state(result))]), _label(lang, "Snapshot comparison", "مقارنة اللقطات"), border=VIOLET))
    changes = data.get("changes") or []
    if isinstance(changes, dict):
        changes = [{"path": key, **value} if isinstance(value, dict) else {"path": key, "after": value}
                   for key, value in changes.items()]
    if changes:
        table = _table("Field", "Before", "After")
        for item in changes[:16]:
            if isinstance(item, dict):
                table.add_row(_t(item.get("path") or item.get("field") or item.get("name")),
                              _t(item.get("before", item.get("old")), MUTED, limit=140),
                              _t(item.get("after", item.get("new")), CYAN, limit=140))
            else:
                table.add_row(_t(item), _t("UNKNOWN"), _t("UNKNOWN"))
        console.print(table)
        if len(changes) > 16:
            console.print(_t(f"+ {len(changes)-16} changes available in JSON", MUTED))


def render_result(command: str, data: dict, *, color: str = "auto", lang: str = "en",
                  width: int | None = None, record: bool = False) -> Console | None:
    """Render a completed command without interpreting markup in observed values.

    ``record=True`` returns a Rich Console suitable for ``export_text`` or
    ``export_svg``. The fallback prints ordinary JSON and returns None.
    Environment-based color suppression takes precedence over ``always``.
    """
    if not RICH_AVAILABLE:
        print("HomeRouterLab Neon · " + _safe(command, 40))
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return None
    if color not in {"auto", "always", "never"}:
        raise ValueError("color must be auto, always, or never")
    disabled = color == "never" or "NO_COLOR" in os.environ or os.environ.get("TERM", "").lower() == "dumb"
    force_terminal = False if disabled else True if color == "always" else None
    console = Console(force_terminal=force_terminal, no_color=disabled,
                      color_system=None if disabled else "truecolor" if color == "always" else "auto", width=width,
                      record=record, markup=False, highlight=False)
    _header(console, command, data, lang)
    if command in {"doctor", "report", "demo"}:
        _render_doctor(console, data, lang)
    elif command == "probe":
        _render_probe(console, data, lang)
    elif command == "plan":
        _render_plan(console, data, lang)
    elif command in {"verify", "selftest"}:
        _render_checks(console, command, data, lang)
    elif command == "diff":
        _render_diff(console, data, lang)
    else:
        console.print(Text(json.dumps(data, ensure_ascii=False, indent=2, default=str)))
    return console
