$ErrorActionPreference = 'Stop'
$root = 'D:\projects\HomeRouterLab-Neon-20261022'
Set-Location -LiteralPath $root

function Write-Utf8NoBom([string]$Path, [string]$Content) {
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  [IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

function Assert-Exit([string]$Step) {
  if ($LASTEXITCODE -ne 0) { throw "$Step failed (exit $LASTEXITCODE)" }
}

# 1) Legacy housekeeping
New-Item -ItemType Directory -Path "$root\scripts\legacy" -Force | Out-Null
foreach ($f in 'wan_probe.py','wan_fix.py','wan_matrix.py') {
  $src = Join-Path $root $f
  if (Test-Path -LiteralPath $src) { Move-Item -LiteralPath $src -Destination "$root\scripts\legacy\$f" -Force }
}
Remove-Item -LiteralPath "$root\install-package.b64" -Force -ErrorAction SilentlyContinue

# 2) Safety re-writes
Write-Utf8NoBom -Path "$root\src\homerouterlab\__init__.py" -Content @'
"""HomeRouterLab Neon — read-only WAN probe for home routers."""
__version__ = "0.2.0"
'@
Write-Utf8NoBom -Path "$root\src\homerouterlab\__main__.py" -Content @'
from .cli import main

raise SystemExit(main())
'@
Write-Utf8NoBom -Path "$root\src\homerouterlab\probe\__init__.py" -Content @'
"""Probe layers. Each layer is read-only and returns a ProbeResult."""
'@

# 3) README
Write-Utf8NoBom -Path "$root\README.md" -Content @'
# HomeRouterLab Neon

Read-only, layered WAN probe for home routers. It never changes router or firewall configuration and never guesses an IP: each layer either returns a validated public IPv4 with evidence, or reports `UNKNOWN`.

## Status (honest)

| Item | State |
|---|---|
| TR-064 / UPnP SOAP on 49000/5000 | **NO_ACCESS** on the tested network (both `192.168.0.1` and `192.168.100.1` refused the port) |
| HTTP status-page scrape | Implemented; returns `OBSERVED` only when a page contains a **validated public** IPv4 (`ipaddress`-checked, CGNAT excluded) |
| Telnet CLI (`display wan layer all`) | Implemented; requires port 23 open and accepted credentials |
| External egress IP | Optional (`--include-external`); explicitly labelled as *not* the router WAN IP |
| Configuration changes | **None.** The tool is read-only. |

Previous version stopped at the first layer that returned anything, even with `wan_ip: null`. v0.2.0 fixes this: a layer counts as successful only if it produced a validated public IPv4.

## Install

```powershell
python -m pip install -e ".[dev]"
```

## Run

```powershell
python -m homerouterlab
python -m homerouterlab --json
python -m homerouterlab --include-external
python -m homerouterlab --hosts 192.168.0.1,192.168.100.1 --timeout 5
```

Exit code `0` only when `status == "OBSERVED"`. `UNKNOWN` and `NO_ACCESS` return `1` — they are real outcomes, not crashes.

## Output

A JSON report is written to `reports/wan-probe-<utc>.json` with:

- `schema`: `homerouterlab.wan-probe/2`
- `result.final`: the chosen layer, status, `wan_ip`, and evidence
- `result.trace`: every layer that ran, in order
- `payload_sha256`: SHA-256 of the canonical payload

`reports/` is git-ignored because it contains LAN addresses.

## Layers

1. **tr064** — SOAP `GetExternalIPAddress` on `WANIPConnection` and `WANPPPConnection`, with control-path discovery from `/rootDesc.xml`, `/tr64desc.xml`, `/igd.xml`.
2. **http** — reads common unauthenticated status pages; accepts only public IPv4 (RFC1918, loopback, link-local, multicast, reserved, and `100.64.0.0/10` are rejected).
3. **telnet** — tries common Huawei/generic credentials and `display wan layer all`.
4. **external** (opt-in) — `api.ipify.org` / `ifconfig.me`; labelled as egress IP.

## Tests

```powershell
python -m pytest
```

CI runs the suite on Ubuntu and Windows for Python 3.10–3.12.

## Boundaries

- A successful local probe does not prove inbound reachability from the internet.
- An IP on a status page is a candidate until verified against the router's authenticated WAN page.
- TR-064 is a LAN-only protocol here. Do not expose port 49000 or UPnP to WAN.

## License

MIT — see `LICENSE`.
'@

# 4) CHANGELOG
Write-Utf8NoBom -Path "$root\CHANGELOG.md" -Content @'
# Changelog

All notable changes to this project are documented here. Format follows Keep a Changelog; versioning follows Semantic Versioning.

## [0.2.0] - 2026-10-22

### Added
- `src/homerouterlab` package with `homerouterlab` console entry point.
- Layered probe: `tr064`, `http`, `telnet`, optional `external`.
- Strict IPv4 validation via `ipaddress`; `100.64.0.0/10` excluded from WAN candidates.
- `payload_sha256` in every JSON report.
- Pytest suite and GitHub Actions CI matrix (Ubuntu/Windows, Python 3.10–3.12).

### Fixed
- A layer returning `CANDIDATES_FOUND` with `wan_ip: null` no longer stops the dispatcher. Only a validated public IPv4 is treated as success.
- Legacy one-off scripts moved to `scripts/legacy/`; they are superseded.

### Removed
- Generated `install-package.b64` artifact.

## [0.1.0] - 2026-10-22

### Added
- Initial CLI: `doctor`, `probe`, `plan`, `report`, `diff`, `verify`, `selftest`, `demo`.
- Local acceptance run: 16/16 CLI checks, 7/7 selftest checks, 50/51 unit tests (one Unix-only skip on Windows).
'@

# 5) SECURITY
Write-Utf8NoBom -Path "$root\SECURITY.md" -Content @'
# Security policy

## Scope

HomeRouterLab Neon is a **read-only** diagnostic tool. It does not modify router or firewall configuration, does not open ports, and does not transmit captured data anywhere except the optional `--include-external` public-IP lookup.

## Reporting a vulnerability

Open a private security advisory at:
https://github.com/Grar00t/HomeRouterLab-Neon/security/advisories/new

Do not open a public issue for vulnerabilities.

## Known boundaries

- TR-064/UPnP has a history of vulnerabilities when exposed to WAN (e.g. CVE-2017-17215). This tool only talks to the router on the LAN. Never forward port 49000 or 37215 from the internet.
- Telnet credentials tried by the `telnet` layer are default vendor credentials, not brute force.
- Reports contain LAN addresses and interface names. `reports/` is git-ignored; do not attach it to public issues without redaction.
'@

# 6) CONTRIBUTING
Write-Utf8NoBom -Path "$root\CONTRIBUTING.md" -Content @'
# Contributing

1. Fork and create a topic branch.
2. Keep the package in `src/homerouterlab/`. Do not add top-level modules.
3. Every probe layer must be read-only and must return a `ProbeResult`. It must not raise on network failure; return `NO_ACCESS` or `ERROR` instead.
4. A layer may return `OBSERVED` only with a validated public IPv4 (use `ipaddress`). Never return a private, loopback, link-local, multicast, reserved, or `100.64.0.0/10` address as WAN.
5. Add a test under `tests/` for any new parsing or filtering rule.
6. Run `python -m pytest` before opening a PR.
7. Do not commit files from `reports/`.

## Commit style

`type(scope): subject` — e.g. `fix(tr064): handle WANPPPConnection`.
'@

# 7) CI
Write-Utf8NoBom -Path "$root\.github\workflows\ci.yml" -Content @'
name: ci

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
        python: ["3.10", "3.11", "3.12"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python }}
          cache: pip
      - name: Install
        run: python -m pip install -e ".[dev]"
      - name: Tests
        run: python -m pytest -q
      - name: CLI smoke
        run: python -m homerouterlab --version
'@

# 8) docs/wan-probe.md
Write-Utf8NoBom -Path "$root\docs\wan-probe.md" -Content @'
# WAN probe (v0.2.0)

## Why the earlier scripts returned `UNKNOWN`

`wan_probe.py` and `wan_fix.py` treated `CANDIDATES_FOUND` as a terminal success even when `wan_ip` was `null`, and filtered `172.` as a whole instead of `172.16.0.0/12`. v0.2.0 replaces both with `src/homerouterlab/probe/`.

## Layer contract

Each layer returns a `ProbeResult`:

- `OBSERVED` — a validated public IPv4, with `evidence` naming the exact source.
- `NO_ACCESS` / `NO_WAN_SERVICE` / `NO_PUBLIC_IP` / `SKIP` — nothing usable; dispatcher continues.
- `ERROR` — unexpected exception; dispatcher records it and continues.

The dispatcher stops only on `OBSERVED`. If no layer observes an IP, the final result is `UNKNOWN` with a trace of what was tried. That is an answer, not a failure.

## Validation rule

`is_public_ipv4()` rejects: RFC1918, loopback, link-local, multicast, reserved, unspecified, and `100.64.0.0/10` (Shared Address Space / CGNAT). This is stricter than `not addr.is_private`, because `is_private` and `is_global` are both `False` for `100.64.0.0/10`.

## What this does not prove

- An IP scraped from an unauthenticated status page is a **candidate**, not proof of the router's WAN configuration. Verify against the authenticated WAN page.
- A local probe cannot prove inbound reachability from the internet. That requires an independent external observer.
'@

# 9) scripts/legacy/README.md
Write-Utf8NoBom -Path "$root\scripts\legacy\README.md" -Content @'
# Legacy scripts

These are the one-off scripts used before v0.2.0. They are kept for provenance only and are superseded by `src/homerouterlab/`.

- `wan_probe.py` — first attempt; TR-064 only on `WANIPConnection`.
- `wan_fix.py` — added HTTP, Telnet, external layers; stopped on `CANDIDATES_FOUND` with a null IP.
- `wan_matrix.py` — port/path matrix; confirmed 49000 closed on both routers.

Do not import these. They are not tested and are not part of the package.
'@

# 10) scripts/make_manifest.py
Write-Utf8NoBom -Path "$root\scripts\make_manifest.py" -Content @'
import hashlib, pathlib, sys

root = pathlib.Path(sys.argv[1])
skip_dirs = {".git", "reports", "__pycache__", ".pytest_cache", ".venv", "build", "dist"}
skip_files = {"SOURCE-MANIFEST.sha256"}
rows = []
for path in sorted(root.rglob("*")):
    if not path.is_file():
        continue
    rel = path.relative_to(root)
    if any(part in skip_dirs for part in rel.parts):
        continue
    if any(part.endswith(".egg-info") for part in rel.parts):
        continue
    if rel.name in skip_files or rel.suffix in {".pyc", ".log"}:
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    rows.append(f"{digest}  {rel.as_posix()}")
(root / "SOURCE-MANIFEST.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8")
print(f"manifest: {len(rows)} files")
'@

# 11) Install (must succeed)
python -m pip install -e ".[dev]" --quiet
Assert-Exit "pip install"

# 12) Tests (must pass before any commit)
python -m pytest -q
Assert-Exit "pytest"

# 13) Manifest
python "$root\scripts\make_manifest.py" $root
Assert-Exit "make_manifest"

# 14) Git
$gitEmail = (git config --global user.email) 2>$null
if (-not $gitEmail) {
  git config user.email "Grar00t@users.noreply.github.com"
  git config user.name "Grar00t"
}
git config core.autocrlf false
if (-not (Test-Path -LiteralPath "$root\.git")) { git init -b main | Out-Null }
git add -A
git diff --cached --quiet
if ($LASTEXITCODE -ne 0) {
  git -c user.name="Grar00t" -c user.email="Grar00t@users.noreply.github.com" commit -m "feat(v0.2.0): src-layout package, layered read-only WAN probe, tests, CI" | Out-Null
}
git branch -M main

# 15) GitHub
gh repo view Grar00t/HomeRouterLab-Neon --json name 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
  $hasOrigin = (git remote get-url origin) 2>$null
  if (-not $hasOrigin) { git remote add origin https://github.com/Grar00t/HomeRouterLab-Neon.git }
  git push -u origin main
  Assert-Exit "git push"
} else {
  gh repo create HomeRouterLab-Neon --public --source . --remote origin --push --disable-wiki --description "Read-only, layered WAN probe and diagnostics for home routers. No configuration changes."
  Assert-Exit "gh repo create"
}

Write-Host "`n=== DONE ===" -ForegroundColor Green
gh repo view Grar00t/HomeRouterLab-Neon --json url,defaultBranchRef --jq '"URL: " + .url + "   branch: " + .defaultBranchRef.name'
python -m homerouterlab --version