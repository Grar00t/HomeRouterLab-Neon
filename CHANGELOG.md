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