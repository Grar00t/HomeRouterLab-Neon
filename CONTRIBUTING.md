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