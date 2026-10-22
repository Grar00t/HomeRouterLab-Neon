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