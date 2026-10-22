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