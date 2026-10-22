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