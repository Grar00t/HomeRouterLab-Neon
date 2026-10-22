# Home gateway legacy discovery

Inspection date: 2026-10-22. Read-only discovery from the supplied CSV and the connected GitHub/Google Drive accounts. No router changes, deleted-file recovery, remote publication, or credentials access occurred.

## Confirmed old project name

The supplied `NETWORK-FILES.csv` contains **4,269 records** and has columns `FullName`, `Length`, `LastWriteTime`, `Extension`. File size is 631,813 bytes; SHA-256 is `d03265c452b974f8320f1d12b66a58eb4096b8a98f0a943cdc6afb1ca6100ac5`.

Records **4–9** identify a project called **HomeRouterLab**. They describe two copies under Windows Recycle Bin. This establishes historical recorded paths and filenames; it does not prove the files still exist at those paths today.

| CSV data record | Recycle container | File | Recorded bytes | Recorded timestamp, unconverted |
|---:|---|---|---:|---|
| 4 | `$RCJP57B.1` | `HomeRouterLab\HomeRouterLab.psd1` | 968 | `06/04/48 07:21:21 م` |
| 5 | `$RCJP57B.1` | `HomeRouterLab\HomeRouterLab.psm1` | 8,516 | `06/04/48 07:21:21 م` |
| 6 | `$RCJP57B.1` | `HomeRouterLab\README.md` | 1,063 | `06/04/48 07:21:21 م` |
| 7 | `$RERTOLH.1` | `HomeRouterLab\HomeRouterLab.psd1` | 968 | `06/04/48 05:13:14 م` |
| 8 | `$RERTOLH.1` | `HomeRouterLab\HomeRouterLab.psm1` | 8,751 | `06/04/48 05:13:14 م` |
| 9 | `$RERTOLH.1` | `HomeRouterLab\README.md` | 1,152 | `06/04/48 05:13:14 م` |

The `.psd1` and `.psm1` extensions support describing the recorded project as a **PowerShell module**. The inventory does not establish a Python implementation. Full paths, including the user SID, remain in the supplied CSV; they are not repeated in this summary.

Known remote filesystem access in the parent session was restricted to `C:\Users\A` and `D:\`. The recorded `C:\$Recycle.Bin` paths fall outside that boundary, so I did not access or restore those files. Their contents remain UNKNOWN.

The other relevant custom filename in the CSV is `C:\Users\A\Desktop\tplinkwifi.net.crt` (1,220 bytes). This filename is consistent with prior TP-Link management-page use, but does not identify the hardware model, the current topology, or a successful TLS configuration. I did not open it.

## GitHub discovery

The GitHub connector returned accessible repositories owned by **Grar00t**, establishing read access to that account's selected repositories. Installed-repository searches for `HomeRouterLab`, `homelab`, and `gateway` returned no matching repositories. Code searches for `HomeRouterLab`, `HomeRouterLab.psm1`, `HomeRouterLab TP-Link`, and `TP-Link` returned no matches in the searched scopes. Search coverage depends on connector indexing and default branches; this is not proof that no historical copy exists.

A `router` repository search returned `Grar00t/allam-evidence-ledger`, which is not evidence that HomeRouterLab lives there. No unrelated contents were fetched from it.

Two existing repositories were read to disambiguate possible established projects:

### Grar00t/khz-cli

Source: https://github.com/Grar00t/khz-cli/blob/main/README.md

README blob SHA: `0eec2070fce8896bc739cdbc054c89063fd52ff1`.

The README describes a **Go CLI for command decisions and receipts**, not a home-router module. It records Git state, runs commands as argv without `sh -c` or `cmd /c`, and writes SHA-256-sealed JSON receipts. Its stated interface conventions are useful precedents for the new home CLI:

- Explicit text statuses: OK / WARN / FAIL / SKIP / INFO; color is not the only signal.
- Global `--json`, `--no-color`, `--color`, `--lang en|ar` flags.
- `NO_COLOR` and `TERM=dumb` disable ANSI; non-TTY stdout is uncolored unless forced.
- Receipts explicitly acknowledge partial side-effect observability and do not claim sandboxing or absence of network/filesystem changes.

These are observed README claims, not fresh execution tests of khz-cli. No source was copied or modified. This separate project should retain its identity.

### Grar00t/ribat

Source: https://github.com/Grar00t/ribat/blob/main/README.md

README blob SHA: `bcb26eb3842ad99cd7b9d44a8f3688571feb68a9`.

The README only describes a distributed computing fabric in C and assembly with zero dependencies. It provides no evidence linking it to HomeRouterLab; no further inspection was warranted.

## Google Drive discovery

Applied the Google Drive skill for metadata discovery. Targeted searches `HomeRouterLab`, `TP-Link`, `homelab`, `ipconfig`, `Huawei CLI`, and `HomeRouter` returned no matches.

The broader `router` search returned a Huawei partner handbook presentation and a generic data inventory workbook. Neither title established a prior home-router CLI or saved conversation. Their contents were not fetched because they were not needed to recover HomeRouterLab.

This subtask did not retrieve earlier conversations. The parent subsequently found a Personal Context tool and reported an October 7 conversation about the PowerShell PC → TP-Link → Huawei CLI and concepts `natdoctor fix/publish`. The parent holds that retrieval and its citation; it is separate from this subtask's CSV and connector evidence. The absence of matches in the Drive/GitHub searches above must not be described as absence of historical conversation evidence.

## Implications for the current build

1. Preserve the established name **HomeRouterLab** if the parent chooses it for a new version, but clearly label it a new implementation: the old source has not been recovered.
2. Do not infer the current Huawei or TP-Link model, LAN subnet, router mode, public WAN status, or CGNAT from filenames. These need the parent's live network observations and relevant device evidence.
3. Reuse the user's established CLI presentation conventions (text statuses, EN/AR option, JSON, NO_COLOR) as interface ideas, with new code and explicit scope.
4. All operations in this subtask were reads. No files on the user's Windows device were changed.
