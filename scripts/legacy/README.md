# Legacy scripts

These are the one-off scripts used before v0.2.0. They are kept for provenance only and are superseded by `src/homerouterlab/`.

- `wan_probe.py` — first attempt; TR-064 only on `WANIPConnection`.
- `wan_fix.py` — added HTTP, Telnet, external layers; stopped on `CANDIDATES_FOUND` with a null IP.
- `wan_matrix.py` — port/path matrix; confirmed 49000 closed on both routers.

Do not import these. They are not tested and are not part of the package.