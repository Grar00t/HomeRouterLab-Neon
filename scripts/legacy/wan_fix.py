from __future__ import annotations
import json, socket, re, sys, time
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

try:
    import upnpy
except ImportError:
    upnpy = None

HOSTS = ["192.168.0.1", "192.168.100.1"]
OUT_DIR = Path(r"D:\projects\HomeRouterLab-Neon-20261022\reports")

def utc():
    return datetime.now(timezone.utc).isoformat()

# ---------- Layer 1: upnpy ----------
def layer_upnpy():
    if upnpy is None:
        return {"layer": "upnpy", "status": "SKIP", "reason": "not installed"}
    try:
        upnp = upnpy.UPnP()
        devices = upnp.discover()
        if not devices:
            return {"layer": "upnpy", "status": "NO_IGD"}
        dev = upnp.get_igd()
        for sid in ("WANPPPConnection.1", "WANIPConnection.1",
                    "WANPPPConnection", "WANIPConnection"):
            try:
                svc = dev[sid]
                res = svc.GetExternalIPAddress()
                ip = res.get("NewExternalIPAddress")
                if ip and ip != "0.0.0.0":
                    return {"layer": "upnpy", "status": "OBSERVED",
                            "service": sid, "wan_ip": ip}
            except Exception:
                continue
        return {"layer": "upnpy", "status": "NO_WAN_SERVICE"}
    except Exception as e:
        return {"layer": "upnpy", "status": f"ERR:{type(e).__name__}", "error": str(e)}

# ---------- Layer 2: HTTP status pages ----------
PATHS = ["/", "/status", "/wan", "/cgi-bin/luci", "/html/status.asp",
         "/userRpm/StatusRpm.htm", "/cgi-bin/webproc"]
IP_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
def layer_http():
    if requests is None:
        return {"layer": "http", "status": "SKIP", "reason": "no requests"}
    hits = []
    for host in HOSTS:
        for path in PATHS:
            try:
                r = requests.get(f"http://{host}{path}", timeout=3, allow_redirects=True)
                if r.status_code == 200 and len(r.text) > 200:
                    # مرشحو IPv4 غير الخاص
                    cands = [ip for ip in IP_RE.findall(r.text)
                             if not ip.startswith(("127.", "192.168.", "10.", "172.", "0.", "255."))]
                    if cands:
                        hits.append({"host": host, "path": path,
                                     "status": r.status_code, "candidates": cands[:5]})
            except Exception:
                continue
    if hits:
        return {"layer": "http", "status": "CANDIDATES_FOUND", "hits": hits}
    return {"layer": "http", "status": "NO_PUBLIC_IP_IN_PAGES"}

# ---------- Layer 3: Telnet (Huawei) ----------
def layer_telnet():
    try:
        import telnetlib
    except ImportError:
        return {"layer": "telnet", "status": "SKIP", "reason": "telnetlib removed (py3.13+)"}
    for host in HOSTS:
        for user, pwd in (("root", "admin"), ("admin", "admin"), ("admin", "")):
            try:
                tn = telnetlib.Telnet(host, 23, timeout=3)
                tn.read_until(b"login:", timeout=2)
                tn.write(user.encode() + b"\n")
                tn.read_until(b"Password:", timeout=2)
                tn.write(pwd.encode() + b"\n")
                tn.write(b"display wan layer all\n")
                time.sleep(1.5)
                out = tn.read_very_eager().decode("utf-8", "replace")
                tn.close()
                ips = [ip for ip in IP_RE.findall(out)
                       if not ip.startswith(("127.", "192.168.", "10.", "172.", "0.", "255."))]
                if ips:
                    return {"layer": "telnet", "status": "OBSERVED",
                            "host": host, "wan_ip": ips[0]}
            except Exception:
                continue
    return {"layer": "telnet", "status": "NO_ACCESS"}

# ---------- Layer 4: external API ----------
def layer_external():
    if requests is None:
        return {"layer": "external", "status": "SKIP"}
    try:
        r = requests.get("https://api.ipify.org?format=json", timeout=5)
        return {"layer": "external", "status": "OBSERVED",
                "public_ip": r.json().get("ip", "UNKNOWN")}
    except Exception as e:
        return {"layer": "external", "status": f"ERR:{type(e).__name__}"}

def main():
    started = utc()
    trace = []
    result = None
    for fn in (layer_upnpy, layer_http, layer_telnet, layer_external):
        r = fn()
        trace.append(r)
        if r.get("status") in ("OBSERVED", "CANDIDATES_FOUND"):
            result = r
            break

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = started.replace(":", "").replace(".", "").replace("-", "")[:15]
    out = OUT_DIR / f"wan-fix-{stamp}.json"
    payload = {
        "schema": "homerouterlab.wan-fix/1",
        "started_utc": started,
        "finished_utc": utc(),
        "final": result or {"layer": "none", "status": "UNKNOWN"},
        "trace": trace,
        "notes": "Read-only multi-layer probe. No configuration change."
    }
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"path": str(out),
                      "final_layer": (result or {}).get("layer"),
                      "status": (result or {}).get("status"),
                      "wan_ip": (result or {}).get("wan_ip") or (result or {}).get("public_ip")},
                     ensure_ascii=False))

if __name__ == "__main__":
    main()
