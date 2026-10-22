from __future__ import annotations
import json, socket, sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

HOSTS = ["192.168.0.1", "192.168.100.1"]
PORT = 49000
URN = "urn:dslforum-org:service:WANIPConnection:1"
TIMEOUT = 3
OUT_DIR = Path(r"D:\projects\HomeRouterLab-Neon-20261022\reports")

def utc():
    return datetime.now(timezone.utc).isoformat()

def so_xml(host):
    body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
        '<s:Body><u:GetExternalIPAddress xmlns:u="' + URN + '"/></s:Body>'
        '</s:Envelope>'
    )
    headers = {
        "SOAPAction": URN + "#GetExternalIPAddress",
        "Content-Type": 'text/xml; charset="utf-8"',
    }
    r = requests.post(f"http://{host}:{PORT}/upnp/control/WANIPConnection1",
                      data=body.encode("utf-8"), headers=headers, timeout=TIMEOUT)
    r.raise_for_status()
    ip = r.headers.get("X-External-IP-Address") or r.headers.get("x-external-ip-address")
    if ip:
        return ip
    import re
    m = re.search(r"<NewExternalIPAddress>([^<]+)</NewExternalIPAddress>", r.text)
    return m.group(1) if m else None

def try_tr064():
    if requests is None:
        return None
    for host in HOSTS:
        try:
            with socket.create_connection((host, PORT), timeout=TIMEOUT):
                pass
            ip = so_xml(host)
            if ip:
                return {"method": "TR-064", "host": host, "wan_ip": ip, "status": "OBSERVED"}
        except Exception:
            continue
    return None

def try_cli():
    try:
        from netmiko import ConnectHandler
    except ImportError:
        return None
    for host in HOSTS:
        try:
            c = ConnectHandler(device_type="huawei", host=host,
                               username="admin", password="", timeout=5)
            out = c.send_command("display wan layer all", use_textfsm=True)
            c.disconnect()
            if isinstance(out, list):
                for row in out:
                    for k, v in row.items():
                        if "ip" in k.lower() and v and v not in ("-", ""):
                            return {"method": "CLI-TextFSM", "host": host,
                                    "wan_ip": v, "status": "OBSERVED"}
        except Exception:
            continue
    return None

def main():
    started = utc()
    result = try_tr064() or try_cli() or {
        "method": "NONE", "status": "UNKNOWN", "wan_ip": "UNKNOWN",
        "note": "TR-064 not reachable and Netmiko/ntc-templates unavailable or failed. No guess made."
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = started.replace(":", "").replace(".", "").replace("-", "")[:15]
    out = OUT_DIR / f"wan-truth-{stamp}.json"
    payload = {
        "schema": "homerouterlab.wan-truth/1",
        "started_utc": started,
        "finished_utc": utc(),
        "result": result,
        "notes": "Read-only probe. TR-064 SOAP on 49000; Netmiko+TextFSM fallback. No config change."
    }
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"path": str(out), "status": result["status"],
                      "wan_ip": result["wan_ip"], "method": result["method"]},
                     ensure_ascii=False))

if __name__ == "__main__":
    main()
