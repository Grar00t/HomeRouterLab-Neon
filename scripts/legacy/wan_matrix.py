import json, socket, sys
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

HOSTS = ["192.168.0.1", "192.168.100.1"]
PORTS = [49000, 5000, 80]
URNS = [
    "urn:dslforum-org:service:WANIPConnection:1",
    "urn:dslforum-org:service:WANPPPConnection:1",
]
PATHS = ["/upnp/control/WANIPConnection1", "/upnp/control/WANPPPConnection1",
         "/upnp/control/WANIPConnection", "/upnp/control/WANPPPConnection"]

def probe_port(host, port):
    try:
        with socket.create_connection((host, port), timeout=2):
            return "OPEN"
    except Exception as e:
        return f"CLOSED:{type(e).__name__}"

def probe_soap(host, port, urn, path):
    if requests is None:
        return "NO_REQUESTS"
    body = ('<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
            '<s:Body><u:GetExternalIPAddress xmlns:u="' + urn + '"/></s:Body>'
            '</s:Envelope>')
    headers = {"SOAPAction": urn + "#GetExternalIPAddress",
               "Content-Type": 'text/xml; charset="utf-8"'}
    url = f"http://{host}:{port}{path}"
    try:
        r = requests.post(url, data=body.encode(), headers=headers, timeout=3)
        ip = r.headers.get("X-External-IP-Address") or r.headers.get("x-external-ip-address")
        if ip:
            return f"OK:{ip}"
        import re
        m = re.search(r"<NewExternalIPAddress>([^<]+)</NewExternalIPAddress>", r.text)
        if m:
            return f"OK:{m.group(1)}"
        return f"HTTP_{r.status_code}_NO_IP"
    except Exception as e:
        return f"ERR:{type(e).__name__}"

report = {"schema": "homerouterlab.wan-matrix/1", "hosts": {}}
for host in HOSTS:
    entry = {"ports": {}, "soap": []}
    for port in PORTS:
        entry["ports"][str(port)] = probe_port(host, port)
    for port in [49000, 5000]:
        for urn in URNS:
            for path in PATHS:
                r = probe_soap(host, port, urn, path)
                if r.startswith("OK:") or r.startswith("HTTP_"):
                    entry["soap"].append({"port": port, "urn": urn.split(":")[-2],
                                          "path": path, "result": r})
    report["hosts"][host] = entry

out = Path(r"D:\projects\HomeRouterLab-Neon-20261022\reports\wan-matrix-20261022.json")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps({"path": str(out), "summary": {h: {"ports": v["ports"],
      "soap_hits": len(v["soap"])} for h, v in report["hosts"].items()}},
      ensure_ascii=False))
