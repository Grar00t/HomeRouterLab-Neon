"""Huawei/Generic CLI probe over Telnet (read-only)."""
from __future__ import annotations

import ipaddress
import re
import socket
import time

from ..models import ProbeResult

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CREDENTIALS = (("root", "admin"), ("admin", "admin"), ("admin", ""), ("telecomadmin", "admintelecom"))
COMMANDS = ("display wan layer all", "display wan info", "show wan", "ifconfig wan")
SHARED = ipaddress.IPv4Network("100.64.0.0/10")


def is_public_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return False
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return False
    if addr in SHARED:
        return False
    return True


def _login_and_run(host: str, user: str, password: str, command: str, timeout: float) -> str:
    with socket.create_connection((host, 23), timeout=timeout) as sock:
        sock.settimeout(timeout)
        time.sleep(0.4)
        try:
            sock.recv(4096)
        except socket.timeout:
            pass
        sock.sendall(user.encode() + b"\n")
        time.sleep(0.3)
        sock.sendall(password.encode() + b"\n")
        time.sleep(0.6)
        sock.sendall(command.encode() + b"\n")
        time.sleep(1.2)
        chunks: list[bytes] = []
        while True:
            try:
                data = sock.recv(8192)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", "replace")


def probe(hosts: list[str], timeout: float = 3.0) -> ProbeResult:
    for host in hosts:
        try:
            with socket.create_connection((host, 23), timeout=timeout):
                pass
        except OSError:
            continue
        for user, password in CREDENTIALS:
            for command in COMMANDS:
                try:
                    out = _login_and_run(host, user, password, command, timeout)
                except Exception:
                    continue
                for ip in IPV4.findall(out):
                    if is_public_ipv4(ip):
                        return ProbeResult(
                            layer="telnet",
                            status="OBSERVED",
                            wan_ip=ip,
                            host=host,
                            evidence={"command": command},
                        )
    return ProbeResult(layer="telnet", status="NO_ACCESS", notes="telnet closed or credentials rejected")