"""Verify the test infrastructure itself: all containers up,
onion service generated, smtp-trap reachable via Tor onion."""

from __future__ import annotations

import socket

import httpx
import pytest
import socks  # PySocks


def test_smtp_trap_healthz(http: httpx.Client) -> None:
    r = http.get("http://smtp-trap:8025/healthz")
    assert r.status_code == 200
    assert r.text == "ok"


def test_dns_trap_healthz(http: httpx.Client) -> None:
    r = http.get("http://dns-trap:8053/healthz")
    assert r.status_code == 200


def test_tor_socks_port_open() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(("tor", 9050))
    s.close()


def test_smtp_reachable_via_tor_onion(
    onion_hostname: str,
    clear_traps: None,
) -> None:
    """Connect to smtp-trap through Tor using its onion address."""
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, "tor", 9050, rdns=True)
    s.settimeout(120)
    s.connect((onion_hostname, 25))
    banner = s.recv(1024)
    assert b"220" in banner, f"expected SMTP 220 banner, got {banner!r}"
    s.sendall(b"QUIT\r\n")
    s.close()


def test_onion_not_resolvable_without_tor(onion_hostname: str) -> None:
    """The onion address must NOT be resolvable without Tor (DNS leak guard)."""
    with pytest.raises((socket.gaierror, OSError)):
        socket.getaddrinfo(onion_hostname, 25)
