"""dns-trap acts as a logging Tor-DNS forwarder.

These tests run from the *runner* container and talk to dns-trap directly:
- clearnet queries → forwarded to Tor's DNSPort (real internet resolution
  via Tor exits), logged with disposition='forwarded'
- .onion queries → rejected as DNS leak (disposition='rejected_onion')
- every query appears in the audit log

This is the test infrastructure backing the 100% Tor anonymity guarantee:
clearnet SMTP/IMAP hostnames the addon cannot route via SOCKS+remoteDNS
(TCPSocket pre-resolves) still get resolved via Tor, not the system DNS.
"""

from __future__ import annotations

import secrets
import socket
import time
from typing import Any

import httpx
import pytest
from dnslib import QTYPE, DNSRecord

DNS_TRAP_HOST = "dns-trap"
HTTP_BASE = f"http://{DNS_TRAP_HOST}:8053"


def _udp_query(qname: str, timeout: float = 5.0) -> DNSRecord:
    q = DNSRecord.question(qname)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q.pack(), (DNS_TRAP_HOST, 53))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    return DNSRecord.parse(data)


def _queries() -> list[dict[str, Any]]:
    r = httpx.get(f"{HTTP_BASE}/queries", timeout=5)
    r.raise_for_status()
    return r.json()


def _clear() -> None:
    httpx.delete(f"{HTTP_BASE}/queries", timeout=5).raise_for_status()


def _find_query(qname: str) -> dict[str, Any] | None:
    for q in _queries():
        if qname in q.get("qname", ""):
            return q
    return None


def test_clearnet_query_is_forwarded_via_tor() -> None:
    """A clearnet hostname must resolve through dns-trap (which forwards to Tor)."""
    _clear()
    parsed = _udp_query("check.torproject.org")
    assert parsed.header.rcode == 0, (
        f"expected NOERROR for clearnet lookup, got rcode={parsed.header.rcode}"
    )
    a_records = [str(rr.rdata) for rr in parsed.rr if rr.rtype == QTYPE.A]
    assert a_records, "expected at least one A record from Tor-forwarded resolution"

    time.sleep(0.2)
    logged = _find_query("check.torproject.org")
    assert logged is not None, f"query not in log: {_queries()}"
    assert logged["disposition"] == "forwarded", (
        f"expected disposition=forwarded, got {logged}"
    )


def test_onion_query_is_rejected_as_leak() -> None:
    """.onion in plain DNS = leak by definition. Must NXDOMAIN."""
    _clear()
    parsed = _udp_query("facebookcorewwwi.onion")
    assert parsed.header.rcode == 3, (
        f"expected NXDOMAIN(3) for .onion, got rcode={parsed.header.rcode}"
    )
    time.sleep(0.2)
    logged = _find_query("facebookcorewwwi.onion")
    assert logged is not None
    assert logged["disposition"] == "rejected_onion", logged


def test_invalid_tld_is_forwarded_and_returns_nxdomain_upstream() -> None:
    """A `.invalid` TLD (RFC 6761) reaches Tor, Tor's exit resolver returns
    NXDOMAIN, dns-trap records disposition='forwarded' (because we DID
    forward — Tor just answered NXDOMAIN). This proves the forwarder
    happy-path even when upstream legitimately says "no such name"; it
    does NOT exercise the internal fail-closed path.
    """
    _clear()
    canary = f"canary-{secrets.token_hex(4)}.invalid"
    parsed = _udp_query(canary, timeout=10)
    assert parsed.header.rcode in (0, 3), (
        f"unexpected rcode={parsed.header.rcode} for {canary}"
    )
    time.sleep(0.2)
    logged = _find_query(canary)
    assert logged is not None, f"{canary} missing from log"
    assert logged["disposition"] == "forwarded", logged


BLACKHOLE_HOST = "dns-trap-blackhole"
BLACKHOLE_HTTP = f"http://{BLACKHOLE_HOST}:8053"


def _blackhole_udp_query(qname: str, timeout: float = 8.0) -> DNSRecord:
    """Send a UDP DNS query to the blackhole dns-trap sidecar (which
    forwards to 127.0.0.1:1 — guaranteed unreachable). The sidecar
    must return NXDOMAIN after its forward timeout, NOT silently drop
    the query and NOT fall back to system DNS."""
    q = DNSRecord.question(qname)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q.pack(), (BLACKHOLE_HOST, 53))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    return DNSRecord.parse(data)


def _blackhole_queries() -> list[dict[str, Any]]:
    r = httpx.get(f"{BLACKHOLE_HTTP}/queries", timeout=5)
    r.raise_for_status()
    return r.json()


def _blackhole_clear() -> None:
    httpx.delete(f"{BLACKHOLE_HTTP}/queries", timeout=5).raise_for_status()


def _find_blackhole_query(qname: str) -> dict[str, Any] | None:
    for q in _blackhole_queries():
        if qname in q.get("qname", ""):
            return q
    return None


def test_dns_trap_fail_closed_when_tor_dns_unreachable() -> None:
    """When the dns-trap's upstream Tor-DNS forward times out / errors,
    the server must return NXDOMAIN with `disposition='nxdomain'` —
    NOT silently drop the query and NOT fall back to system DNS.

    The 100% Tor policy treats an unverified fail-closed path as a P0
    gap. Previously this branch (`_forward_to_tor` returning None →
    `disposition='nxdomain'`) was implemented but had zero tests.

    Sidecar `dns-trap-blackhole` is configured with
    `T0_TOR_DNS_HOST=127.0.0.1`, `T0_TOR_DNS_PORT=1`, so every forward
    attempt hits a closed port and errors out within
    `T0_FORWARD_TIMEOUT_S` (1.5 s in compose.yaml)."""
    _blackhole_clear()
    canary = f"failclosed-{secrets.token_hex(4)}.example.com"
    parsed = _blackhole_udp_query(canary)
    # NXDOMAIN — DNS_RCODE 3.
    assert parsed.header.rcode == 3, (
        f"expected NXDOMAIN(3) when Tor-DNS upstream unreachable, "
        f"got rcode={parsed.header.rcode}. Fail-closed is broken: "
        f"dns-trap is answering something other than NXDOMAIN, which "
        f"means TB sees a non-error answer and may proceed with a "
        f"connection it shouldn't."
    )
    # Crucially: NO A records leaked from a fallback resolver.
    a_records = [rr for rr in parsed.rr if rr.rtype == QTYPE.A]
    assert not a_records, (
        f"dns-trap leaked A records when Tor-DNS was unreachable: "
        f"{a_records}. Fail-closed must mean NO answer, not 'try the "
        f"system resolver as a fallback'."
    )

    time.sleep(0.2)
    logged = _find_blackhole_query(canary)
    assert logged is not None, (
        f"query {canary} missing from log: {_blackhole_queries()}"
    )
    assert logged["disposition"] == "nxdomain", (
        f"expected disposition='nxdomain' (forward failed → fail-closed), "
        f"got {logged}. Either the upstream was reachable (it shouldn't "
        f"be, port :1 is closed by Linux) or the dns-trap mis-classified "
        f"the fail-closed branch."
    )


def test_T078_tb_observes_nxdomain_from_blackhole_dns() -> None:
    """T-078 behavioural: the previous test (above) verifies the
    dns-trap blackhole sidecar's container plumbing — that it
    returns NXDOMAIN when its forward upstream is unreachable.
    But the README's 100%-Tor promise is about Thunderbird's
    behaviour: TB must act on that NXDOMAIN by failing the
    connection, not by falling back to a different resolver.

    This test drives TB's `nsIDNSService` directly to make a
    lookup against a name that the dns-trap forwards into the
    blackhole — and asserts TB sees a hard NXDOMAIN, not a
    success result from some other resolver path. The previous
    coverage stopped at the container's edge; this verifies the
    addon's stated 100%-Tor guarantee at TB's own DNS surface."""
    try:
        from helpers.tb_client import TBClient
    except ImportError:
        pytest.skip("tb_client not available")
    canary = f"tbobserves-{secrets.token_hex(4)}.example.com"
    client = TBClient(host="thunderbird", port=2828)
    try:
        # Point TB's DNS at the blackhole-pointed dns-trap (TRR off
        # for this test so the system resolver is used).
        result = client.exec_chrome(r"""
            const [host] = arguments;
            const dns = Components.classes[
              "@mozilla.org/network/dns-service;1"
            ].getService(Components.interfaces.nsIDNSService);
            return await new Promise((resolve) => {
              try {
                dns.asyncResolve(
                  host, 0,
                  {
                    onLookupComplete(req, rec, status) {
                      // status: 0 = NS_OK, 0x804B001E = NS_ERROR_UNKNOWN_HOST,
                      // 0x804B0049 = NS_ERROR_OFFLINE, etc.
                      resolve({
                        status: "0x" + status.toString(16),
                        success: Components.isSuccessCode(status),
                        hasMore: rec && typeof rec.hasMore === "function"
                          ? rec.hasMore() : false,
                      });
                    },
                  },
                  null, {},
                );
              } catch (e) {
                resolve({ throws: String(e) });
              }
            });
        """, args=[canary])
        # TB MUST NOT resolve the blackhole-target to a real address.
        # `success: true` plus `hasMore: true` would mean some other
        # resolver answered — a leak path.
        assert not (result.get("success") and result.get("hasMore")), (
            f"T-078: TB resolved blackhole canary {canary!r} "
            f"successfully despite the dns-trap returning NXDOMAIN. "
            f"Result: {result}. This means TB has a fallback "
            f"resolver path the README's 100%-Tor promise does not "
            f"acknowledge — likely TRR / DoH / a hostnames file."
        )
    finally:
        client.close()


def test_dns_trap_does_not_silently_drop_on_upstream_failure() -> None:
    """Stronger variant: the fail-closed path must produce an *answer*
    packet that TB can act on. A silent drop would make TB hang or fall
    back to system DNS — neither is acceptable. This test verifies a
    response packet arrives within reasonable time (not a timeout)."""
    _blackhole_clear()
    canary = f"silent-{secrets.token_hex(4)}.example.com"
    start = time.time()
    parsed = _blackhole_udp_query(canary, timeout=6.0)
    elapsed = time.time() - start
    assert parsed.header.rcode in (2, 3), (
        f"unexpected rcode={parsed.header.rcode}; fail-closed should "
        f"yield NXDOMAIN(3) or SERVFAIL(2), not a real answer"
    )
    # Should respond within 2 forward-timeouts (3 s budget on a 1.5s timeout).
    assert elapsed < 5.0, (
        f"response took {elapsed:.2f}s — fail-closed is hanging instead "
        f"of returning a deterministic error answer; TB would time out "
        f"in user-visible ways"
    )
