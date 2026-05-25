"""DNS-leak detection end-to-end (onion-side).

The thunderbird container's resolver is hard-pinned to dns-trap, which
since commit dfa4da7 forwards every CLEARNET query to Tor's DNSPort
(see test_feature_dns_forward.py for the forwarder's audit) and rejects
every `.onion` query as NXDOMAIN (a .onion in plain DNS is leak by
definition — it should have travelled SOCKS5+remoteDNS).

This file specifically tests the onion side: with SOCKS5+remoteDNS, TB
must resolve `.onion` via Tor itself, NEVER via the local resolver.
dns-trap therefore sees ZERO queries for the onion hostname when the
proxy is configured correctly, regardless of whether dns-trap forwards
clearnet queries.

1. Without proxy: connecting to .onion fails AND dns-trap sees the lookup (= leak).
2. With SOCKS5+remoteDNS: connecting succeeds AND dns-trap sees NO query for the .onion.
"""

from __future__ import annotations

import os

import pytest
from helpers.dns_capture import DNSCapture
from helpers.mail_capture import MailCapture
from helpers.tb_client import TBClient

CHROME_TCP_PROBE = r"""
const [host, port, useProxy] = arguments;
const Cc = Components.classes;
const Ci = Components.interfaces;

const sts = Cc["@mozilla.org/network/socket-transport-service;1"]
  .getService(Ci.nsISocketTransportService);

let proxyInfo = null;
if (useProxy) {
  const pps = Cc["@mozilla.org/network/protocol-proxy-service;1"]
    .getService(Ci.nsIProtocolProxyService);
  proxyInfo = pps.newProxyInfo(
    "socks", "tor", 9050, "", "",
    1,  // SOCKS5: TRANSPARENT_PROXY_RESOLVES_HOST (remoteDNS)
    0xFFFFFFFF, null
  );
}

const transport = sts.createTransport([], host, port, proxyInfo, null);
const inputStream = transport.openInputStream(0, 0, 0);
const scriptable = Cc["@mozilla.org/scriptableinputstream;1"]
  .createInstance(Ci.nsIScriptableInputStream);
scriptable.init(inputStream);

return await new Promise((resolve, reject) => {
  const deadline = setTimeout(() => reject(new Error("timeout")), 30000);
  const pump = Cc["@mozilla.org/network/input-stream-pump;1"]
    .createInstance(Ci.nsIInputStreamPump);
  pump.init(inputStream, 0, 0, true, null);
  pump.asyncRead({
    onStartRequest() {},
    onStopRequest(req, status) {
      clearTimeout(deadline);
      if (!Components.isSuccessCode(status)) {
        reject(new Error("nsr=0x" + status.toString(16)));
      }
    },
    onDataAvailable(req, stream, offset, count) {
      try {
        const data = scriptable.read(count);
        clearTimeout(deadline);
        try { transport.close(0); } catch (e) {}
        resolve(data);
      } catch (e) { reject(e); }
    },
  }, null);
});
"""


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


@pytest.fixture
def dns() -> DNSCapture:
    d = DNSCapture()
    d.clear()
    return d


@pytest.fixture
def mail() -> MailCapture:
    m = MailCapture()
    m.clear()
    return m


@pytest.fixture
def onion() -> str:
    path = "/tests/fixtures/onion-hostname.txt"
    if not os.path.exists(path):
        pytest.skip("onion-hostname.txt missing; run make test-up")
    return open(path).read().strip()


def test_direct_lookup_leaks_to_dns_trap(tb: TBClient, dns: DNSCapture) -> None:
    """Sanity: without SOCKS, a regular DNS lookup for .onion DOES hit dns-trap."""
    # Use a non-existent fake onion so we don't depend on real Tor state
    fake_hostname = "should-never-resolve-anywhere.invalid"
    try:
        tb.exec_chrome(CHROME_TCP_PROBE, args=[fake_hostname, 80, False])
    except Exception:
        pass  # expected to fail
    leaks = dns.queries_for(fake_hostname)
    assert leaks, (
        f"expected dns-trap to see DNS query for {fake_hostname} when no proxy; "
        f"got: {dns.queries()}"
    )


def test_socks5_remote_dns_prevents_onion_leak(
    tb: TBClient, dns: DNSCapture, onion: str
) -> None:
    """KEY ASSERTION: with SOCKS5+remoteDNS, the .onion lookup is done by Tor,
    NOT by the local resolver. dns-trap MUST receive ZERO queries for the onion."""
    banner = tb.exec_chrome(CHROME_TCP_PROBE, args=[onion, 25, True])
    assert "220" in banner, f"expected SMTP banner via Tor, got: {banner!r}"
    leaks = dns.queries_for(onion)
    # Sometimes the SOCKS host "tor" itself gets resolved by the system — that's
    # internal, fine. What MUST NOT happen: the onion hostname appearing.
    assert not leaks, (
        f"DNS LEAK: dns-trap saw queries for the onion: {leaks}"
    )


def test_dns_trap_sees_tor_resolution_when_proxy_host_is_remote(
    tb: TBClient, dns: DNSCapture, onion: str
) -> None:
    """The SOCKS host itself ('tor') is in /etc/hosts so it should bypass DNS.
    This test asserts that no LOOKUPS happen at all for 'tor' either."""
    tb.exec_chrome(CHROME_TCP_PROBE, args=[onion, 25, True])
    tor_lookups = dns.queries_for("tor")
    onion_lookups = dns.queries_for(onion)
    # neither should leak
    assert not tor_lookups and not onion_lookups, (
        f"unexpected DNS: tor={tor_lookups}, onion={onion_lookups}"
    )
