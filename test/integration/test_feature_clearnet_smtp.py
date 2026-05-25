"""Clearnet SMTP via the addon — does the 100% Tor guarantee hold?

The README states "DNS through Tor only — zero DNS queries reach the
local resolver during real Tor-routed sends". This is verified for
*onion* SMTP servers by test_feature_dns_leak.py. What was previously
untested: configuring an SMTP server with a **clearnet** hostname
(e.g. `smtp.gmail.com`) — does the resolution still go through Tor?

These tests trigger TB to resolve a clearnet hostname and assert
dns-trap saw the lookup with `disposition='forwarded'` (meaning it
went through Tor's DNSPort, not the system resolver directly).

Also exercises the safety check: a user who pastes a hostname into
`network.proxy.socks` (instead of a loopback IP) must NOT have TB
resolve that hostname via the system resolver before connecting —
that would itself leak the user's intent to use Tor.
"""

from __future__ import annotations

import secrets
import time

import pytest
from helpers.dns_capture import DNSCapture
from helpers.tb_client import TBClient

XPI = "/build/onionbird.xpi"

# Open a socket transport — this is the same pattern test_feature_dns_leak
# uses to force TB's resolver to attempt a lookup. With useProxy=False the
# resolution goes through TB's system resolver (which is dns-trap in the
# container). With useProxy=True we go through Tor's SOCKS5 remoteDNS.
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
return await new Promise((resolve) => {
  const deadline = setTimeout(() => resolve("timeout"), 6000);
  const pump = Cc["@mozilla.org/network/input-stream-pump;1"]
    .createInstance(Ci.nsIInputStreamPump);
  try {
    pump.init(inputStream, 0, 0, true, null);
    pump.asyncRead({
      onStartRequest() {},
      onStopRequest(req, status) {
        clearTimeout(deadline);
        try { transport.close(0); } catch (e) {}
        resolve("done:0x" + status.toString(16));
      },
      onDataAvailable() {
        clearTimeout(deadline);
        try { transport.close(0); } catch (e) {}
        resolve("data");
      },
    }, null);
  } catch (e) {
    clearTimeout(deadline);
    resolve("throw:" + String(e));
  }
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


def test_clearnet_lookup_routes_through_dns_trap(
    tb: TBClient, dns: DNSCapture
) -> None:
    """Trigger TB to resolve a clearnet hostname. dns-trap must see the
    query with disposition='forwarded' — meaning the resolution was
    handed to Tor's DNSPort, NOT answered by some system fallback
    resolver. This is the load-bearing claim for users who keep a
    clearnet mail provider (Gmail, Outlook, corporate Exchange)."""
    canary = f"clearnet-{secrets.token_hex(4)}.example.com"
    # No proxy — exercises the system-resolver path. The container's
    # /etc/resolv.conf points at dns-trap, so the request hits the
    # trap, which then forwards to Tor.
    tb.exec_chrome(CHROME_TCP_PROBE, args=[canary, 80, False])
    time.sleep(1.5)
    queries = dns.queries_for(canary)
    assert queries, (
        f"clearnet DNS lookup for {canary} did NOT hit dns-trap. "
        f"Either TB has DoH enabled (network.trr.mode must be 5) or "
        f"the container's /etc/resolv.conf is not pointed at dns-trap."
    )
    dispositions = {q["disposition"] for q in queries}
    assert "forwarded" in dispositions, (
        f"clearnet DNS for {canary} was NOT forwarded to Tor by the "
        f"trap; dispositions seen: {dispositions}. 100% Tor for "
        f"clearnet providers is broken."
    )


def test_addon_refuses_hostname_socks_proxy(tb: TBClient) -> None:
    """If a user configures `network.proxy.socks = "tor.example.org"`
    (a hostname instead of a loopback IP), the addon must refuse to
    use it — resolving the SOCKS host itself via the system resolver
    would leak the user's intent to use Tor.

    Either the addon falls back to loopback (auto-detection finds the
    container's 127.0.0.1:9050 / :9150) or it falls closed. Either
    way, after enableHardening the SOCKS host pref must NOT be the
    hostname the user supplied."""
    tb.set_pref("network.proxy.socks", "tor.example.org")
    tb.set_pref("network.proxy.socks_port", 9050)
    tb.install_addon(XPI, temporary=True)
    # T-081: poll for the SOCKS-host pref to change instead of a
    # fixed 4-second sleep. The addon's enableHardening normally
    # completes well under 1 s; the fixed 4 s wait was 3 s of
    # waste on a fast host and a flake risk on a slow CI box.
    deadline = time.time() + 30
    while time.time() < deadline:
        if tb.get_pref("network.proxy.socks") != "tor.example.org":
            break
        time.sleep(0.25)

    actual = tb.get_pref("network.proxy.socks")
    assert actual != "tor.example.org", (
        f"addon left a hostname-based SOCKS proxy in place "
        f"({actual!r}); TB would resolve `tor.example.org` via system "
        f"DNS before connecting, leaking the user's intent to use Tor"
    )
    assert (
        actual == "localhost"
        or actual == "::1"
        or (isinstance(actual, str) and actual.startswith("127."))
    ), (
        f"SOCKS host after hardening is {actual!r} — expected a "
        f"loopback address (the addon's isLoopbackSocksHost gate)."
    )
