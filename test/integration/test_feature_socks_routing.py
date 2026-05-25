"""End-to-end: with onionbird SOCKS prefs set, a TB-internal TCP connect to
an .onion address must succeed and the smtp-trap must receive a connection
NOT from the TB container's IP (proving Tor was traversed).

Without SOCKS config, the .onion is unresolvable -> connection fails.
"""

from __future__ import annotations

import os

import pytest
from helpers.mail_capture import MailCapture
from helpers.tb_client import TBClient


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


@pytest.fixture
def mail() -> MailCapture:
    m = MailCapture()
    m.clear()
    return m


@pytest.fixture
def onion() -> str:
    path = "/tests/fixtures/onion-hostname.txt"
    if not os.path.exists(path):
        pytest.skip("onion-hostname.txt not present; run `make test-up`")
    return open(path).read().strip()


CHROME_TCP_BANNER = r"""
const [host, port, useProxy] = arguments;
const Cc = Components.classes;
const Ci = Components.interfaces;

const sts = Cc["@mozilla.org/network/socket-transport-service;1"]
  .getService(Ci.nsISocketTransportService);

let proxyInfo = null;
if (useProxy) {
  const pps = Cc["@mozilla.org/network/protocol-proxy-service;1"]
    .getService(Ci.nsIProtocolProxyService);
  // Construct SOCKS5 proxy info that matches the prefs we set
  proxyInfo = pps.newProxyInfo(
    "socks",       // type
    "tor",         // host
    9050,          // port
    "",            // username
    "",            // password
    /* socks5_remote_dns_resolve */ 1,  // flags: TRANSPARENT_PROXY_RESOLVES_HOST
    0xFFFFFFFF,    // failoverTimeout
    null           // failoverProxy
  );
}

const transport = sts.createTransport(
  [], host, port, proxyInfo, null
);

const inputStream = transport.openInputStream(0, 0, 0);
const scriptable = Cc["@mozilla.org/scriptableinputstream;1"]
  .createInstance(Ci.nsIScriptableInputStream);
scriptable.init(inputStream);

return await new Promise((resolve, reject) => {
  const deadline = setTimeout(() => reject(new Error("timeout")), 60000);
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


def test_direct_to_onion_fails(tb: TBClient, onion: str) -> None:
    """Without proxy info, TB cannot reach the .onion."""
    with pytest.raises(Exception) as excinfo:
        tb.exec_chrome(CHROME_TCP_BANNER, args=[onion, 25, False])
    msg = str(excinfo.value).lower()
    assert any(t in msg for t in ("0x80", "timeout", "unknown host", "name")), (
        f"expected onion to be unreachable directly, got: {excinfo.value}"
    )


def test_socks5_enables_onion_smtp(tb: TBClient, onion: str, mail: MailCapture) -> None:
    """With SOCKS5+remote-DNS proxy info, TB reaches the onion via Tor.
    smtp-trap MUST receive a connection (peer != TB's IP -> via Tor)."""
    tb.set_pref("network.proxy.socks_remote_dns", True)
    mail.clear()
    banner = tb.exec_chrome(CHROME_TCP_BANNER, args=[onion, 25, True])
    assert banner is not None
    assert "220" in banner, f"expected SMTP 220 banner, got: {banner!r}"
