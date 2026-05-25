"""Tor test mode probe semantics.

The Options-page button is wired by static UI tests. This container test proves
the underlying probe idea works in the local stack: Tor's SOCKS5 RESOLVE command
can be used against `tor:9050` without sending mail, without using Thunderbird's
system resolver for the target host, and without mutating prefs.
"""

from __future__ import annotations

import re

import pytest
from helpers.tb_client import TBClient


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


TOR_READINESS_PROBE_JS = r"""
const [socksHost, socksPort, host] = arguments;
const Cc = Components.classes;
const Ci = Components.interfaces;

function randomHex(byteCount) {
  const buf = new Uint8Array(byteCount);
  globalThis.crypto.getRandomValues(buf);
  let s = "";
  for (const b of buf) s += b.toString(16).padStart(2, "0");
  return s;
}

function waitBytes(binIn, n) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 12000;
    const tm = Cc["@mozilla.org/thread-manager;1"].getService(Ci.nsIThreadManager);
    const tick = () => {
      try {
        if (binIn.available() >= n) {
          resolve(binIn.readByteArray(n));
          return;
        }
      } catch (e) {
        reject(e);
        return;
      }
      if (Date.now() > deadline) {
        reject(new Error("read timeout"));
        return;
      }
      tm.dispatchToMainThread({ run: tick });
    };
    tm.dispatchToMainThread({ run: tick });
  });
}

async function torSocksResolve(socksHost, socksPort, host) {
  const sts = Cc["@mozilla.org/network/socket-transport-service;1"]
    .getService(Ci.nsISocketTransportService);
  const transport = sts.createTransport([], socksHost, socksPort, null, null);
  transport.setTimeout(Ci.nsISocketTransport.TIMEOUT_CONNECT, 10);
  transport.setTimeout(Ci.nsISocketTransport.TIMEOUT_READ_WRITE, 10);
  const outStream = transport.openOutputStream(0, 0, 0);
  const inStream = transport.openInputStream(0, 0, 0);
  const binOut = Cc["@mozilla.org/binaryoutputstream;1"]
    .createInstance(Ci.nsIBinaryOutputStream);
  binOut.setOutputStream(outStream);
  const binIn = Cc["@mozilla.org/binaryinputstream;1"]
    .createInstance(Ci.nsIBinaryInputStream);
  binIn.setInputStream(inStream);

  try {
    const token = randomHex(16);
    binOut.writeByteArray([0x05, 0x01, 0x02]);
    const greet = await waitBytes(binIn, 2);
    if (greet[0] !== 0x05 || greet[1] !== 0x02) {
      throw new Error(`socks5 user/pass auth refused: ${greet}`);
    }
    const enc = new TextEncoder();
    const u = enc.encode(token);
    const p = enc.encode(token);
    binOut.writeByteArray([0x01, u.length, ...u, p.length, ...p]);
    const sub = await waitBytes(binIn, 2);
    if (sub[0] !== 0x01 || sub[1] !== 0x00) {
      throw new Error(`socks5 user/pass sub-negotiation failed: ${sub}`);
    }

    const dom = enc.encode(host);
    binOut.writeByteArray([0x05, 0xF0, 0x00, 0x03, dom.length, ...dom, 0x00, 0x00]);
    const hdr = await waitBytes(binIn, 4);
    if (hdr[0] !== 0x05) throw new Error("socks5 bad version in response");
    if (hdr[1] !== 0x00) throw new Error(`socks5 resolve failed rep=${hdr[1]}`);

    let ip;
    if (hdr[3] === 0x01) {
      const v4 = await waitBytes(binIn, 4);
      ip = `${v4[0]}.${v4[1]}.${v4[2]}.${v4[3]}`;
    } else if (hdr[3] === 0x04) {
      const v6 = await waitBytes(binIn, 16);
      const groups = [];
      for (let i = 0; i < 16; i += 2) {
        groups.push(((v6[i] << 8) | v6[i + 1]).toString(16));
      }
      ip = groups.join(":");
    } else {
      throw new Error(`unexpected SOCKS atyp=${hdr[3]}`);
    }
    await waitBytes(binIn, 2);
    return { ok: true, socksHost, socksPort, host, ip };
  } finally {
    try { transport.close(0); } catch (e) {}
  }
}

return await torSocksResolve(socksHost, socksPort, host);
"""


def test_container_tor_supports_anonymous_socks5_resolve_without_pref_mutation(
    tb: TBClient,
) -> None:
    tb.set_pref("network.proxy.socks", "tor")
    tb.set_pref("network.proxy.socks_port", 9050)
    before = {
        "socks": tb.get_pref("network.proxy.socks"),
        "port": tb.get_pref("network.proxy.socks_port"),
        "remote_dns": tb.get_pref("network.proxy.socks_remote_dns"),
    }

    result = tb.exec_chrome(
        TOR_READINESS_PROBE_JS,
        args=["tor", 9050, "example.com"],
    )

    after = {
        "socks": tb.get_pref("network.proxy.socks"),
        "port": tb.get_pref("network.proxy.socks_port"),
        "remote_dns": tb.get_pref("network.proxy.socks_remote_dns"),
    }

    assert result["ok"] is True
    assert result["socksHost"] == "tor"
    assert result["socksPort"] == 9050
    assert result["host"] == "example.com"
    assert re.match(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-f:]+$", result["ip"], re.I)
    assert before == after
