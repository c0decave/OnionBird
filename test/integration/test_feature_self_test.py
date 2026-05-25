"""Stream-isolated 3-lookup canary: SOCKS5-RESOLVE × N circuits + system.

The canary now issues N (default 3) SOCKS5 RESOLVE queries with distinct
isolation tokens, forcing Tor to use independent circuits and exits, and
builds the union of returned IPs. The system / Necko resolver is queried
once. A leak is flagged only when system_ip is a non-private public IP
AND not in the Tor set — eliminating the CDN-round-robin false positive
where a single Tor circuit's view was treated as the only "true" answer.

Tests:
1. End-to-end: the JS path returns a tor_ips array with >=1 entry.
2. Leak decision: Python-mirrored logic with synthetic inputs covers
   all branches (leak / no-leak / private / inconclusive).
3. Circuit isolation actually works: with 3 isolation tokens, the
   resolver behind Tor returns AT LEAST ONE result (does not all-fail).
"""

from __future__ import annotations

import re

import pytest
from helpers.tb_client import TBClient

MAX_PTR_CONFIRMATIONS = 8
CANARY_HOST = "check.torproject.org"


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


# Inline canary harness: 3 stream-isolated SOCKS5 RESOLVE queries + 1
# system resolve. The Python unit tests below mirror the verdict logic; this
# JS block proves the container stack supports the same primitive operations.
SELF_TEST_JS = r"""
const [host, socksHost, socksPort, tries] = arguments;
const Cc = Components.classes;
const Ci = Components.interfaces;

function waitBytes(binIn, n) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 12000;
    const tm = Cc["@mozilla.org/thread-manager;1"].getService(Ci.nsIThreadManager);
    const tick = () => {
      try {
        if (binIn.available() >= n) { resolve(binIn.readByteArray(n)); return; }
      } catch (e) { reject(e); return; }
      if (Date.now() > deadline) { reject(new Error("read timeout")); return; }
      tm.dispatchToMainThread({ run: tick });
    };
    tm.dispatchToMainThread({ run: tick });
  });
}

function canonicalizeIp(ip) {
  if (!ip || ip.indexOf(":") === -1) return ip;
  let parts;
  if (ip.indexOf("::") !== -1) {
    const segments = ip.split("::");
    if (segments.length !== 2) return ip;
    const [head, tail] = segments;
    const headG = head ? head.split(":") : [];
    const tailG = tail ? tail.split(":") : [];
    const missing = 8 - headG.length - tailG.length;
    if (missing < 0) return ip;
    parts = headG.concat(Array(missing).fill("0"), tailG);
  } else {
    parts = ip.split(":");
  }
  parts = parts.map(g => parseInt(g, 16).toString(16));
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === "0") {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else {
      curStart = -1; curLen = 0;
    }
  }
  if (bestLen >= 2) {
    const left = parts.slice(0, bestStart).join(":");
    const right = parts.slice(bestStart + bestLen).join(":");
    return `${left}::${right}`;
  }
  return parts.join(":");
}

async function socks5Resolve(socksHost, socksPort, host, isolationToken) {
  const sts = Cc["@mozilla.org/network/socket-transport-service;1"]
    .getService(Ci.nsISocketTransportService);
  const transport = sts.createTransport([], socksHost, socksPort, null, null);
  transport.setTimeout(Ci.nsISocketTransport.TIMEOUT_CONNECT, 10);
  transport.setTimeout(Ci.nsISocketTransport.TIMEOUT_READ_WRITE, 10);
  const outStream = transport.openOutputStream(0, 0, 0);
  const inStream  = transport.openInputStream(0, 0, 0);
  const binOut = Cc["@mozilla.org/binaryoutputstream;1"].createInstance(Ci.nsIBinaryOutputStream);
  binOut.setOutputStream(outStream);
  const binIn = Cc["@mozilla.org/binaryinputstream;1"].createInstance(Ci.nsIBinaryInputStream);
  binIn.setInputStream(inStream);
  try {
    if (isolationToken) {
      binOut.writeByteArray([0x05, 0x01, 0x02]);
      const greet = await waitBytes(binIn, 2);
      if (greet[0] !== 5 || greet[1] !== 2) throw new Error("auth refused " + greet[1]);
      const enc = new TextEncoder();
      const u = enc.encode(isolationToken);
      const p = enc.encode(isolationToken);
      const sr = [0x01, u.length];
      for (const b of u) sr.push(b);
      sr.push(p.length);
      for (const b of p) sr.push(b);
      binOut.writeByteArray(sr);
      const sresp = await waitBytes(binIn, 2);
      if (sresp[0] !== 1 || sresp[1] !== 0) throw new Error("subneg " + sresp);
    } else {
      binOut.writeByteArray([0x05, 0x01, 0x00]);
      const g = await waitBytes(binIn, 2);
      if (g[0] !== 5 || g[1] !== 0) throw new Error("greet");
    }
    const enc = new TextEncoder();
    const dom = enc.encode(host);
    const req = [0x05, 0xF0, 0x00, 0x03, dom.length];
    for (const b of dom) req.push(b);
    req.push(0, 0);
    binOut.writeByteArray(req);
    const hdr = await waitBytes(binIn, 4);
    if (hdr[0] !== 5) throw new Error("bad version");
    if (hdr[1] !== 0) throw new Error("rep=" + hdr[1]);
    const atyp = hdr[3];
    let addr;
    if (atyp === 1) {
      const v = await waitBytes(binIn, 4);
      addr = `${v[0]}.${v[1]}.${v[2]}.${v[3]}`;
    } else if (atyp === 4) {
      const v = await waitBytes(binIn, 16);
      const groups = [];
      for (let i = 0; i < 16; i += 2) {
        groups.push(((v[i] << 8) | v[i + 1]).toString(16));
      }
      addr = canonicalizeIp(groups.join(":"));
    } else if (atyp === 3) {
      const len = (await waitBytes(binIn, 1))[0];
      const name = await waitBytes(binIn, len);
      addr = String.fromCharCode(...name);
    } else {
      throw new Error("atyp=" + atyp);
    }
    await waitBytes(binIn, 2);
    return addr;
  } finally {
    try { transport.close(0); } catch (e) {}
  }
}

async function systemResolve(host) {
  const dns = Cc["@mozilla.org/network/dns-service;1"].getService(Ci.nsIDNSService);
  return await new Promise((resolve, reject) => {
    const listener = {
      QueryInterface: ChromeUtils.generateQI(["nsIDNSListener"]),
      onLookupComplete(_r, record, status) {
        if (!Components.isSuccessCode(status)) {
          reject(new Error("dns 0x" + status.toString(16))); return;
        }
        try {
          record.QueryInterface(Ci.nsIDNSAddrRecord);
          resolve(record.getNextAddrAsString());
        } catch (e) { reject(e); }
      },
    };
    const tm = Cc["@mozilla.org/thread-manager;1"].getService(Ci.nsIThreadManager);
    dns.asyncResolve(
      host, Ci.nsIDNSService.RESOLVE_TYPE_DEFAULT, 0, null, listener, tm.mainThread, {}
    );
  });
}

async function socks5ResolvePtr(socksHost, socksPort, ipv4, isolationToken) {
  const sts = Cc["@mozilla.org/network/socket-transport-service;1"]
    .getService(Ci.nsISocketTransportService);
  const transport = sts.createTransport([], socksHost, socksPort, null, null);
  transport.setTimeout(Ci.nsISocketTransport.TIMEOUT_CONNECT, 10);
  transport.setTimeout(Ci.nsISocketTransport.TIMEOUT_READ_WRITE, 10);
  const outStream = transport.openOutputStream(0, 0, 0);
  const inStream  = transport.openInputStream(0, 0, 0);
  const binOut = Cc["@mozilla.org/binaryoutputstream;1"].createInstance(Ci.nsIBinaryOutputStream);
  binOut.setOutputStream(outStream);
  const binIn = Cc["@mozilla.org/binaryinputstream;1"].createInstance(Ci.nsIBinaryInputStream);
  binIn.setInputStream(inStream);
  const parts = ipv4.split(".");
  if (parts.length !== 4) throw new Error("bad ipv4");
  const octets = parts.map(p => parseInt(p, 10));
  try {
    if (isolationToken) {
      binOut.writeByteArray([0x05, 0x01, 0x02]);
      const g = await waitBytes(binIn, 2);
      if (g[0] !== 5 || g[1] !== 2) throw new Error("ptr auth " + g[1]);
      const enc = new TextEncoder();
      const u = enc.encode(isolationToken);
      const p = enc.encode(isolationToken);
      const sr = [0x01, u.length, ...u, p.length, ...p];
      binOut.writeByteArray(sr);
      const sresp = await waitBytes(binIn, 2);
      if (sresp[0] !== 1 || sresp[1] !== 0) throw new Error("ptr subneg");
    } else {
      binOut.writeByteArray([0x05, 0x01, 0x00]);
      const g = await waitBytes(binIn, 2);
      if (g[0] !== 5 || g[1] !== 0) throw new Error("ptr greet");
    }
    binOut.writeByteArray([0x05, 0xF1, 0x00, 0x01, ...octets, 0x00, 0x00]);
    const hdr = await waitBytes(binIn, 4);
    if (hdr[0] !== 5) throw new Error("ptr ver");
    if (hdr[1] !== 0) {
      if (hdr[1] === 4) return null;
      throw new Error("ptr rep=" + hdr[1]);
    }
    if (hdr[3] !== 3) throw new Error("ptr atyp=" + hdr[3]);
    const len = (await waitBytes(binIn, 1))[0];
    if (len === 0) return null;
    const name = await waitBytes(binIn, len);
    await waitBytes(binIn, 2);
    return String.fromCharCode(...name);
  } finally {
    try { transport.close(0); } catch (e) {}
  }
}

const tor_ips = [];
const errors = [];
for (let i = 0; i < tries; i++) {
  const tok = `t0r-canary-${Date.now()}-${i}`;
  try {
    const ip = await socks5Resolve(socksHost, socksPort, host, tok);
    if (ip && tor_ips.indexOf(ip) === -1) tor_ips.push(ip);
  } catch (e) {
    errors.push(`socks5#${i}: ${e.message || e}`);
  }
}
let system_ip = null, err = null, system_ptr = null;
try { system_ip = await systemResolve(host); } catch (e) { err = String(e); }
// If system_ip is set and not already in tor_ips, do a PTR-via-Tor to
// check if it belongs to the target host or a subdomain of it.
if (system_ip && tor_ips.indexOf(system_ip) === -1) {
  try {
    system_ptr = await socks5ResolvePtr(socksHost, socksPort, system_ip, "t0r-canary-ptr");
  } catch (e) {
    errors.push(`ptr: ${e.message || e}`);
  }
}
return { host, tor_ips, system_ip, system_ptr, errors, error: err };
"""


def _is_private(ip: str | None) -> bool:
    if not ip:
        return False
    return bool(
        re.match(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)", ip)
        or re.match(r"^198\.(1[89])\.", ip)
        or ip in ("::1",) or ip.startswith("fc") or ip.startswith("fd")
    )


def _normal_host(host: str | None) -> str:
    if not host:
        return ""
    return host.lower().rstrip(".")


def _ptr_confirms_target(system_ptr: str | None, target_host: str | None) -> bool:
    ptr = _normal_host(system_ptr)
    target = _normal_host(target_host)
    return bool(ptr and target and (ptr == target or ptr.endswith(f".{target}")))


def _leak_detected(
    tor_ips: list[str],
    system_ip: str | None = None,
    *,
    system_ips: list[str] | None = None,
    target_host: str | None = None,
    system_ptr: str | None = None,
    system_ptrs: list[str | None] | None = None,
) -> bool:
    """Mirror of runSelfTest's verdict logic for unit testing.

    Keep this in lockstep with
    addon/experiments/onionbird/implementation.js::runSelfTest.

    A leak is flagged when:
      - at least one system resolver IP is public/actionable
      - at least one actionable system IP is NOT in the tor_ips set
      - AND every divergent IP is not PTR-confirmed as target_host
        or one of its subdomains.
    """
    if not tor_ips:
        return False
    candidates = list(system_ips or ([system_ip] if system_ip else []))
    actionable = [ip for ip in candidates if ip and not _is_private(ip)]
    if not actionable:
        return False
    divergent = [ip for ip in actionable if ip not in tor_ips]
    if not divergent:
        return False
    ptr_candidates = list(system_ptrs or ([system_ptr] if system_ptr else []))
    if len(divergent) > MAX_PTR_CONFIRMATIONS:
        return True
    if len(ptr_candidates) < len(divergent):
        return True
    if all(
        _ptr_confirms_target(ptr, target_host)
        for ptr in ptr_candidates[:len(divergent)]
    ):
        return False
    return True


def test_canary_returns_tor_ips_array(tb: TBClient) -> None:
    r = tb.exec_chrome(SELF_TEST_JS, args=[CANARY_HOST, "tor", 9050, 3])
    assert isinstance(r["tor_ips"], list)
    assert len(r["tor_ips"]) >= 1, f"all 3 isolated lookups failed: {r}"
    for ip in r["tor_ips"]:
        assert isinstance(ip, str) and ip.strip(), ip


def test_canary_system_ip_observed_via_dns_trap_path(tb: TBClient) -> None:
    """System resolver in our test stack -> dns-trap -> tor:5353. Must
    return a valid IP, not error out."""
    r = tb.exec_chrome(SELF_TEST_JS, args=[CANARY_HOST, "tor", 9050, 3])
    assert r["system_ip"], f"system resolve failed: {r}"
    assert isinstance(r["system_ip"], str) and r["system_ip"].strip()


def test_canary_in_test_stack_does_not_falsely_flag_leak(tb: TBClient) -> None:
    """In a healthy stack the canary must not flag a leak even when Tor
    samples vs system path return DIFFERENT IPs from the same multi-A
    service — PTR-via-Tor confirms the system_ip belongs to the target
    domain."""
    # Use a domain with a small + stable A-set if possible, but the PTR
    # path should handle multi-A CDNs too. check.torproject.org is the
    # canonical anchor in Tor docs.
    r = tb.exec_chrome(SELF_TEST_JS, args=[CANARY_HOST, "tor", 9050, 3])
    is_leak = _leak_detected(
        r["tor_ips"], r["system_ip"],
        target_host=CANARY_HOST,
        system_ptr=r.get("system_ptr"),
    )
    if is_leak:
        pytest.fail(
            f"healthy stack flagged: tor_ips={r['tor_ips']} "
            f"system_ip={r['system_ip']} ptr={r.get('system_ptr')!r}"
        )


# --- Unit tests on the leak-decision logic ---

def test_leak_logic_flags_when_system_ip_not_in_tor_set_and_no_ptr() -> None:
    assert _leak_detected(
        ["185.220.101.5", "199.249.230.10"], "8.8.8.8",
        target_host="torproject.org", system_ptr=None,
    ) is True


def test_leak_logic_flags_when_ptr_points_elsewhere() -> None:
    assert _leak_detected(
        ["185.220.101.5"], "8.8.8.8",
        target_host="torproject.org",
        system_ptr="dns.google",
    ) is True


def test_leak_logic_flags_when_ptr_only_shares_public_suffix() -> None:
    """A 2-label suffix shortcut would incorrectly accept co.uk here."""
    assert _leak_detected(
        ["185.220.101.5"], "8.8.8.8",
        target_host="victim.co.uk",
        system_ptr="attacker.co.uk",
    ) is True


def test_leak_logic_no_leak_when_ptr_confirms_target_subdomain() -> None:
    """The whole point of the PTR check: system_ip differs from tor_ips
    but belongs to the target's DNS tree (multi-A across ASNs)."""
    assert _leak_detected(
        ["116.202.120.165"], "204.8.99.146",
        target_host="torproject.org",
        system_ptr="archive.torproject.org",
    ) is False


def test_leak_logic_no_leak_when_system_ip_in_tor_set() -> None:
    assert _leak_detected(["1.2.3.4", "5.6.7.8"], "5.6.7.8") is False


def test_leak_logic_flags_extra_system_ip_even_when_one_ip_matches_tor() -> None:
    """A poisoned resolver can include one real A record plus one injected IP."""
    assert _leak_detected(
        ["1.2.3.4"],
        system_ips=["1.2.3.4", "8.8.8.8"],
        target_host="torproject.org",
        system_ptrs=["dns.google"],
    ) is True


def test_leak_logic_no_leak_when_each_divergent_ip_is_ptr_confirmed() -> None:
    assert _leak_detected(
        ["1.2.3.4"],
        system_ips=["1.2.3.4", "204.8.99.146"],
        target_host="torproject.org",
        system_ptrs=["archive.torproject.org"],
    ) is False


def test_leak_logic_ignores_private_system_ip() -> None:
    assert _leak_detected(["1.2.3.4"], "192.168.1.1") is False


def test_leak_logic_ignores_benchmarking_system_ip() -> None:
    assert _leak_detected(["1.2.3.4"], "198.18.112.3") is False
    assert _leak_detected(["1.2.3.4"], "198.19.0.9") is False


def test_leak_logic_inconclusive_when_missing_data() -> None:
    assert _leak_detected([], "1.1.1.1") is False
    assert _leak_detected(["1.1.1.1"], None) is False
    assert _leak_detected([], None) is False


def test_ptr_confirmation_requires_target_or_subdomain() -> None:
    assert _ptr_confirms_target("torproject.org", "torproject.org") is True
    assert _ptr_confirms_target("archive.torproject.org", "torproject.org") is True
    assert _ptr_confirms_target("archive.torproject.org.", "torproject.org.") is True
    assert _ptr_confirms_target("attacker.co.uk", "victim.co.uk") is False
    assert _ptr_confirms_target("evil-torproject.org", "torproject.org") is False
    assert _ptr_confirms_target("", "torproject.org") is False
    assert _ptr_confirms_target(None, "torproject.org") is False
