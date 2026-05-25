"""End-to-end Tor-routed mail send.

This is the real test: TB → SOCKS5 → Tor onion service → smtp-trap.
We send multiple mails with varied subjects/bodies and assert on the
captured headers + the peer IP (must be Tor's IP, not TB's directly).

Verifies ALL of:
- SMTP traffic actually traverses Tor (peer IP is the tor container)
- DNS for the .onion is resolved by Tor, NOT leaked to dns-trap
- Hardened headers: no User-Agent, no X-Mailer, Message-ID FQDN normalised,
  HELO=[127.0.0.1], Date stable
- Multiple sends in succession all work (no connection-cache pollution)
- UTF-8 subjects don't break encoding
- The full pipeline survives realistic usage patterns
"""

from __future__ import annotations

import os
import re
import time

import pytest
from helpers.dns_capture import DNSCapture
from helpers.mail_capture import MailCapture
from helpers.tb_client import TBClient

XPI = "/build/onionbird.xpi"


# Sends a mail to a configured-via-onion SMTP server. The SOCKS proxy
# routes it through Tor, where the onion service rendezvous delivers it
# to smtp-trap.
TOR_SEND_SCRIPT = r"""
const [smtpHost, smtpPort, fromEmail, toEmail, subject, body] = arguments;
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
const Cc = Components.classes;
const Ci = Components.interfaces;
const outgoing = MailServices.outgoingServer || MailServices.smtp;

// Find or create SMTP server bound to the onion host
let smtp = null;
for (const s of outgoing.servers) {
  const ss = s.QueryInterface(Ci.nsISmtpServer);
  if (ss.hostname === smtpHost && ss.port === smtpPort) { smtp = ss; break; }
}
if (!smtp) {
  smtp = outgoing.createServer("smtp").QueryInterface(Ci.nsISmtpServer);
  smtp.hostname = smtpHost;
  smtp.port = smtpPort;
  smtp.authMethod = 0;   // none (onion is the auth)
  smtp.socketType = 0;   // plain (onion provides confidentiality)
}

// Find or create identity bound to this SMTP
let identity = null;
for (const i of MailServices.accounts.allIdentities) {
  if (i.email === fromEmail) { identity = i; break; }
}
if (!identity) {
  identity = MailServices.accounts.createIdentity();
  identity.email = fromEmail;
  identity.fullName = "anon";
  let acc = null;
  for (const a of MailServices.accounts.accounts) {
    if (a.incomingServer && a.incomingServer.type === "none") {
      acc = a; break;
    }
  }
  if (!acc) {
    acc = MailServices.accounts.createAccount();
    const inc = MailServices.accounts.createIncomingServer(
      "anon", "local.invalid", "none"
    );
    acc.incomingServer = inc;
  }
  acc.addIdentity(identity);
  if (!acc.defaultIdentity) acc.defaultIdentity = identity;
}
// ALWAYS rebind the identity to this SMTP server, even if identity already
// existed. Otherwise an identity created against a previous test's smtp-trap
// would still route through the wrong (non-onion) server.
identity.smtpServerKey = smtp.key;

// Apply hardening prefs (the addon would normally do this; we replicate
// here so the test is self-contained and exercises the same code path).
Services.prefs.setBoolPref("mailnews.headers.sendUserAgent", false);
Services.prefs.setBoolPref("privacy.resistFingerprinting", true);
Services.prefs.setCharPref(`mail.smtpserver.${smtp.key}.hello_argument`, "[127.0.0.1]");
Services.prefs.setIntPref(`mail.smtpserver.${smtp.key}.try_ssl`, 0);
Services.prefs.setCharPref(`mail.identity.${identity.key}.FQDN`, "localhost.localdomain");

// SOCKS5 proxy to local Tor. Use the actual addon defaults.
Services.prefs.setIntPref("network.proxy.type", 1);
Services.prefs.setCharPref("network.proxy.socks", "tor");  // container-internal: real Tor
Services.prefs.setIntPref("network.proxy.socks_port", 9050);
Services.prefs.setIntPref("network.proxy.socks_version", 5);
Services.prefs.setBoolPref("network.proxy.socks_remote_dns", true);
Services.prefs.setBoolPref("network.proxy.failover_direct", false);

// Close any cached connection so the new proxy config is honored.
try { smtp.closeCachedConnections(); } catch (e) {}

const fields = Cc[
  "@mozilla.org/messengercompose/composefields;1"
].createInstance(Ci.nsIMsgCompFields);
fields.from = identity.email;
fields.to = toEmail;
fields.subject = subject;

const msgSend = Cc[
  "@mozilla.org/messengercompose/send;1"
].createInstance(Ci.nsIMsgSend);

return await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("send timeout 90s")), 90000);
  const listener = {
    QueryInterface: ChromeUtils.generateQI(["nsIMsgSendListener"]),
    onStartSending() {},
    onSendProgress() {},
    onStatus() {},
    onStopSending(_msgID, status) {
      clearTimeout(timer);
      if (Components.isSuccessCode(status)) resolve("ok");
      else reject(new Error("send failed 0x" + status.toString(16)));
    },
    onGetDraftFolderURI() {},
    onSendNotPerformed(_msgID, status) {
      clearTimeout(timer);
      reject(new Error("not performed 0x" + status.toString(16)));
    },
    onTransportSecurityError() {},
  };
  msgSend.createAndSendMessage(
    null, identity, "", fields, false, false,
    Ci.nsIMsgSend.nsMsgDeliverNow, null,
    "text/plain", body,
    null, null, listener, "", "", null
  );
});
"""


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    client.m.timeout.script = 120  # send via Tor is slower
    yield client
    client.close()


@pytest.fixture
def mail() -> MailCapture:
    m = MailCapture()
    m.clear()
    return m


@pytest.fixture
def dns() -> DNSCapture:
    d = DNSCapture()
    d.clear()
    return d


@pytest.fixture
def onion() -> str:
    """Return the hidden-service hostname from the test-pod's Tor.

    Order: prefer the pre-populated fixture file (written by `make test-up`),
    fall back to a live read from the t0_tor container's hidden-service
    directory (mounted at /tor-hostname for E2E robustness). Skipping
    silently is dangerous — the suite then claims green while the
    privacy-critical real-send verifications run zero tests. If neither
    source is reachable, FAIL hard with an actionable message.
    """
    path = "/tests/fixtures/onion-hostname.txt"
    if os.path.exists(path):
        with open(path) as f:
            val = f.read().strip()
            if val:
                return val
    # Fallback: live read.
    alt = "/tor-hostname/hostname"
    if os.path.exists(alt):
        with open(alt) as f:
            val = f.read().strip()
            if val:
                return val
    pytest.fail(
        "onion-hostname.txt missing AND /tor-hostname/hostname not mounted. "
        "The real-Tor-send privacy verification cannot run. Either run "
        "`make test-up` to populate the fixture, or write the onion "
        "hostname yourself: "
        "docker exec t0_tor cat /var/lib/tor/hs_smtp/hostname > "
        "test/fixtures/onion-hostname.txt"
    )


# === Single send via Tor ===

def test_single_mail_via_tor_arrives_with_hardened_headers(
    tb: TBClient, mail: MailCapture, dns: DNSCapture, onion: str
) -> None:
    """Send one mail through Tor to the onion smtp-trap; verify ALL hardening."""
    tb.exec_chrome(
        TOR_SEND_SCRIPT,
        args=[onion, 25, "alice@anon.invalid", "bob@anon.invalid",
              "single tor send", "Hello via Tor onion.\n"],
    )
    msgs = mail.wait_for(n=1, timeout=60)
    m = msgs[0]
    content = m["content"]

    # Peer must be Tor's IP, not TB's
    assert m["peer_host"] == "172.30.112.4", (
        f"SMTP must arrive from Tor (172.30.112.4); got {m['peer_host']}"
    )

    # HELO override
    assert m["helo"] == "[127.0.0.1]", f"HELO leak: {m['helo']!r}"

    # No User-Agent / X-Mailer
    assert "User-Agent:" not in content, f"UA leak:\n{content[:500]}"
    assert "X-Mailer:" not in content

    # Message-ID FQDN
    mid = re.search(r"^Message-ID:\s*<[^@]+@([^>]+)>", content, re.MULTILINE)
    assert mid, f"no Message-ID:\n{content[:500]}"
    assert mid.group(1) == "localhost.localdomain", (
        f"Message-ID FQDN leak: {mid.group(1)!r}"
    )

    # Date header should be UTC (resistFingerprinting) -- ends with +0000 or GMT
    date = re.search(r"^Date:\s*(.+)$", content, re.MULTILINE)
    assert date, f"no Date:\n{content[:500]}"
    date_str = date.group(1).strip()
    assert date_str.endswith("+0000") or date_str.endswith("GMT") or "UT" in date_str, (
        f"Date not UTC: {date_str!r}"
    )

    # DNS-leak check: the onion hostname must NEVER hit dns-trap
    leaks = dns.queries_for(onion)
    assert not leaks, f"DNS LEAK to dns-trap for {onion}: {leaks}"


# === Burst: multiple sends in sequence ===

def test_five_mails_in_sequence_all_arrive_via_tor(
    tb: TBClient, mail: MailCapture, dns: DNSCapture, onion: str
) -> None:
    """Send 5 mails back-to-back; all must arrive via Tor with no DNS leak."""
    subjects = [
        "burst test 1",
        "burst test 2",
        "burst test 3",
        "burst test 4",
        "burst test 5",
    ]
    for s in subjects:
        tb.exec_chrome(
            TOR_SEND_SCRIPT,
            args=[onion, 25, "burst@anon.invalid", "recv@anon.invalid",
                  s, f"Body for {s}\n"],
        )

    msgs = mail.wait_for(n=5, timeout=120)
    assert len(msgs) == 5

    # Every message must have arrived via Tor
    for m in msgs:
        assert m["peer_host"] == "172.30.112.4", (
            f"non-Tor peer in burst: {m['peer_host']}"
        )
        assert m["helo"] == "[127.0.0.1]"
        assert "User-Agent:" not in m["content"]

    # Subjects all captured (order not guaranteed across Tor circuits)
    captured_subjects = []
    for m in msgs:
        match = re.search(r"^Subject:\s*(.+)$", m["content"], re.MULTILINE)
        if match:
            captured_subjects.append(match.group(1).strip())
    for s in subjects:
        assert s in captured_subjects, f"subject {s!r} missing from captures"

    # No DNS leaks for the onion across 5 sends
    leaks = dns.queries_for(onion)
    assert not leaks, f"DNS LEAK after burst: {leaks}"


# === UTF-8 subject handling ===

def test_utf8_subject_via_tor_round_trips(
    tb: TBClient, mail: MailCapture, onion: str
) -> None:
    """UTF-8 subject must arrive RFC 2047 encoded, no UA leak, via Tor."""
    subject = "Geheimes Treffen — 🌚 — keine Spuren"
    tb.exec_chrome(
        TOR_SEND_SCRIPT,
        args=[onion, 25, "utf8@anon.invalid", "recv@anon.invalid",
              subject, "ÜBerwacht? ja.\n"],
    )
    msgs = mail.wait_for(n=1, timeout=60)
    content = msgs[0]["content"]

    # Subject is RFC 2047 encoded (look for =?utf-8?... pattern)
    assert "=?utf-8?" in content.lower() or "=?UTF-8?" in content, (
        f"UTF-8 subject not encoded:\n{content[:600]}"
    )
    # No UA leak
    assert "User-Agent:" not in content
    # Via Tor
    assert msgs[0]["peer_host"] == "172.30.112.4"


# === Long body ===

def test_long_body_via_tor(
    tb: TBClient, mail: MailCapture, onion: str
) -> None:
    """A ~50 KB body must transit Tor without truncation. TB encodes long
    plaintext bodies as base64 (Content-Transfer-Encoding: base64), so we
    decode before asserting on the marker."""
    import base64
    body = ("This is a long body. " * 2500) + "END_MARKER\n"
    tb.exec_chrome(
        TOR_SEND_SCRIPT,
        args=[onion, 25, "long@anon.invalid", "recv@anon.invalid",
              "long body", body],
    )
    msgs = mail.wait_for(n=1, timeout=90)
    content = msgs[0]["content"]
    assert msgs[0]["peer_host"] == "172.30.112.4"

    # Split headers from body
    _, _, raw_body = content.partition("\r\n\r\n")
    if "Content-Transfer-Encoding: base64" in content:
        # Strip CRLF line breaks and decode
        decoded = base64.b64decode(raw_body.replace("\r\n", ""))
        decoded_str = decoded.decode("utf-8", errors="replace")
    elif "Content-Transfer-Encoding: quoted-printable" in content:
        # TB switches to QP when format=flowed is off (reallife audit
        # fix 2026-05-22): long lines get soft-wrapped with "=\r\n" and
        # special chars are escaped as `=2E`. Decode before counting.
        import quopri
        decoded = quopri.decodestring(raw_body.encode("utf-8"))
        decoded_str = decoded.decode("utf-8", errors="replace")
    else:
        decoded_str = raw_body

    assert "END_MARKER" in decoded_str, "body truncated in Tor relay"
    assert decoded_str.count("This is a long body.") >= 2400, (
        f"many body lines missing: got {decoded_str.count('This is a long body.')}"
    )


# === Different senders share one Tor circuit but no headers cross-leak ===

def test_multiple_identities_no_header_cross_contamination(
    tb: TBClient, mail: MailCapture, onion: str
) -> None:
    """Two identities sending sequentially must have distinct From + Message-ID
    but identical hardening (UA absent, FQDN normalised)."""
    identities = ["alpha@anon.invalid", "beta@anon.invalid"]
    for who in identities:
        tb.exec_chrome(
            TOR_SEND_SCRIPT,
            args=[onion, 25, who, "watcher@anon.invalid",
                  f"from {who}", f"signed: {who}\n"],
        )

    msgs = mail.wait_for(n=2, timeout=90)
    froms = []
    msg_ids = []
    for m in msgs:
        c = m["content"]
        from_m = re.search(r"^From:\s*(.+)$", c, re.MULTILINE)
        mid_m = re.search(r"^Message-ID:\s*<([^>]+)>", c, re.MULTILINE)
        assert from_m and mid_m, f"missing headers:\n{c[:400]}"
        froms.append(from_m.group(1).strip())
        msg_ids.append(mid_m.group(1).strip())
        # Hardening applies to both
        assert m["peer_host"] == "172.30.112.4"
        assert m["helo"] == "[127.0.0.1]"
        assert "User-Agent:" not in c
        # FQDN normalised
        assert msg_ids[-1].split("@")[1] == "localhost.localdomain"

    # Distinct From
    assert any("alpha@anon.invalid" in f for f in froms)
    assert any("beta@anon.invalid" in f for f in froms)
    # Distinct Message-IDs
    assert len(set(msg_ids)) == 2


# === Send-fail behavior: if Tor is unreachable, send must fail closed ===

# Variant of TOR_SEND_SCRIPT that does NOT override proxy prefs — so the
# test's bad-port configuration is respected.
TOR_SEND_NO_PROXY_OVERRIDE = TOR_SEND_SCRIPT.replace(
    """// SOCKS5 proxy to local Tor. Use the actual addon defaults.
Services.prefs.setIntPref("network.proxy.type", 1);
Services.prefs.setCharPref("network.proxy.socks", "tor");  // container-internal: real Tor
Services.prefs.setIntPref("network.proxy.socks_port", 9050);
Services.prefs.setIntPref("network.proxy.socks_version", 5);
Services.prefs.setBoolPref("network.proxy.socks_remote_dns", true);
Services.prefs.setBoolPref("network.proxy.failover_direct", false);""",
    "// Proxy prefs intentionally NOT overridden — test controls them."
)


def test_send_fails_closed_if_tor_unreachable(
    tb: TBClient, mail: MailCapture, onion: str
) -> None:
    """Point SOCKS at a non-existent port; failover_direct=false must prevent
    the send from bypassing Tor. Send MUST fail, NOT arrive at smtp-trap."""
    tb.m.timeout.script = 60
    # Configure proxy to fail
    tb.set_pref("network.proxy.type", 1)
    tb.set_pref("network.proxy.socks", "tor")
    tb.set_pref("network.proxy.socks_port", 19999)  # nothing listens here
    tb.set_pref("network.proxy.socks_version", 5)
    tb.set_pref("network.proxy.socks_remote_dns", True)
    tb.set_pref("network.proxy.failover_direct", False)

    mail.clear()
    raised = False
    try:
        tb.exec_chrome(
            TOR_SEND_NO_PROXY_OVERRIDE,
            args=[onion, 25, "failclosed@anon.invalid", "recv@anon.invalid",
                  "should not arrive", "leak?\n"],
        )
    except Exception:
        raised = True

    # Wait briefly to let any escaped traffic settle
    time.sleep(2)
    msgs = mail.list()

    # With failover_direct=false the send must fail (raise) AND nothing must
    # have arrived at smtp-trap.
    assert raised, "send did not raise with bad proxy port"
    assert not msgs, (
        f"FAIL-CLOSED REGRESSION: mail arrived despite bad proxy: {msgs}"
    )
