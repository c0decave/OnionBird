"""End-to-end: TB actually composes and sends mail via SMTP, smtp-trap captures
the raw RFC 5322 message, and we assert on real headers (User-Agent, HELO, etc).

This is the load-bearing "the addon actually defends against header leaks" test.
"""

from __future__ import annotations

import re

import pytest
from helpers.mail_capture import MailCapture
from helpers.tb_client import TBClient

SETUP_AND_SEND = r"""
const [smtpHost, smtpPort, fromEmail, toEmail, subject, body] = arguments;
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
const Cc = Components.classes;
const Ci = Components.interfaces;
const outgoing = MailServices.outgoingServer || MailServices.smtp;

// Find or create SMTP server
let smtp = null;
for (const s of outgoing.servers) {
  const ss = s.QueryInterface(Ci.nsISmtpServer);
  if (ss.hostname === smtpHost && ss.port === smtpPort) { smtp = ss; break; }
}
if (!smtp) {
  smtp = outgoing.createServer("smtp").QueryInterface(Ci.nsISmtpServer);
  smtp.hostname = smtpHost;
  smtp.port = smtpPort;
  smtp.authMethod = 0;
  smtp.socketType = 0;
}

// Find or create identity bound to a real account
let identity = null;
for (const i of MailServices.accounts.allIdentities) {
  if (i.email === fromEmail) { identity = i; break; }
}
if (!identity) {
  identity = MailServices.accounts.createIdentity();
  identity.email = fromEmail;
  identity.fullName = "anon";
  // Reuse an existing account if any (Local Folders or whatever exists)
  // Otherwise create a fresh pop3 account with a unique hostname.
  let account = null;
  for (const a of MailServices.accounts.accounts) {
    if (a.incomingServer && a.incomingServer.type === "none") {
      account = a; break;
    }
  }
  if (!account) {
    account = MailServices.accounts.createAccount();
    const incoming = MailServices.accounts.createIncomingServer(
      "anon", "local.invalid", "none"
    );
    account.incomingServer = incoming;
  }
  account.addIdentity(identity);
  if (!account.defaultIdentity) {
    account.defaultIdentity = identity;
  }
}
// ALWAYS rebind smtpServerKey, even if identity pre-existed from another test.
identity.smtpServerKey = smtp.key;

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
  const timer = setTimeout(() => reject(new Error("send timeout 30s")), 30000);
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


RESET_SMTP_STATE = r"""
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
const Ci = Components.interfaces;
const outgoing = MailServices.outgoingServer || MailServices.smtp;
// Reset all SMTP servers to plain unauthenticated state for testing
for (const s of outgoing.servers) {
  const ss = s.QueryInterface(Ci.nsISmtpServer);
  ss.authMethod = 0;    // no auth
  ss.socketType = 0;    // plain (no TLS)
  // Clear hardening prefs that previous tests may have set
  Services.prefs.clearUserPref(`mail.smtpserver.${ss.key}.hello_argument`);
  Services.prefs.clearUserPref(`mail.smtpserver.${ss.key}.try_ssl`);
  Services.prefs.clearUserPref(`mail.smtpserver.${ss.key}.useSecAuth`);
  try { ss.closeCachedConnections(); } catch (e) {}
}
// Reset identity FQDN overrides
for (const i of MailServices.accounts.allIdentities) {
  Services.prefs.clearUserPref(`mail.identity.${i.key}.FQDN`);
}
return "reset";
"""


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    # Reset to known direct-connection state
    client.set_pref("network.proxy.type", 0)
    # Clear any per-server / per-identity state from previous tests
    client.exec_chrome(RESET_SMTP_STATE)
    yield client
    client.close()


@pytest.fixture
def mail() -> MailCapture:
    m = MailCapture()
    m.clear()
    return m


def test_baseline_send_includes_user_agent(tb: TBClient, mail: MailCapture) -> None:
    """Default TB sends with User-Agent header present."""
    tb.set_pref("mailnews.headers.sendUserAgent", True)
    tb.m.timeout.script = 60
    tb.exec_chrome(
        SETUP_AND_SEND,
        args=["smtp-trap", 25, "real-baseline@anon.invalid", "bob@anon.invalid",
              "baseline test", "Hello\n"],
    )
    msgs = mail.wait_for(n=1, timeout=30)
    content = msgs[0]["content"]
    assert "User-Agent:" in content, f"baseline missing User-Agent:\n{content[:400]}"


def test_user_agent_suppressed_when_pref_off(tb: TBClient, mail: MailCapture) -> None:
    """With sendUserAgent=false: no User-Agent, no X-Mailer."""
    tb.set_pref("mailnews.headers.sendUserAgent", False)
    tb.m.timeout.script = 60
    tb.exec_chrome(
        SETUP_AND_SEND,
        args=["smtp-trap", 25, "real-ua-off@anon.invalid", "bob@anon.invalid",
              "ua off test", "Hello\n"],
    )
    msgs = mail.wait_for(n=1, timeout=30)
    content = msgs[0]["content"]
    assert "User-Agent:" not in content, f"UA leak:\n{content[:400]}"
    assert "X-Mailer:" not in content, f"X-Mailer leak:\n{content[:400]}"


def test_message_id_fqdn_overridden_in_real_send(tb: TBClient, mail: MailCapture) -> None:
    """When mail.identity.idN.FQDN is set, the captured Message-ID uses that domain."""
    tb.m.timeout.script = 60
    # Send once to ensure identity exists, then override FQDN, send again
    tb.exec_chrome(
        SETUP_AND_SEND,
        args=["smtp-trap", 25, "real-msgid@anon.invalid", "bob@anon.invalid",
              "msgid setup", "x\n"],
    )
    mail.clear()
    # Find the identity key
    identity_key = tb.exec_chrome(r"""
        const { MailServices } = ChromeUtils.importESModule(
          "resource:///modules/MailServices.sys.mjs"
        );
        for (const i of MailServices.accounts.allIdentities) {
          if (i.email === "real-msgid@anon.invalid") return i.key;
        }
        return null;
    """)
    assert identity_key, "identity not found"
    tb.set_pref(f"mail.identity.{identity_key}.FQDN", "localhost.localdomain")

    tb.exec_chrome(
        SETUP_AND_SEND,
        args=["smtp-trap", 25, "real-msgid@anon.invalid", "bob@anon.invalid",
              "msgid test", "x\n"],
    )
    msgs = mail.wait_for(n=1, timeout=30)
    content = msgs[0]["content"]
    m = re.search(r"^Message-ID:\s*<[^@]+@([^>]+)>", content, re.MULTILINE)
    assert m, f"no Message-ID:\n{content[:400]}"
    assert m.group(1) == "localhost.localdomain", f"FQDN leak: {m.group(1)!r}"


def test_helo_overridden_in_real_send(tb: TBClient, mail: MailCapture) -> None:
    """When hello_argument is set, captured HELO == '[127.0.0.1]'."""
    tb.m.timeout.script = 60
    # Ensure SMTP server exists and is configured for plain SMTP, then set
    # the hello_argument pref via setCharPref (NOT setStringPref — TB
    # SmtpServer reads via getCharPref, see also TBClient.set_pref).
    smtp_key = tb.exec_chrome(r"""
        const { MailServices } = ChromeUtils.importESModule(
          "resource:///modules/MailServices.sys.mjs"
        );
        const Ci = Components.interfaces;
        const outgoing = MailServices.outgoingServer || MailServices.smtp;
        let smtp = null;
        for (const s of outgoing.servers) {
          const ss = s.QueryInterface(Ci.nsISmtpServer);
          if (ss.hostname === "smtp-trap") { smtp = ss; break; }
        }
        if (!smtp) {
          smtp = outgoing.createServer("smtp").QueryInterface(Ci.nsISmtpServer);
          smtp.hostname = "smtp-trap";
          smtp.port = 25;
        }
        smtp.authMethod = 0;
        smtp.socketType = 0;
        Services.prefs.setCharPref(
          `mail.smtpserver.${smtp.key}.hello_argument`,
          "[127.0.0.1]"
        );
        return {key: smtp.key, helo_pref: Services.prefs.getCharPref(
          `mail.smtpserver.${smtp.key}.hello_argument`, "<unset>"
        )};
    """)
    assert smtp_key["helo_pref"] == "[127.0.0.1]", (
        f"pref not set correctly: {smtp_key}"
    )

    # Verify pref is set right before send
    verify = tb.exec_chrome(f"""
        return Services.prefs.getCharPref(
          "mail.smtpserver.{smtp_key['key']}.hello_argument", "<unset>"
        );
    """)
    assert verify == "[127.0.0.1]", f"pref lost: {verify!r}"

    tb.exec_chrome(
        SETUP_AND_SEND,
        args=["smtp-trap", 25, "real-helo@anon.invalid", "bob@anon.invalid",
              "helo test", "x\n"],
    )
    msgs = mail.wait_for(n=1, timeout=30)
    assert msgs[0]["helo"] == "[127.0.0.1]", (
        f"HELO leak: {msgs[0]['helo']!r} (pref was: {verify!r})"
    )
