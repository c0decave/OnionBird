"""Drive a host Thunderbird via Marionette to send real mail through a
configured provider account."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Reuse the in-repo TBClient with one tweak: pass in arbitrary host/port.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from helpers.tb_client import TBClient  # noqa: E402

from external.providers import ProviderConfig  # noqa: E402

SEND_SCRIPT = r"""
const [
  smtpHost, smtpPort, smtpUser, smtpPass, smtpSocketType,
  fromEmail, toEmail, subject, body,
  socksHost, socksPort,
] = arguments;

const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
const Cc = Components.classes;
const Ci = Components.interfaces;
const outgoing = MailServices.outgoingServer || MailServices.smtp;

// Find or create the SMTP server
let smtp = null;
for (const s of outgoing.servers) {
  const ss = s.QueryInterface(Ci.nsISmtpServer);
  if (ss.hostname === smtpHost && ss.port === smtpPort) { smtp = ss; break; }
}
if (!smtp) {
  smtp = outgoing.createServer("smtp").QueryInterface(Ci.nsISmtpServer);
  smtp.hostname = smtpHost;
  smtp.port = smtpPort;
}
smtp.socketType = smtpSocketType;
smtp.authMethod = smtpUser ? 3 : 0;   // 3=passwordCleartext, 0=none
smtp.username = smtpUser || "";

// Apply hardening
Services.prefs.setBoolPref("mailnews.headers.sendUserAgent", false);
Services.prefs.setBoolPref("privacy.resistFingerprinting", true);
Services.prefs.setCharPref(`mail.smtpserver.${smtp.key}.hello_argument`, "[127.0.0.1]");

// SOCKS to host Tor
Services.prefs.setIntPref("network.proxy.type", 1);
Services.prefs.setCharPref("network.proxy.socks", socksHost);
Services.prefs.setIntPref("network.proxy.socks_port", socksPort);
Services.prefs.setIntPref("network.proxy.socks_version", 5);
Services.prefs.setBoolPref("network.proxy.socks_remote_dns", true);
Services.prefs.setBoolPref("network.proxy.failover_direct", false);

// Find or create identity bound to this server
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
    if (a.incomingServer && a.incomingServer.type === "none") { acc = a; break; }
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
identity.smtpServerKey = smtp.key;
// Reallife-audit final (2026-05-22): default to the From-domain so the
// Message-ID looks like a normal provider user (e.g. `@undisclose.de`)
// rather than a sprechende "privacy-tool" signature (`@localhost.localdomain`,
// `@*.invalid`). DKIM d= already discloses the same domain, no new leak.
const _fromDomain = (fromEmail.includes("@") ? fromEmail.split("@").pop() : "") ||
                    "localhost.localdomain";
Services.prefs.setCharPref(`mail.identity.${identity.key}.FQDN`, _fromDomain);

// Stash password in the credential manager so SMTP auth works headless
if (smtpPass) {
  const loginInfo = Cc["@mozilla.org/login-manager/loginInfo;1"]
    .createInstance(Ci.nsILoginInfo);
  loginInfo.init(
    "smtp://" + smtpHost, null, "smtp://" + smtpHost,
    smtpUser, smtpPass, "", ""
  );
  // TB 140: try removeAllLogins-for-origin (not method we have), so search+remove
  try {
    const existing = await Services.logins.searchLoginsAsync({
      origin: "smtp://" + smtpHost,
    });
    for (const l of existing) {
      try { Services.logins.removeLogin(l); } catch (e) {}
    }
  } catch (e) {}
  // addLoginAsync is the modern API in TB 140
  await Services.logins.addLoginAsync(loginInfo);
}

try { smtp.closeCachedConnections(); } catch (e) {}

const fields = Cc[
  "@mozilla.org/messengercompose/composefields;1"
].createInstance(Ci.nsIMsgCompFields);
fields.from = fromEmail;
fields.to = toEmail;
fields.subject = subject;

const msgSend = Cc[
  "@mozilla.org/messengercompose/send;1"
].createInstance(Ci.nsIMsgSend);

return await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("send timeout 120s")), 120000);
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


def send_via(
    tb: TBClient,
    provider: ProviderConfig,
    *,
    to: str,
    subject: str,
    body: str,
    socks_host: str = "127.0.0.1",
    socks_port: int = 9050,
) -> Any:
    tb.m.timeout.script = 150
    return tb.exec_chrome(
        SEND_SCRIPT,
        args=[
            provider.smtp_host,
            provider.smtp_port,
            provider.user,
            provider.password,
            provider.smtp_socket_type,
            provider.email,
            to,
            subject,
            body,
            socks_host,
            socks_port,
        ],
    )
