"""HELO override + STARTTLS — driven by the real addon enable path.

The previous version directly used `Services.prefs.setCharPref` to set
the per-SMTP-server prefs, then read them back. That tested Mozilla's
pref service and the B-008 setCharPref-vs-setStringPref interop
(useful regression guard), but did not call the addon's
`applyHardeningToAllSmtpServers` at all.

This version installs the XPI, ensures an onion SMTP server is present,
lets enableHardening run, and asserts the per-server hardening prefs
materialise via the addon's chain. The B-008 read-back assertion is
kept so a future regression there still fails.
"""

from __future__ import annotations

import time

import pytest
from helpers.tb_client import TBClient

XPI = "/build/onionbird.xpi"

# An onion-shaped hostname so the addon classifies the server as a
# Tor target and harden it (clearnet servers are intentionally not
# hardened by default — see B-003 in implementation.js).
ONION_HOST = "cl76kxdkjvyeqrug65aukstub3cvkvax6pzbdjup54qidq2uqinfnbid.onion"


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


CREATE_ONION_SMTP = r"""
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
const Ci = Components.interfaces;
const host = arguments[0];
const outgoing = MailServices.outgoingServer || MailServices.smtp;

let smtp = null;
for (const s of outgoing.servers) {
  const ss = s.QueryInterface ? s.QueryInterface(Ci.nsISmtpServer) : s;
  if (ss.hostname === host) { smtp = ss; break; }
}
if (!smtp) {
  const raw = outgoing.createServer("smtp");
  smtp = raw.QueryInterface(Ci.nsISmtpServer);
  smtp.hostname = host;
  smtp.port = 25;
}
// Clear hardening-owned prefs so the addon must set them.
const helo = `mail.smtpserver.${smtp.key}.hello_argument`;
const try_ssl = `mail.smtpserver.${smtp.key}.try_ssl`;
try { Services.prefs.clearUserPref(helo); } catch (e) {}
try { Services.prefs.clearUserPref(try_ssl); } catch (e) {}
return smtp.key;
"""


def _wait_for(get_value, expected, timeout: float = 30.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = get_value()
        if last == expected:
            return last
        time.sleep(0.25)
    return last


def test_addon_enable_writes_helo_for_onion_smtp(tb: TBClient) -> None:
    """The addon must rewrite HELO to `[127.0.0.1]` for onion SMTP
    servers via applyHardeningToAllSmtpServers. Reading via getCharPref
    (not get_pref's type-switch) so a B-008 regression — setStringPref
    written, getCharPref unable to read — would also fail this test."""
    smtp_key = tb.exec_chrome(CREATE_ONION_SMTP, args=[ONION_HOST])
    assert smtp_key

    tb.set_pref("network.proxy.socks", "tor")
    tb.set_pref("network.proxy.socks_port", 9050)
    tb.install_addon(XPI, temporary=True)

    helo_key = f"mail.smtpserver.{smtp_key}.hello_argument"
    try_ssl_key = f"mail.smtpserver.{smtp_key}.try_ssl"

    def read_helo_via_getCharPref() -> str | None:
        return tb.exec_chrome(
            f'try {{ return Services.prefs.getCharPref('
            f'  "{helo_key}", "<unset>"); }} '
            f'catch (e) {{ return "<error:" + String(e) + ">"; }}'
        )

    helo = _wait_for(read_helo_via_getCharPref, "[127.0.0.1]")
    assert helo == "[127.0.0.1]", (
        f"addon enable did not set HELO via getCharPref-readable path "
        f"(got {helo!r}); B-008 regression or applyHardeningToAllSmtpServers "
        f"is broken"
    )

    # For onion servers the addon disables TLS (Onion services provide
    # E2E auth + confidentiality; STARTTLS would force an unnecessary
    # x509 trust dance against a fake cert). try_ssl == 0.
    try_ssl = _wait_for(lambda: tb.get_pref(try_ssl_key), 0)
    assert try_ssl == 0, (
        f"addon did not configure onion SMTP try_ssl=0 (got {try_ssl!r})"
    )


def test_addon_loaded_when_smtp_present(tb: TBClient) -> None:
    """The addon installs successfully when an SMTP server exists.
    Smoke for the install path."""
    tb.exec_chrome(CREATE_ONION_SMTP, args=[ONION_HOST])
    tb.install_addon(XPI, temporary=True)
    policy_info = tb.exec_chrome(
        r"""
        const policy = WebExtensionPolicy.getByID("onionbird@undisclose.de");
        return policy ? { id: policy.id, active: policy.active } : null;
        """
    )
    assert policy_info is not None
    assert policy_info["id"] == "onionbird@undisclose.de"
    assert policy_info["active"] is True
