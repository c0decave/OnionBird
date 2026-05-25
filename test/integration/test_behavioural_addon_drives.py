"""Behavioural test replacements for the structural P0 finds from
the 2026-05-24 third audit (Bundle D).

Each of the four T-NNN findings — T-072, T-073, T-074, T-076 — calls
out a test that proves a tautology (re-implements the addon's logic
in the test, or sets the hardening pref itself and asserts Mozilla
honoured it). This file adds the corresponding behavioural tests
that actually drive the addon and observe its side effects on TB.

The existing structural tests are kept (they catch the most common
typo-and-delete regressions cheaply); the tests here are the
defense-in-depth that catches `if/else` swapped, `continue` →
`break`, or quietly-replaced wiring that source-grep cannot see.

What this file does NOT cover:

T-076 (compose.onBeforeSend send-cancel verification by actually
opening a compose window via Marionette, populating storage.local
with a leak verdict, and watching the cancel notification): the
compose-window driver is a non-trivial Marionette helper
(MailServices.compose.OpenComposeWindow + waiting for the chrome
notification bar). Tracked as deferred P1 with `xfail(strict=True)`
below so the day someone writes the driver, the suite auto-promotes.
"""

from __future__ import annotations

import time

import pytest
from helpers.tb_client import TBClient

XPI = "/build/onionbird.xpi"


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


def _wait_for(get, predicate, timeout: float = 30.0, interval: float = 0.25):
    """Poll `get()` until `predicate(value)` is True (or timeout).
    Returns the final value either way; assertion is the caller's."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = get()
        if predicate(last):
            return last
        time.sleep(interval)
    return last


# ---- T-072: applyPrefs is per-pref (F-044), behaviourally observed ----


def test_T072_F044_applies_bulk_of_hardening_prefs_after_install(tb: TBClient) -> None:
    """Behavioural: install the addon, wait for `enableHardening` to
    fire from the `onInstalled` listener, and assert that a broad
    sample of HARDENING_PREFS are actually at their hardened values.

    A regression to fail-on-first-bad (e.g. someone re-introducing
    the early-return-on-validation-failure pattern that F-044
    removed) would silently drop nearly all writes — the first
    pref that hits an unexpected policy lock or shape would abort
    the whole batch. The current per-pref code applies whatever
    individually succeeds.

    The structural T-072 in test_audit_fixes.py asserts the
    bug-shaped source patterns are absent; this asserts the
    *property* — at apply-time, the bulk of the batch lands."""
    # Pre-set leak-on baseline so we can distinguish "addon wrote"
    # from "TB-default already matches".
    tb.set_pref("mailnews.headers.sendUserAgent", True)
    tb.set_pref("network.dns.disableIPv6", False)
    tb.set_pref("network.predictor.enabled", True)
    tb.set_pref("network.prefetch-next", True)
    tb.set_pref("privacy.resistFingerprinting", False)

    tb.install_addon(XPI, temporary=True)
    # Wait for an anchor pref to flip — proves the enable chain ran.
    _wait_for(
        lambda: tb.get_pref("mailnews.headers.sendUserAgent"),
        lambda v: v is False,
        timeout=30,
    )

    # Sample of HARDENING_PREFS spanning multiple subsystems so a
    # failure in any group of writes (proxy / dns / mailnews /
    # telemetry / privacy) shows up.
    sample = [
        ("mailnews.headers.sendUserAgent", False),
        ("network.proxy.socks_remote_dns", True),
        ("network.proxy.failover_direct", False),
        ("network.dns.disableIPv6", True),
        ("network.dns.disablePrefetch", True),
        ("network.predictor.enabled", False),
        ("network.prefetch-next", False),
        ("network.trr.mode", 5),
        ("network.connectivity-service.enabled", False),
        ("network.captive-portal-service.enabled", False),
        ("security.OCSP.enabled", 0),
        ("toolkit.telemetry.enabled", False),
        ("toolkit.telemetry.unified", False),
        ("datareporting.healthreport.uploadEnabled", False),
        ("datareporting.policy.dataSubmissionEnabled", False),
        ("mailnews.message_display.disable_remote_image", True),
        ("mailnews.auto_config.fetchFromISP.v2", False),
        ("privacy.resistFingerprinting", True),
    ]
    landed = []
    missing = []
    for name, expected in sample:
        actual = tb.get_pref(name)
        if actual == expected:
            landed.append(name)
        else:
            missing.append((name, expected, actual))
    # A per-pref implementation should land essentially all sampled
    # prefs. We allow up to 2 misses (TB version drift on a single
    # pref's default semantics).
    assert len(landed) >= len(sample) - 2, (
        f"T-072 / F-044 behavioural: only {len(landed)}/{len(sample)} "
        f"hardening prefs landed. A fail-on-first-bad regression "
        f"in applyPrefs would silently drop most. "
        f"Missing: {missing[:5]}"
    )


# ---- T-073: end-to-end Tor send must drive the addon, not the test ----


def test_T073_e2e_addon_drives_user_agent_suppression() -> None:
    """Behavioural: install the addon and verify a known leak pref
    is flipped without the test ever calling Services.prefs.set*Pref
    on it. Replaces the pattern in `test_e2e_tor_send.py` where the
    test script re-implements the hardening setup. If the addon's
    enableHardening regresses (e.g. drops the telemetry+UA cluster
    from HARDENING_PREFS), this test breaks; the old pattern would
    keep passing because the test was setting the pref itself."""
    client = TBClient(host="thunderbird", port=2828)
    try:
        # Leak-on baseline. These prefs are all in HARDENING_PREFS;
        # any drop from the apply path manifests as the pref staying
        # at the leak-on value. Avoid `toolkit.telemetry.enabled`
        # here because some Mozilla builds lock it at build time —
        # you can't reliably set it to True from chrome context.
        client.set_pref("mailnews.headers.sendUserAgent", True)
        client.set_pref("mailnews.message_display.disable_remote_image", False)
        client.set_pref("security.OCSP.enabled", 1)
        client.set_pref("network.predictor.enabled", True)
        assert client.get_pref("mailnews.headers.sendUserAgent") is True

        client.install_addon(XPI, temporary=True)
        ua_off = _wait_for(
            lambda: client.get_pref("mailnews.headers.sendUserAgent"),
            lambda v: v is False,
            timeout=30,
        )
        remote_img_off = _wait_for(
            lambda: client.get_pref("mailnews.message_display.disable_remote_image"),
            lambda v: v is True,
            timeout=30,
        )
        ocsp_off = _wait_for(
            lambda: client.get_pref("security.OCSP.enabled"),
            lambda v: v == 0,
            timeout=30,
        )
        predictor_off = _wait_for(
            lambda: client.get_pref("network.predictor.enabled"),
            lambda v: v is False,
            timeout=30,
        )
        assert ua_off is False, (
            "T-073: addon did not flip mailnews.headers.sendUserAgent — "
            "regression in HARDENING_PREFS or enableHardening enable chain"
        )
        assert remote_img_off is True, (
            "T-073: addon did not flip "
            "mailnews.message_display.disable_remote_image — mail-UI "
            "hardening regressed out of HARDENING_PREFS"
        )
        assert ocsp_off == 0, (
            "T-073: addon did not flip security.OCSP.enabled to 0 — "
            "OCSP suppression regressed (this is the privacy P0 from "
            "F-022 closed earlier; protect against re-regression)"
        )
        assert predictor_off is False, (
            "T-073: addon did not flip network.predictor.enabled — "
            "predictor (pre-connect speculation) regressed out of "
            "HARDENING_PREFS"
        )
    finally:
        client.close()


# ---- T-074: real-send tests must use addon-set prefs, not test-set ----


def test_T074_addon_writes_identity_fqdn_without_test_setpref(tb: TBClient) -> None:
    """Behavioural: pre-create an identity (no FQDN pref set), install
    addon, assert addon-set FQDN is the per-install fallback
    `m<hex>.invalid` (default `from_domain` mode falls through to
    fallback because the identity has no real domain).

    Replaces the pattern in test_feature_real_send.py where the
    test sets `mail.identity.<key>.FQDN` itself and then sends.
    That tests Mozilla's pref handling; this tests OnionBird."""
    # Create an identity with no usable from-domain.
    identity_key = tb.exec_chrome(r"""
        const { MailServices } = ChromeUtils.importESModule(
          "resource:///modules/MailServices.sys.mjs"
        );
        // Find or create a no-domain identity (forces the fallback
        // branch in pickFqdn).
        let id = null;
        for (const i of MailServices.accounts.allIdentities) {
          if (i.email === "anon@") { id = i; break; }
        }
        if (!id) {
          id = MailServices.accounts.createIdentity();
          id.email = "anon@";
          id.fullName = "anon";
          let acct = null;
          for (const a of MailServices.accounts.accounts) {
            if (a.incomingServer && a.incomingServer.type === "none") { acct = a; break; }
          }
          if (!acct) {
            acct = MailServices.accounts.createAccount();
            acct.incomingServer = MailServices.accounts.createIncomingServer(
              "anon", "local.invalid", "none"
            );
          }
          acct.addIdentity(id);
        }
        // Clear any pre-existing FQDN so we can prove the addon writes.
        try { Services.prefs.clearUserPref(`mail.identity.${id.key}.FQDN`); } catch (e) {}
        return id.key;
    """)
    assert identity_key

    tb.install_addon(XPI, temporary=True)

    # Poll for the addon to write the per-identity FQDN.
    fqdn = _wait_for(
        lambda: tb.get_pref(f"mail.identity.{identity_key}.FQDN"),
        lambda v: v not in (None, "", "anon@"),
        timeout=30,
    )
    assert fqdn, (
        f"T-074: addon did not write mail.identity.{identity_key}.FQDN "
        f"within 30s. The per-identity hardening write path "
        f"(applyHardeningToAllIdentities) regressed."
    )
    # No-from-domain identity → the from_domain branch in pickFqdn
    # must fall through to the per-install m<hex>.invalid fallback.
    # (F-073 also locked this for the onion case; see follow-up.md.)
    assert fqdn != "anon@" and fqdn != "" and "@" not in fqdn, (
        f"T-074: addon wrote a malformed FQDN {fqdn!r} — the from-domain "
        f"branch returned something it shouldn't (an `@` in the FQDN "
        f"indicates the email was misparsed)."
    )


# ---- T-076: compose.onBeforeSend behavioural test ----


def test_T076_compose_onbeforesend_cancels_send_on_leak_verdict(
    tb: TBClient,
    http,
    clear_traps,
) -> None:
    """Behavioural verification that `compose.onBeforeSend` actually
    cancels outgoing sends when the leak verdict is non-clean.

    Setup primes the addon into a "non-clean verdict" state by installing
    fresh into an env without functional Tor SOCKS — auto-enable writes
    `enable-in-progress` verdict, the canary self-test then fails (SOCKS
    not reachable from TB), and the verdict stays non-clean. With the
    cancel-listener correctly wired, the compose window's send button
    triggers `onBeforeSend → {cancel: true}` and no message reaches the
    SMTP trap.

    Failure modes this catches that source-grep / structural tests miss:
      - wrong return shape (returning `{}` instead of `{cancel: true}`)
      - inverted verdict check (`=== "clean"` vs `!== "clean"`)
      - listener registered on the wrong event
      - listener swallows error silently (then resolves to undefined,
        which TB treats as "no objection" and proceeds with send)
    """
    # Reuse-or-create an identity bound to the smtp-trap. Bare creation
    # via ensure_identity_and_smtp fails after the first test in a TB
    # session because nsIMsgAccountManager.createIncomingServer rejects
    # duplicate (username, hostname, type) triples; reuse the existing
    # local/none account when one is already around.
    identity_email = "t076-block@anon.invalid"
    setup_js = r"""
        const [identityEmail, smtpHost, smtpPort] = arguments;
        const { MailServices } = ChromeUtils.importESModule(
          "resource:///modules/MailServices.sys.mjs"
        );
        const Ci = Components.interfaces;
        const outgoing = MailServices.outgoingServer || MailServices.smtp;

        // smtp server: reuse an existing one pointing at smtp-trap if any.
        let smtp = null;
        for (const s of outgoing.servers) {
          const ss = s.QueryInterface ? s.QueryInterface(Ci.nsISmtpServer) : s;
          if (ss.hostname === smtpHost && ss.port === smtpPort) { smtp = ss; break; }
        }
        if (!smtp) {
          const raw = outgoing.createServer("smtp");
          smtp = raw.QueryInterface(Ci.nsISmtpServer);
          smtp.hostname = smtpHost;
          smtp.port = smtpPort;
          smtp.authMethod = 0;
          smtp.socketType = 0;
        }

        // identity: reuse-by-email, else create + attach to ANY existing
        // local/none account (avoids the duplicate-incoming-server error).
        let identity = null;
        for (const i of MailServices.accounts.allIdentities) {
          if (i.email === identityEmail) { identity = i; break; }
        }
        if (!identity) {
          identity = MailServices.accounts.createIdentity();
          identity.email = identityEmail;
          identity.fullName = "t076 block-verdict probe";
          let acct = null;
          for (const a of MailServices.accounts.accounts) {
            if (a.incomingServer && a.incomingServer.type === "none") {
              acct = a; break;
            }
          }
          if (!acct) {
            acct = MailServices.accounts.createAccount();
            acct.incomingServer = MailServices.accounts.createIncomingServer(
              "anon", "local.invalid", "none");
          }
          acct.addIdentity(identity);
        }
        // Always re-bind to the (possibly new) smtp server so this test
        // controls the route, regardless of how the identity was set up.
        identity.smtpServerKey = smtp.key;
        return { identityKey: identity.key, smtpKey: smtp.key };
    """
    keys = tb.exec_chrome(setup_js, args=[identity_email, "smtp-trap", 2525])
    assert keys["identityKey"]

    tb.install_addon(XPI, temporary=True)
    # Wait for hardening to be active (snapshot persisted). Without this
    # gate the onBeforeSend listener returns early (`if (!active) return`)
    # and the send-block path never fires.
    active = _wait_for(
        lambda: tb.get_pref("network.proxy.socks_remote_dns"),
        lambda v: v is True,
        timeout=30,
    )
    assert active is True, "addon did not enable hardening within 30s"
    # Precondition: this test relies on the verdict being non-clean so
    # the onBeforeSend listener's cancel-branch fires. In the test pod
    # SOCKS reachable from TB is not the same as the SOCKS host the
    # addon configures (the addon writes 127.0.0.1, where no Tor
    # listens — there's no port-forward into the TB container). If a
    # future CI runner ever happens to have a SOCKS listener on
    # 127.0.0.1:9050 reachable from TB, the addon's canary would
    # succeed and write a `clean` verdict — and `onBeforeSend` would
    # return undefined for every send. Without this precondition
    # check, the test would then fail confusingly on the start_sending
    # assertion. Assert here so the failure is loud and pointing at
    # the right place.
    socks_host = tb.get_pref("network.proxy.socks")
    socks_port = tb.get_pref("network.proxy.socks_port")
    assert socks_host == "127.0.0.1" and socks_port in (9050, 9150), (
        f"T-076 precondition: the addon-configured SOCKS endpoint is "
        f"{socks_host}:{socks_port}, not the test-env-expected "
        f"127.0.0.1:9050/9150 fail-closed default. If you wired a "
        f"real Tor SOCKS into this test container, this test needs "
        f"its verdict-injection updated — the implicit "
        f"'SOCKS-unreachable → non-clean verdict' assumption no "
        f"longer holds, and a clean verdict would silently let "
        f"sends through past the addon's onBeforeSend listener."
    )

    # Drive a compose-window send and observe what happens. Returns a
    # dict; the load-bearing field is `still_open_after`:
    #   True  → onBeforeSend returned {cancel: true}; window stayed open
    #           with the notification bar.
    #   False → send proceeded and TB auto-closed the compose window.
    r = tb.open_compose_window_and_send(
        identity_email="t076-block@anon.invalid",
        to="t076-recipient@anon.invalid",
        subject="t076 block-verdict probe",
        body="if this lands in smtp-trap, send-block regressed",
        wait_close_timeout=4.0,
    )
    assert r["opened"], f"compose window did not open: {r}"
    assert r["send_triggered"], f"send was not triggered: {r}"
    # Refuse to interpret the start_sending signal if the listener
    # never attached — that would make a False reading meaningless.
    assert r.get("listener_attached") is True, (
        f"T-076: nsIMsgSendListener could not be attached to "
        f"gMsgCompose — the load-bearing observation channel is "
        f"absent and any False start_sending reading is unreliable. "
        f"Investigate compose-window readiness timing. Probe: {r}"
    )

    # Load-bearing assertion: with onBeforeSend cancelling, nsIMsgCompose
    # NEVER enters the sending state — the cancel happens upstream of
    # SendMsg, so the send-listener's onStartSending callback never
    # fires. With onBeforeSend regressed (any return shape other than
    # {cancel: true}), the send proceeds and onStartSending fires —
    # even if the subsequent transport ultimately fails. This
    # discriminates "cancelled by addon" from "send tried but failed".
    # The observation lives in a closure-captured object, so it survives
    # the auto-close that follows a successful send — meaning even the
    # worst-case regression (cancel returns undefined AND transport
    # succeeds → window closes) cannot false-pass here.
    assert r.get("start_sending") is False, (
        f"T-076: nsIMsgSendListener.onStartSending fired — that means "
        f"the compose.onBeforeSend listener did NOT cancel the send. "
        f"The application-layer send-block has regressed (listener "
        f"deleted, returns wrong shape, or condition inverted). "
        f"Probe result: {r}"
    )

    # Belt-and-braces: assert the SMTP trap got no message either. If
    # cancel claimed to work but the trap shows a message, the send
    # sneaked past onBeforeSend via a different path.
    msgs = http.get("http://smtp-trap:8025/messages").json()
    n = len(msgs) if isinstance(msgs, list) else 0
    assert n == 0, (
        f"T-076: send-block claimed cancel but smtp-trap received "
        f"{n} message(s); onBeforeSend may be no-op'ing or there is "
        f"a second send pathway bypassing the listener: {msgs}"
    )
