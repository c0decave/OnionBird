"""End-to-end UI tests for the Options page — drives the real addon
via Marionette content context (opens the options page in a tab,
finds DOM elements, clicks buttons, observes status text).

Coverage targets every Options section: SOCKS override (happy, sad,
edge, fuzzy), Run Tor test, hardening enable/disable, FQDN modes,
theme, help mode.

These tests catch the "structural tests are green but the plugin
doesn't work" failure mode — they exercise the actual JS code paths
the user triggers when clicking buttons in their Thunderbird.
"""
from __future__ import annotations

import socket
import time

import pytest

from helpers.tb_client import TBClient

XPI = "/build/onionbird.xpi"


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    # Always restore chrome context before close (otherwise next test's
    # reset_global_prefs runs in content context and breaks).
    try:
        client.m.set_context(client.m.CONTEXT_CHROME)
    except Exception:
        pass
    client.close()


@pytest.fixture
def options(tb: TBClient):
    """Install the addon and open its Options page; yield (tb, addon_id).
    Tears down by closing the tab and restoring chrome context.
    """
    addon_id = tb.install_addon(XPI, temporary=True)
    # Auto-enable runs immediately on install; give it a moment to
    # settle so the options page loads against a stable storage state.
    time.sleep(1.0)
    tb.open_addon_page(addon_id, "ui/options.html")
    # Page may be loading async data (loadSocksOverride, refreshStatus,
    # loadFqdnPrefs). Give it a beat.
    time.sleep(0.5)
    yield tb, addon_id
    tb.close_addon_page()


@pytest.fixture
def tor_ip() -> str:
    ip = socket.gethostbyname("tor")
    assert ip and ip != "tor", f"tor container not resolvable; got {ip!r}"
    return ip


# ===========================================================================
# Sanity: infrastructure
# ===========================================================================


def test_options_page_loads_and_h1_renders(options) -> None:
    """Baseline: the options page actually opens and the title renders.
    If this fails, every other E2E test is meaningless — first verify
    the infrastructure works."""
    tb, _ = options
    assert tb.text("h1").strip() == "onionbird"


# ===========================================================================
# SOCKS override
# ===========================================================================


def test_e2e_socks_override_save_happy_path(options, tor_ip) -> None:
    """Type host + port → click Save → status shows OK → prefs persisted.

    This is the path the user runs daily. If THIS doesn't work, nothing else
    matters."""
    tb, _ = options
    tb.set_input("#socks-override-host", tor_ip)
    tb.set_input("#socks-override-port", "9050")
    tb.click("#socks-override-save")
    tb.wait_for_text(
        "#socks-override-status",
        lambda txt: "OK" in txt or "ok" in txt.lower(),
        timeout=8.0,
        label="save OK",
    )
    # Verify the prefs were actually written.
    saved_host = tb.get_pref("onionbird.socks.host")
    saved_port = tb.get_pref("onionbird.socks.port")
    assert saved_host == tor_ip, f"override host not persisted: {saved_host!r}"
    assert saved_port == 9050, f"override port not persisted: {saved_port!r}"


def test_e2e_socks_override_invalid_host_sad_path(options) -> None:
    """A non-IP-literal, non-loopback host (DNS name) must be rejected
    with the InvalidHost status — DNS-resolvable names leak via the
    system resolver before reaching Tor."""
    tb, _ = options
    tb.set_input("#socks-override-host", "evil.example.com")
    tb.set_input("#socks-override-port", "9050")
    tb.click("#socks-override-save")
    status = tb.wait_for_text(
        "#socks-override-status",
        lambda txt: "invalid" in txt.lower() or "ungültig" in txt.lower(),
        timeout=5.0,
        label="invalid-host rejection",
    )
    assert "host" in status.lower() or "ipv" in status.lower(), (
        f"InvalidHost message expected; got: {status!r}"
    )


def test_e2e_socks_override_invalid_port_sad_path(options) -> None:
    """Port outside 1..65535 must be rejected with InvalidPort status —
    NOT InvalidHost (that was F-176's regression)."""
    tb, _ = options
    tb.set_input("#socks-override-host", "127.0.0.1")
    # Port 0 — Number.isFinite(0)===true but the bounds check rejects.
    tb.set_input("#socks-override-port", "0")
    tb.click("#socks-override-save")
    status = tb.wait_for_text(
        "#socks-override-status",
        lambda txt: "invalid" in txt.lower() or "ungültig" in txt.lower(),
        timeout=5.0,
        label="invalid-port rejection",
    )
    assert "port" in status.lower(), (
        f"F-176: InvalidPort message expected (NOT InvalidHost); got: {status!r}"
    )


def test_e2e_socks_override_partial_edit_uses_placeholder_fallback(
    options, tor_ip
) -> None:
    """F-177 v2: user types only the host (port left empty); Save must
    fall back to the port placeholder ("9050") and succeed."""
    tb, _ = options
    tb.set_input("#socks-override-host", tor_ip)
    tb.set_input("#socks-override-port", "")  # blank
    tb.click("#socks-override-save")
    tb.wait_for_text(
        "#socks-override-status",
        lambda txt: "ok" in txt.lower(),
        timeout=5.0,
        label="partial edit OK",
    )
    # The port input should have been reflected back to 9050 (so the
    # user sees what was persisted). Use the input's .value PROPERTY,
    # not the HTML attribute — JS sets .value directly.
    port_val = tb.input_value("#socks-override-port")
    assert port_val == "9050", (
        f"F-177 v2: port input should reflect the fallback default 9050 "
        f"after Save; got {port_val!r}"
    )
    assert tb.get_pref("onionbird.socks.port") == 9050


def test_e2e_socks_override_both_empty_is_rejected(options) -> None:
    """F-177 v2 safety: Save with BOTH inputs empty must NOT silently
    pin 127.0.0.1:9050 (that would disable the auto-detect ladder for
    users on Tor-Browser-bundle 9150)."""
    tb, _ = options
    tb.set_input("#socks-override-host", "")
    tb.set_input("#socks-override-port", "")
    tb.click("#socks-override-save")
    status = tb.wait_for_text(
        "#socks-override-status",
        lambda txt: "invalid" in txt.lower() or "ungültig" in txt.lower(),
        timeout=5.0,
        label="both-empty rejection",
    )
    # Override prefs must NOT be set.
    saved_host = tb.get_pref("onionbird.socks.host")
    assert not saved_host, (
        f"F-177 v2 P0-1 regression: both-empty Save silently pinned "
        f"host={saved_host!r}. The auto-detect ladder is now disabled."
    )


def test_e2e_socks_override_test_endpoint_against_real_tor(
    options, tor_ip
) -> None:
    """Type the test pod's Tor (172.30.x.x:9050) → click Test endpoint →
    status must transition to OK. This proves end-to-end:
      - F-168 I-1 userProbe bypass works (non-loopback IP literal accepted)
      - F-178 TextEncoder polyfill works (SOCKS5 RESOLVE succeeds)
      - Tor in the test pod is reachable from TB
    """
    tb, _ = options
    tb.set_input("#socks-override-host", tor_ip)
    tb.set_input("#socks-override-port", "9050")
    tb.click("#socks-override-test")
    # Probe takes a few seconds (SOCKS5 handshake + RESOLVE).
    status = tb.wait_for_text(
        "#socks-override-status",
        lambda txt: "ok" in txt.lower() or "error" in txt.lower() or "fail" in txt.lower(),
        timeout=20.0,
        label="test endpoint result",
    )
    assert "ok" in status.lower(), (
        f"E2E test endpoint failed against test pod Tor at {tor_ip}:9050. "
        f"Status: {status!r}. Possible causes (in priority order): "
        f"(1) F-178 regression: 'TextEncoder' in status → polyfill missing. "
        f"(2) F-168 I-1 regression: 'not allowed' in status → userProbe bypass missing. "
        f"(3) Tor not running in test pod (check `docker ps | grep t0_tor`)."
    )


def test_e2e_socks_override_reset_clears_inputs_and_prefs(
    options, tor_ip
) -> None:
    """After Save then Reset: inputs go empty, status says Reset, prefs cleared."""
    tb, _ = options
    # Pre-save an override.
    tb.set_input("#socks-override-host", tor_ip)
    tb.set_input("#socks-override-port", "9050")
    tb.click("#socks-override-save")
    tb.wait_for_text(
        "#socks-override-status",
        lambda txt: "ok" in txt.lower(),
        timeout=5.0,
        label="pre-reset save",
    )
    # Now Reset.
    tb.click("#socks-override-reset")
    tb.wait_for_text(
        "#socks-override-status",
        lambda txt: "clear" in txt.lower() or "reset" in txt.lower()
        or "gelöscht" in txt.lower() or "auto" in txt.lower(),
        timeout=5.0,
        label="reset status",
    )
    # F-177 v2: inputs MUST be empty after Reset (no silent pin-to-default).
    host_val = tb.input_value("#socks-override-host")
    port_val = tb.input_value("#socks-override-port")
    assert host_val == "" or host_val is None, (
        f"F-177 v2 P0-1: Reset must leave host input empty (the pre-fix "
        f"v1 left '127.0.0.1' which made the next Save silently pin port "
        f"9050). Got host={host_val!r}"
    )
    assert port_val == "" or port_val is None, (
        f"F-177 v2 P0-1: Reset must leave port input empty. Got port={port_val!r}"
    )
    # Prefs must be cleared.
    cleared_host = tb.get_pref("onionbird.socks.host")
    cleared_port = tb.get_pref("onionbird.socks.port")
    assert not cleared_host, f"override host not cleared: {cleared_host!r}"
    assert not cleared_port, f"override port not cleared: {cleared_port!r}"


# ===========================================================================
# Run Tor test mode
# ===========================================================================


def test_e2e_run_tor_test_picks_user_override(options, tor_ip) -> None:
    """The Tor-test-mode ladder probes the user-override first. With F-180,
    a saved override at test-pod Tor (172.30.x.x:9050) must succeed and
    the badge transitions to "available"."""
    tb, _ = options
    # Save override first.
    tb.set_input("#socks-override-host", tor_ip)
    tb.set_input("#socks-override-port", "9050")
    tb.click("#socks-override-save")
    tb.wait_for_text(
        "#socks-override-status",
        lambda txt: "ok" in txt.lower(),
        timeout=5.0,
        label="override saved",
    )
    # Now trigger Run Tor test.
    tb.click("#run-tor-test")
    # The ladder probes several candidates; can take ~30s if some fail.
    badge_text = tb.wait_for_text(
        "#tor-test-badge",
        lambda txt: "available" in txt.lower() and "unavailable" not in txt.lower(),
        timeout=60.0,
        label="tor test badge available",
    )
    # Verify the chosen endpoint was the user-override (not a fallback).
    endpoint = tb.text("#tor-test-endpoint")
    assert tor_ip in endpoint, (
        f"F-180: Run Tor test reported available but the chosen endpoint "
        f"doesn't include the user-override IP ({tor_ip}). Endpoint: "
        f"{endpoint!r}. The userProbe bypass in detectSocksConfig is broken "
        f"OR a fallback candidate succeeded somehow."
    )


# ===========================================================================
# Theme controls
# ===========================================================================


@pytest.mark.parametrize("theme", ["light", "dark", "system"])
def test_e2e_theme_toggle(options, theme) -> None:
    """Click each theme button → data-theme attribute updates (or is
    cleared for 'system'), aria-pressed reflects."""
    tb, _ = options
    tb.click(f'[data-theme-choice="{theme}"]')
    # Allow the click handler + storeTheme to run.
    time.sleep(0.2)
    pressed = tb.attr(f'[data-theme-choice="{theme}"]', "aria-pressed")
    assert pressed == "true", (
        f"theme button {theme!r} should be aria-pressed=true after click; "
        f"got {pressed!r}"
    )
    html_theme = tb.attr("html", "data-theme")
    if theme == "system":
        assert html_theme in (None, ""), (
            f"system theme should clear <html data-theme>; got {html_theme!r}"
        )
    else:
        assert html_theme == theme, (
            f"<html data-theme> should be {theme!r}; got {html_theme!r}"
        )


# ===========================================================================
# Help mode
# ===========================================================================


@pytest.mark.parametrize("mode", ["tldr", "nerd"])
def test_e2e_help_mode_toggle(options, mode) -> None:
    """Switching help mode re-renders the help content section."""
    tb, _ = options
    tb.click(f'[data-help-mode="{mode}"]')
    time.sleep(0.2)
    pressed = tb.attr(f'[data-help-mode="{mode}"]', "aria-pressed")
    assert pressed == "true"
    # The help-content container should have at least one <h3> after render.
    header_count = tb.element_count("#help-content h3")
    assert header_count >= 1, (
        f"help-content should render at least one section header for "
        f"mode={mode!r}; found {header_count}"
    )


# ===========================================================================
# Message-ID FQDN
# ===========================================================================


@pytest.mark.parametrize(
    "mode,expected_pref",
    [
        ("from_domain", "from_domain"),
        ("localhost", "localhost"),
        ("localhost.localdomain", "localhost.localdomain"),
    ],
)
def test_e2e_fqdn_mode_save(options, mode, expected_pref) -> None:
    """Pick FQDN mode → click Save → status OK → onionbird pref reflects."""
    tb, _ = options
    tb.select_option("#fqdn-mode", mode)
    tb.click("#fqdn-save")
    tb.wait_for_text(
        "#fqdn-status",
        lambda txt: "saved" in txt.lower() or "ok" in txt.lower(),
        timeout=5.0,
        label=f"FQDN mode {mode} save",
    )
    saved = tb.get_pref("onionbird.messageid.fqdn_mode")
    assert saved == expected_pref, (
        f"FQDN mode pref expected {expected_pref!r}; got {saved!r}"
    )


def test_e2e_fqdn_custom_mode_with_valid_domain(options) -> None:
    """Custom mode with a real domain → save → pref reflects."""
    tb, _ = options
    tb.select_option("#fqdn-mode", "custom")
    # The custom input becomes visible only after the mode change event.
    time.sleep(0.2)
    tb.set_input("#fqdn-custom", "anonymous.invalid")
    tb.click("#fqdn-save")
    tb.wait_for_text(
        "#fqdn-status",
        lambda txt: "saved" in txt.lower() or "ok" in txt.lower(),
        timeout=5.0,
        label="custom FQDN save",
    )
    assert tb.get_pref("onionbird.messageid.fqdn_mode") == "custom"
    assert tb.get_pref("onionbird.messageid.fqdn_custom") == "anonymous.invalid"


# ===========================================================================
# Canary self-test (leak detection)
# ===========================================================================


def test_e2e_run_self_test_returns_verdict(options) -> None:
    """User reported: clicking 'Run self-test' with the default host
    `check.torproject.org` produced the error 'invalid SOCKS host: <invalid>'
    in BOTH verdict and error fields. This test reproduces the exact
    user gesture — open Options, click #run-self-test, wait, read
    #canary-verdict — and asserts the verdict is NOT an unhandled
    'invalid' error.

    Acceptable verdicts (the canary can legitimately fail in the
    test-pod environment): clean, leak, divergence, inconclusive
    (network/timeout). What's NOT acceptable: a coding-error message
    like 'invalid SOCKS host: <invalid>' bubbling up to the UI."""
    tb, _ = options
    tb.click("#run-self-test")
    # Self-test does 3 SOCKS5 RESOLVE round-trips; budget generously.
    tb.wait_for_text(
        "#canary-verdict",
        lambda t: t and t.strip() not in ("", "—") and "no data yet" not in t.lower(),
        timeout=45.0,
        label="canary verdict populated",
    )
    verdict = tb.text("#canary-verdict")
    error = tb.text("#canary-error")
    assert "<invalid>" not in verdict and "<invalid>" not in error, (
        f"F-182: canary self-test bubbled up an internal validation "
        f"error. The user clicked Run self-test from a fresh Options "
        f"page and got 'invalid SOCKS host: <invalid>'. Verdict={verdict!r}, "
        f"error={error!r}. This indicates a non-string SOCKS host is "
        f"reaching normalizeSocksHost — investigate the runSelfTest "
        f"path in implementation.js around line 1995."
    )


# ===========================================================================
# Hardening enable / disable
# ===========================================================================


def test_e2e_enable_hardening_with_user_override(options, tor_ip) -> None:
    """End-to-end happy path: save user-override → Enable hardening →
    network.proxy.socks pref reflects the override, hardeningActive=true.

    This is the path that ALSO depends on F-180 — enableHardening calls
    detectSocksConfig which needs the userProbe bypass for the
    user-override candidate."""
    tb, _ = options
    # 1. Save override.
    tb.set_input("#socks-override-host", tor_ip)
    tb.set_input("#socks-override-port", "9050")
    tb.click("#socks-override-save")
    tb.wait_for_text(
        "#socks-override-status",
        lambda t: "ok" in t.lower(),
        timeout=5.0,
        label="save",
    )
    # 2. Enable hardening.
    tb.click("#enable")
    # Wait for the log to show completion. The log gets a "done" or
    # "warnings" line at the end, plus a JSON dump.
    tb.wait_for_text(
        "#log",
        lambda t: "done" in t.lower() or "warning" in t.lower() or '"ok":true' in t,
        timeout=30.0,
        label="enable hardening complete",
    )
    # 3. Verify the override was honoured: TB's network.proxy.socks must
    # match the override IP. Without F-180 this would silently fall back.
    saved_host = tb.get_pref("network.proxy.socks")
    saved_port = tb.get_pref("network.proxy.socks_port")
    assert saved_host == tor_ip, (
        f"F-180 end-to-end: enable hardening with user-override "
        f"{tor_ip}:9050 did not write the override into network.proxy.socks. "
        f"Got host={saved_host!r}, port={saved_port!r}. The detectSocksConfig "
        f"gate is rejecting the user-override candidate."
    )
    assert saved_port == 9050


def test_e2e_enable_applies_all_critical_hardening_prefs(options, tor_ip) -> None:
    """README claims 100% Tor + DNS through Tor + no fingerprint headers.
    After Enable hardening, every load-bearing pref must reflect those
    claims. This test enumerates the critical ones and asserts.
    """
    tb, _ = options
    tb.set_input("#socks-override-host", tor_ip)
    tb.set_input("#socks-override-port", "9050")
    tb.click("#socks-override-save")
    tb.wait_for_text(
        "#socks-override-status",
        lambda t: "ok" in t.lower(),
        timeout=5.0,
        label="save",
    )
    tb.click("#enable")
    tb.wait_for_text(
        "#log",
        lambda t: "done" in t.lower() or "warning" in t.lower() or '"ok":true' in t,
        timeout=30.0,
        label="enable",
    )
    # Each (pref, expected, README-claim-tag) tuple.
    expected = [
        ("network.proxy.type", 1, "SOCKS proxy enabled"),
        ("network.proxy.socks", tor_ip, "override applied"),
        ("network.proxy.socks_port", 9050, "override port applied"),
        ("network.proxy.socks_version", 5, "SOCKS5"),
        ("network.proxy.socks_remote_dns", True, "DNS through Tor only"),
        ("network.proxy.failover_direct", False, "fail closed if proxy unreachable"),
        ("mailnews.headers.sendUserAgent", False, "no User-Agent header"),
        ("calendar.useragent.extra", "", "no Calendar UA leak"),
        ("privacy.resistFingerprinting", True, "Date UTC + locale spoof"),
        ("network.dns.disableIPv6", True, "IPv6 disabled (TB SOCKS IPv6 bugs)"),
        ("network.trr.mode", 5, "DoH off (defense-in-depth DNS)"),
        ("media.peerconnection.enabled", False, "no WebRTC"),
        ("network.dns.disablePrefetch", True, "no DNS prefetch"),
        ("network.predictor.enabled", False, "no network predictor"),
        ("network.prefetch-next", False, "no prefetch"),
        ("geo.enabled", False, "no geolocation"),
        ("security.OCSP.enabled", 0, "no clearnet OCSP"),
        ("browser.safebrowsing.malware.enabled", False, "no Safebrowsing"),
        ("browser.safebrowsing.phishing.enabled", False, "no phishing-check beacons"),
        ("network.captive-portal-service.enabled", False, "no captive-portal probes"),
        ("network.connectivity-service.enabled", False, "no connectivity beacons"),
        ("app.update.enabled", False, "no app update phone-home"),
        ("services.sync.enabled", False, "Sync/FxA locked off"),
        ("identity.fxaccounts.enabled", False, "FxA off"),
        ("extensions.blocklist.enabled", False, "no blocklist beacon"),
        ("breakpad.reportURL", "", "no crash-report clearnet beacon"),
    ]
    failures = []
    for pref, want, claim in expected:
        got = tb.get_pref(pref)
        if got != want:
            failures.append(f"  {pref!r} = {got!r}, expected {want!r}  ←  {claim}")
    assert not failures, (
        "Hardening claims NOT held in TB prefs after Enable:\n"
        + "\n".join(failures)
    )


def test_e2e_disable_hardening_restores_prefs_from_snapshot(options, tor_ip) -> None:
    """README claim: "Hardening is reversible. Snapshot taken before
    first enable, restored on disable."

    Note on baseline: the fixture installs the addon temporarily, which
    triggers auto-enable. So by the time the test starts, hardening
    prefs are already applied. We can't observe a true "user's
    pre-addon state" in the test pod. Instead we verify the
    snapshot+restore PRIMITIVE works end-to-end by:
      1. Disable now (snapshot was already taken at auto-enable) →
         records "snapshot baseline" prefs.
      2. Re-enable → prefs flip to hardened (or stay if were hardened).
      3. Disable again with confirm → assert prefs match the baseline
         captured in step 1.
    This proves disable consistently restores to the same snapshot,
    which is what "reversible" means in the README.
    """
    tb, _ = options
    sample_prefs = [
        "network.proxy.type",
        "network.proxy.socks_remote_dns",
        "mailnews.headers.sendUserAgent",
        "privacy.resistFingerprinting",
        "media.peerconnection.enabled",
        "geo.enabled",
        "security.OCSP.enabled",
        "browser.safebrowsing.malware.enabled",
    ]

    # 1. Disable so we observe snapshot-baseline values.
    tb.auto_dismiss_dialogs()
    tb.click("#disable")
    tb.wait_for_text(
        "#log",
        lambda t: "restoring" in t.lower() or "done" in t.lower(),
        timeout=30.0,
        label="initial disable",
    )
    baseline = {p: tb.get_pref(p) for p in sample_prefs}

    # 2. Save override + re-enable.
    tb.set_input("#socks-override-host", tor_ip)
    tb.set_input("#socks-override-port", "9050")
    tb.click("#socks-override-save")
    tb.wait_for_text(
        "#socks-override-status",
        lambda t: "ok" in t.lower(),
        timeout=5.0,
        label="save",
    )
    tb.click("#enable")
    tb.wait_for_text(
        "#log",
        lambda t: "done" in t.lower() or "warning" in t.lower() or '"ok":true' in t,
        timeout=30.0,
        label="re-enable",
    )
    # Sanity: hardening should now produce values that differ from
    # baseline (at minimum proxy.type=1).
    assert tb.get_pref("network.proxy.type") == 1, (
        "re-enable did not flip network.proxy.type to 1 (SOCKS)"
    )

    # 3. Disable again → must restore to baseline.
    tb.click("#disable")
    tb.wait_for_text(
        "#log",
        lambda t: t.count("done") >= 1 or t.count("ok") >= 1 or "restoring" in t.lower(),
        timeout=30.0,
        label="final disable",
    )
    drift = []
    for p in sample_prefs:
        now = tb.get_pref(p)
        if now != baseline[p]:
            drift.append(f"  {p!r}: snapshot={baseline[p]!r}, restored={now!r}")
    assert not drift, (
        "README claim 'Hardening is reversible' broken: Disable did "
        "not restore to the snapshot baseline observed after the prior "
        "Disable. Snapshot+restore is lossy:\n" + "\n".join(drift)
    )


def test_e2e_disable_restores_explicit_known_snapshot(options, tor_ip) -> None:
    """README claim: 'Hardening is reversible. Snapshot taken before
    first enable, restored on disable.'

    Defense-in-depth (F-185, layer C): the cycle-based test above
    (test_e2e_disable_hardening_restores_prefs_from_snapshot) is
    pollution-relative — it captures whatever baseline the addon happens
    to have snapshotted at auto-enable and proves the second cycle
    matches the first. That misses the case where BOTH cycles converge
    to a polluted snapshot.

    This test makes the baseline FULLY EXPLICIT: disable to clear any
    existing snapshot, set known user-prefs to non-default values, then
    enable (snapshot now captures those known values), then disable and
    assert the restored prefs are exactly the known values. No
    dependency on what other tests put in storage.local."""
    tb, _ = options
    # Hardened-mode values for these prefs are (True, False, True). The
    # known baseline MUST differ from hardened so a restore that
    # silently no-ops (prefs left at hardened state) is detectable. We
    # use the TB defaults (False, True, False) — after enable they
    # flip to hardened, after disable the snapshot/restore primitive
    # MUST flip them back. A skipped restorePrefs would leave them
    # hardened and this assertion catches it.
    known_baseline = {
        "network.proxy.socks_remote_dns": False,
        "mailnews.headers.sendUserAgent": True,
        "privacy.resistFingerprinting": False,
    }

    # Step 1: disable to clear any inherited snapshot.
    tb.auto_dismiss_dialogs()
    tb.click("#disable")
    tb.wait_for_text(
        "#log",
        lambda t: "restoring" in t.lower() or "done" in t.lower(),
        timeout=30.0,
        label="pre-clear disable",
    )
    time.sleep(1.0)

    # Step 2: set the user prefs to the known baseline. These will be
    # the values enable() snapshots from.
    for p, v in known_baseline.items():
        tb.set_pref(p, v)

    # Step 3: SOCKS override + enable. enable() takes a fresh snapshot
    # because step 1 cleared any prior one.
    tb.set_input("#socks-override-host", tor_ip)
    tb.set_input("#socks-override-port", "9050")
    tb.click("#socks-override-save")
    tb.wait_for_text(
        "#socks-override-status",
        lambda t: "ok" in t.lower(),
        timeout=5.0,
        label="save",
    )
    tb.click("#enable")
    tb.wait_for_text(
        "#log",
        lambda t: "done" in t.lower() or "warning" in t.lower() or '"ok":true' in t,
        timeout=30.0,
        label="enable",
    )

    # Step 4: disable and assert prefs match known_baseline.
    tb.click("#disable")
    tb.wait_for_text(
        "#log",
        lambda t: t.count("done") >= 1 or t.count("ok") >= 1,
        timeout=30.0,
        label="final disable",
    )
    time.sleep(1.0)
    drift = []
    for p, want in known_baseline.items():
        got = tb.get_pref(p)
        if got != want:
            drift.append(f"  {p!r}: known_baseline={want!r}, restored={got!r}")
    assert not drift, (
        "snapshot/restore primitive is broken: an explicit baseline was "
        "set, enable() snapshotted it, disable() should restore exactly "
        "those values:\n" + "\n".join(drift)
    )


def test_e2e_log_does_not_contain_plain_ip_or_full_hostname(
    options, tor_ip
) -> None:
    """README claim: 'Privacy-safe diagnostics. Options-page command
    logs and notifications redact IPs, hostnames, and secrets.' Verify
    the #log textContent after enable doesn't leak the configured
    Tor IP, full hostnames, or any look-alike.

    Loopback IPs (127.0.0.1, ::1, localhost) are allowed verbatim —
    they're not user-identifying. The configured non-loopback IP
    (here the test pod's tor_ip) MUST be redacted to '<configured>'."""
    tb, _ = options
    tb.set_input("#socks-override-host", tor_ip)
    tb.set_input("#socks-override-port", "9050")
    tb.click("#socks-override-save")
    tb.wait_for_text(
        "#socks-override-status",
        lambda t: "ok" in t.lower(),
        timeout=5.0,
        label="save",
    )
    tb.click("#enable")
    tb.wait_for_text(
        "#log",
        lambda t: "done" in t.lower() or "warning" in t.lower() or '"ok":true' in t,
        timeout=30.0,
        label="enable",
    )
    log_text = tb.text("#log")
    assert tor_ip not in log_text, (
        f"PRIVACY LEAK: the configured Tor IP {tor_ip!r} appears in "
        f"plaintext in the #log textContent. README claims 'logs and "
        f"notifications redact IPs'. Got log:\n{log_text[:600]}"
    )
    # 'check.torproject.org' is a common probe target — it shouldn't
    # appear verbatim either (would tell anyone reading a support log
    # that the user pinged Tor's check service from this machine).
    assert "check.torproject.org" not in log_text, (
        f"PRIVACY LEAK: the canary probe target appears in the log. "
        f"Log:\n{log_text[:600]}"
    )


def test_e2e_fqdn_custom_mode_with_invalid_domain_rejected(options) -> None:
    """Custom mode with bare-numeric / single-label domain → rejected
    (isValidMessageIdFqdn enforces multi-label + valid chars)."""
    tb, _ = options
    tb.select_option("#fqdn-mode", "custom")
    time.sleep(0.2)
    tb.set_input("#fqdn-custom", "notadomain")  # single label
    tb.click("#fqdn-save")
    status = tb.wait_for_text(
        "#fqdn-status",
        lambda txt: (
            "invalid" in txt.lower()
            or "ungültig" in txt.lower()
            or "must be" in txt.lower()
            or "valid" in txt.lower()
        ),
        timeout=5.0,
        label="invalid FQDN rejection",
    )
    assert status, "expected non-empty rejection status"
    # And the pref must NOT have been written.
    saved_mode = tb.get_pref("onionbird.messageid.fqdn_mode")
    assert saved_mode != "custom" or tb.get_pref(
        "onionbird.messageid.fqdn_custom"
    ) != "notadomain", "invalid FQDN value was silently persisted"
