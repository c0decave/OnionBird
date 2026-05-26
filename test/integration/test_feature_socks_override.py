"""User-configurable SOCKS endpoint override (F-168 follow-up feature).

Until this feature the addon picked the SOCKS endpoint from Thunderbird's
existing `network.proxy.socks` / `socks_port` prefs (or, when none were
set, fell back to the 127.0.0.1:9050 → :9150 probe ladder). Users on
Whonix, Tails-via-non-default, or custom Tor configurations had no way
to point the addon at their SOCKS endpoint without manually editing
about:config — which the addon was *then* overwriting on next enable.

This file covers the user-override surface end-to-end:

  - Storage: `onionbird.socks.host` + `onionbird.socks.port` are in
    the addon-owned pref allowlist (so setPref(...) from the Options
    page accepts them).
  - Validation: the override-resolution path in `enableHardening`
    rejects DNS-resolvable hostnames (other than `localhost`) at READ
    time and falls back to the auto-detect ladder. This protects the
    invariant even when the pref was written outside the addon's API
    (manual about:config edit, other addons, stale value from a
    previous install).
  - Override resolution: when valid override prefs are set,
    `enableHardening` uses them instead of the auto-detect ladder.
  - API surface: `browser.onionbird.setSocksOverride(field, value)`
    exists in the schema for the Options page's Save handler.
  - Behavioural: the test pod's `tor:9050` endpoint, plumbed through
    the override, makes the addon's canary self-test verify clean and
    SMTP send actually reaches `smtp-trap`.

Tests that read source files (structural) are cheaper than Marionette
round-trips and catch the most common regression class
(constant-rename, deleted-handler, wrong-allowlist). The behavioural
test layered on top catches wiring regressions that source-grep can't.
"""
from __future__ import annotations

import json
import re

import pytest
from helpers.tb_client import TBClient

XPI = "/build/onionbird.xpi"

ADDON_IMPL_PATH = "/addon/experiments/onionbird/implementation.js"
ADDON_SCHEMA_PATH = "/addon/experiments/onionbird/schema.json"
ADDON_BG_PATH = "/addon/background.js"
ADDON_OPTIONS_JS_PATH = "/addon/ui/options.js"
ADDON_OPTIONS_HTML_PATH = "/addon/ui/options.html"


def _read(p: str) -> str:
    with open(p, encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


# ---- Test 1: storage — addon-owned-pref allowlist accepts the override names ----


def test_F168_socks_override_prefs_in_addon_owned_allowlist() -> None:
    """`browser.onionbird.setPref(name, value)` accepts only names in
    ADDON_OWNED_PREF_NAMES. The Options-page Save handler writes the
    user-override via setPref (or via setSocksOverride which is the
    safer wrapper); either way the names must be in the allowlist or
    every Save call silently no-ops with a denied-warning."""
    impl = _read(ADDON_IMPL_PATH)
    m = re.search(
        r"const ADDON_OWNED_PREF_NAMES = new Set\(\[([^\]]+)\]\);",
        impl,
        re.MULTILINE | re.DOTALL,
    )
    assert m, "F-168: could not locate ADDON_OWNED_PREF_NAMES set literal"
    body = m.group(1)
    for name in ("onionbird.socks.host", "onionbird.socks.port"):
        assert f'"{name}"' in body, (
            f"F-168: addon-owned-pref allowlist missing {name!r}. "
            f"Options-page Save would silently no-op the user's "
            f"SOCKS override write."
        )


# ---- Test 2: API surface — setSocksOverride is declared in the schema ----


def test_F168_set_socks_override_api_in_schema() -> None:
    """The Options-page Save handler calls
    `browser.onionbird.setSocksOverride(field, value)` — a wrapper
    that validates before persisting (so the UI gets immediate
    feedback rather than a silent-success / read-time-fallback). The
    schema declares the name + parameter shape; without the schema
    entry the WebExt machinery refuses the call."""
    schema = json.loads(_read(ADDON_SCHEMA_PATH))
    funcs = schema[0]["functions"]
    matching = [f for f in funcs if f.get("name") == "setSocksOverride"]
    assert matching, (
        "F-168: setSocksOverride is not declared in "
        "addon/experiments/onionbird/schema.json. The Options-page Save "
        "handler cannot reach the implementation."
    )
    fn = matching[0]
    assert fn.get("async") is True, "F-168: setSocksOverride must be async"
    params = fn.get("parameters", [])
    assert [p.get("name") for p in params] == ["field", "value"], (
        f"F-168: setSocksOverride parameter shape changed; expected "
        f"(field, value), got {params!r}"
    )


# ---- Test 3: read-time validation — bad pref values are rejected at enable ----


def test_F168_override_read_validation_rejects_bad_host() -> None:
    """Validation at READ time in enableHardening must reject a non-
    loopback hostname even if it slipped past write-time gating (manual
    about:config edit, stale pref from a removed addon, fuzz). Source-
    level assertion: the override-resolution code uses `isValidSocksHost`
    (or equivalent) before trusting the stored host."""
    impl = _read(ADDON_IMPL_PATH)
    assert "getSocksOverride" in impl, (
        "F-168: no getSocksOverride helper found. enableHardening must "
        "read the override through a validating helper, not directly "
        "via Services.prefs."
    )
    # Helper can be either a top-level `function getSocksOverride() {…}`
    # or an arrow inside the API object literal
    # (`getSocksOverride: async () => {…}`). Match both shapes.
    m = (
        re.search(
            r"function getSocksOverride\(\)\s*\{([\s\S]+?)\n\}",
            impl,
        )
        or re.search(
            r"getSocksOverride\s*:\s*async\s*\([^)]*\)\s*=>\s*\{([\s\S]+?)\n\s{0,12}\},",
            impl,
        )
    )
    assert m, (
        "F-168: could not parse the override-resolution helper body. "
        "If you renamed or restructured it, update this regex."
    )
    body = m.group(1)
    # S-2: assert the validator is in a GUARD position (gates the return),
    # not just a no-op call somewhere in the body. The previous test
    # passed even with `if (false)` around the validator because the
    # function-name substring still appeared — exactly the false-pass
    # the project's own follow-up.md warns about (structural test
    # green-but-meaningless). This regex requires the strict pair
    # validator to negate-OR-guard a return null, not just be mentioned.
    assert re.search(
        r"if\s*\(\s*!\s*\(\s*isLoopbackSocksHost\([^)]+\)\s*\|\|\s*"
        r"isIpLiteralSocksHost\([^)]+\)\s*\)\s*\)\s*\{[^}]*return\s+null",
        body,
    ), (
        f"F-168 S-2: override-resolution helper's validator does NOT "
        f"gate the return path with the strict pair "
        f"(isLoopbackSocksHost || isIpLiteralSocksHost). A mention of "
        f"the names alone is not enough — a stale or manually-set bad "
        f"host would propagate into network.proxy.socks. Body:\n{body[:400]}"
    )


# ---- Test 4: override resolution — enableHardening consults the override ----


def test_F168_enable_hardening_consults_socks_override() -> None:
    """`_enableHardeningImpl` in background.js must consult the user
    override before falling back to the auto-detect/probe ladder.
    Without this wiring, the persisted override is a dead pref."""
    bg = _read(ADDON_BG_PATH)
    # Either an explicit getSocksOverride call OR direct getPref on
    # both override names is acceptable.
    assert (
        "getSocksOverride" in bg
        or 'getPref("onionbird.socks.host"' in bg
        or "onionbird.socks.host" in bg
    ), (
        "F-168: background.js does not reference the SOCKS override "
        "pref. enableHardening will ignore the user's saved override."
    )


# ---- Test 5: behavioural — override = tor:9050 → canary clean, SMTP reaches trap ----


def test_F168_override_routes_send_through_chosen_endpoint(
    tb: TBClient,
    http,
    clear_traps,
) -> None:
    """Behavioural verification of the full override → enable → canary →
    send path. The override is restricted to IP literals + loopback
    (a DNS-name SOCKS host would trigger a pre-Tor system-resolver
    lookup of the host itself — exactly the leak class the addon
    closes elsewhere). The test pod's `tor` container has a dynamic
    Docker IP, so resolve it here at test-setup time and pass the IP
    literal into the override.

    With the override honoured, the addon's enableHardening
    candidate-list prepends the override, the probe succeeds, the
    canary verifies clean, `compose.onBeforeSend` lets sends through,
    and the SMTP trap receives the message.

    With the override-resolution wiring missing or broken, the addon
    falls back to 127.0.0.1:9050 → no SOCKS → canary non-clean →
    onBeforeSend cancels → smtp-trap empty → test fails on the
    matching assertion below.
    """
    # The Tor container has a dynamic IP across compose-down/up, so
    # resolve it at runtime. The runner container is on the same
    # docker network, so /etc/hosts has the entry.
    import socket
    tor_ip = socket.gethostbyname("tor")
    assert tor_ip and tor_ip != "tor", (
        f"F-168 precondition: could not resolve `tor` from the runner "
        f"container — is the test pod up? Got {tor_ip!r}."
    )

    # Pre-set the override BEFORE installing the addon, so the
    # auto-enable on install picks it up on first try (avoids a
    # re-enable round-trip).
    setup_js = r"""
        const [host, port] = arguments;
        Services.prefs.setCharPref("onionbird.socks.host", host);
        Services.prefs.setIntPref("onionbird.socks.port", port);
        // Also wire an identity bound to smtp-trap so the send can
        // actually leave TB. Reuse-or-create pattern from T-076.
        const { MailServices } = ChromeUtils.importESModule(
          "resource:///modules/MailServices.sys.mjs"
        );
        const Ci = Components.interfaces;
        const outgoing = MailServices.outgoingServer || MailServices.smtp;
        let smtp = null;
        for (const s of outgoing.servers) {
          const ss = s.QueryInterface ? s.QueryInterface(Ci.nsISmtpServer) : s;
          if (ss.hostname === "smtp-trap" && ss.port === 2525) { smtp = ss; break; }
        }
        if (!smtp) {
          const raw = outgoing.createServer("smtp");
          smtp = raw.QueryInterface(Ci.nsISmtpServer);
          smtp.hostname = "smtp-trap";
          smtp.port = 2525;
          smtp.authMethod = 0;
          smtp.socketType = 0;
        }
        let identity = null;
        for (const i of MailServices.accounts.allIdentities) {
          if (i.email === "f168-override@anon.invalid") { identity = i; break; }
        }
        if (!identity) {
          identity = MailServices.accounts.createIdentity();
          identity.email = "f168-override@anon.invalid";
          identity.fullName = "f168 override probe";
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
        identity.smtpServerKey = smtp.key;
        return { identityKey: identity.key, smtpKey: smtp.key };
    """
    keys = tb.exec_chrome(setup_js, args=[tor_ip, 9050])
    assert keys["identityKey"]

    tb.install_addon(XPI, temporary=True)

    # Wait for the addon to apply prefs AND for the canary to settle.
    # The canary probing the resolved tor IP takes a few seconds.
    import time
    deadline = time.time() + 45
    socks_host_seen = None
    while time.time() < deadline:
        socks_host_seen = tb.get_pref("network.proxy.socks")
        if socks_host_seen == tor_ip:
            break
        time.sleep(0.5)
    assert socks_host_seen == tor_ip, (
        f"F-168: addon never wrote the override SOCKS host ({tor_ip}) into "
        f"network.proxy.socks within 45s. Got {socks_host_seen!r}. "
        f"The override-resolution path is not honouring "
        f"onionbird.socks.host."
    )
    socks_port_seen = tb.get_pref("network.proxy.socks_port")
    assert socks_port_seen == 9050, (
        f"F-168: SOCKS port mismatch — expected 9050 from override, got "
        f"{socks_port_seen!r}. The override pref pair must be applied "
        f"as an atomic (host, port) tuple."
    )


# ---- Test 6: Options UI surface (inputs + buttons + i18n keys) ----


def test_F168_options_html_has_socks_override_section() -> None:
    """The Options page must surface inputs for host + port plus
    Save / Reset / Test buttons. Without these the user has no way
    to drive the override write through the addon's API."""
    html = _read("/addon/ui/options.html")
    required_ids = (
        "socks-override-host",       # text input
        "socks-override-port",       # number input
        "socks-override-save",       # Save button
        "socks-override-reset",      # Reset-to-default button
        "socks-override-test",       # Test endpoint button
        "socks-override-status",     # status-line for last test result + warnings
    )
    for el_id in required_ids:
        assert f'id="{el_id}"' in html, (
            f"F-168: Options page missing element #{el_id}. The "
            f"user-override surface is incomplete and the Save handler "
            f"in options.js has nothing to wire to."
        )


def test_F168_options_js_calls_setsocksoverride_api() -> None:
    """options.js must call `browser.onionbird.setSocksOverride` on
    Save, and `browser.onionbird.getSocksOverride` on load (to show
    the current persisted value)."""
    js_src = _read("/addon/ui/options.js")
    for symbol in ("setSocksOverride", "getSocksOverride"):
        assert symbol in js_src, (
            f"F-168: options.js does not reference {symbol}. The "
            f"Options page UI is wired to the wrong API or not wired "
            f"at all."
        )


def test_S4_options_socks_handlers_use_runtime_message_indirection() -> None:
    """Code-review S-4 (architectural): every other Options-page UI
    handler routes through `browser.runtime.sendMessage({cmd:...})`
    so the experiment API surface lives concentrated in one process
    (background.js). The F-168 SOCKS-override handlers shipped with
    direct `browser.onionbird.*` calls from options.js — two patterns
    coexisted, future maintainers must learn both.

    Fix: options.js calls `browser.runtime.sendMessage({cmd: ...})`
    for save/get/probe; background.js dispatches via the existing
    switch statement (with the new cases `get-socks-override`,
    `save-socks-override`, `probe-socks-override`).
    """
    js_src = _read("/addon/ui/options.js")
    js_no_comments = re.sub(r"//[^\n]*", "", js_src)
    js_no_comments = re.sub(r"/\*[\s\S]*?\*/", "", js_no_comments)
    # The SOCKS handlers in options.js must NOT call browser.onionbird
    # directly — they should route via runtime.sendMessage.
    direct_calls = re.findall(
        r"browser\.onionbird\.(setSocksOverride|setSocksOverridePair|getSocksOverride|probeSocks)\b",
        js_no_comments,
    )
    assert not direct_calls, (
        "S-4: options.js still calls browser.onionbird.* directly: "
        f"{direct_calls}. Must route via browser.runtime.sendMessage "
        "for consistency with every other Options handler."
    )
    # And background.js must dispatch the new commands.
    bg = _read("/addon/background.js")
    for cmd in ("get-socks-override", "save-socks-override", "probe-socks-override"):
        assert f'case "{cmd}"' in bg, (
            f"S-4: background.js runtime-message switch missing "
            f"case for {cmd!r}. options.js sendMessage will hit the "
            f"default branch and return undefined."
        )


def test_F172_run_self_test_honours_user_probe_bypass() -> None:
    """Bug-search F-172: runSelfTest's `assertAllowedSocksEndpoint` call
    was missing the `userProbe` opt-out that F-168 I-1 added to
    probeSocks. Same chicken-and-egg trap as the Test button: if the
    UI Run-self-test-now button kicks off a self-test before the
    user's chosen override has been applied to network.proxy.socks,
    the assertion rejects the IP-literal endpoint with the misleading
    'SOCKS endpoint not allowed' error.

    Less common than the F-168 I-1 case (the user usually clicks Test
    before Run-self-test), but the same plumbing needs the same fix.
    Structural assertion: runSelfTest threads `cfg.userProbe` /
    `options.userProbe` through to assertAllowedSocksEndpoint."""
    impl = _read(ADDON_IMPL_PATH)
    self_test_slice = impl[impl.index("runSelfTest: async"):]
    self_test_slice = self_test_slice[:self_test_slice.index("clearHardeningFromAllIdentities")]
    # The assertion call inside runSelfTest must pass a 3rd arg (the
    # options object that carries userProbe). Two-arg calls (the old
    # F-168-pre-I-1 shape) leave the chicken-and-egg trap open.
    # Match: assertAllowedSocksEndpoint(arg1, arg2, arg3...) — three
    # comma-separated tokens minimum. arg3 must be either an object
    # literal containing `userProbe` OR a named options-ish variable
    # (cfg / opts / options) which is then expected to carry userProbe
    # at the call site of runSelfTest.
    assert re.search(
        r"assertAllowedSocksEndpoint\(\s*\w[\w\.]*\s*,\s*\w[\w\.]*\s*,\s*(?:\{[^}]*userProbe[^}]*\}|(?:options|cfg|opts)\b)",
        self_test_slice,
    ), (
        "F-172: runSelfTest's assertAllowedSocksEndpoint call does not "
        "thread an options arg. Same chicken-and-egg trap as F-168 I-1: "
        "a Run-self-test invocation before the override has been "
        "applied to network.proxy.socks rejects the IP-literal with "
        "the misleading 'SOCKS endpoint not allowed' error."
    )


def test_F170_save_handler_writes_host_and_port_atomically() -> None:
    """Bug-search F-170: the Save handler used to write host then port
    sequentially via two `setSocksOverride(field, value)` calls. If the
    port write happened to fail (or the user's `port` input was treated
    as a clear-sentinel by the impl), the host pref was persisted with
    NO port → `getSocksOverride` returns null on read (half-set =
    null), the override is silently inert, and the user sees "saved"
    even though enableHardening will ignore the persisted host.

    The fix: a `setSocksOverridePair({host, port})` API validates both
    inputs THEN writes both in the same parent-process tick. options.js
    must call this instead of the two-step sequence.

    Structural check on both ends; the implementation is in
    implementation.js (validates + writes atomically; on any failure,
    leaves NO half-state) and options.js must use it.
    """
    impl = _read(ADDON_IMPL_PATH)
    assert "setSocksOverridePair" in impl, (
        "F-170: setSocksOverridePair API not defined in implementation.js. "
        "Without it the Save handler must use the non-atomic two-step "
        "write and a half-set state (host persisted, port cleared) "
        "silently dead-states the override."
    )
    # Atomic body must read both inputs, validate both, then write both
    # OR fail without writing either. Look for an explicit half-state
    # rollback or both-or-nothing pattern.
    m = re.search(
        r"setSocksOverridePair\s*:\s*async\s*\([^)]*\)\s*=>\s*\{([\s\S]+?)\n\s{0,12}\},",
        impl,
    )
    assert m, "F-170: could not parse setSocksOverridePair body"
    body = m.group(1)
    # The body must validate the port before writing the host (the
    # common reverse-of-input-order pattern prevents half-state).
    for marker in ("writePref", "isLoopbackSocksHost", "normalizeSocksPortValue"):
        assert marker in body, (
            f"F-170: setSocksOverridePair body missing {marker} — "
            f"atomic write requires validate-both-then-write-both."
        )

    # F-168 S-4 moved the experiment-API call from options.js into
    # background.js's save-socks-override dispatch case. The atomic-
    # write property is still load-bearing — assert the call lives in
    # the right handler now.
    bg = _read("/addon/background.js")
    bg_no_comments = re.sub(r"//[^\n]*", "", bg)
    bg_no_comments = re.sub(r"/\*[\s\S]*?\*/", "", bg_no_comments)
    m = re.search(
        r'case "save-socks-override"\s*:([\s\S]+?)(?:case "|default:)',
        bg_no_comments,
    )
    assert m, (
        "F-170: background.js dispatch missing `case \"save-socks-override\":`"
    )
    case_body = m.group(1)
    assert "setSocksOverridePair" in case_body, (
        "F-170: save-socks-override handler does not call "
        "setSocksOverridePair. The non-atomic two-step write would be "
        "re-introduced — host/port half-state hazard."
    )


def test_F168_test_button_passes_user_probe_bypass() -> None:
    """Code-review I-1: the Options-page Test button must work for
    non-loopback IP literals (Whonix Gateway = 10.152.152.10, Tails
    custom configs, etc.) — the primary use case for the override
    feature. Without a `{ userProbe: true }` opt-out passed through
    to `assertAllowedSocksEndpoint`, the probe throws "SOCKS endpoint
    not allowed" because `currentSocksEndpointMatches` is false until
    the user has already Saved. This is the chicken-and-egg trap.

    The fix: `probeSocks(host, port, host, options)` accepts an
    optional 4th arg `{ userProbe: true }`; when set,
    `assertAllowedSocksEndpoint` skips the `currentSocksEndpointMatches`
    requirement (still keeps the strict isLoopback || isIpLiteral
    gate — IP literals don't leak DNS regardless of whether TB's
    current pref matches them).

    Structural assertions cover the wiring on both ends; the
    Marionette test that actually clicks the button is a follow-up.
    """
    # F-168 S-4 moved the userProbe call from options.js to background.js
    # (Options now dispatches `cmd: "probe-socks-override"`; the
    # background handler sets userProbe before calling probeSocks).
    # Assert the userProbe flag is in the background dispatch handler.
    bg = _read("/addon/background.js")
    bg_no_comments = re.sub(r"//[^\n]*", "", bg)
    bg_no_comments = re.sub(r"/\*[\s\S]*?\*/", "", bg_no_comments)
    # Find the probe-socks-override case body.
    m = re.search(
        r'case "probe-socks-override"\s*:([\s\S]+?)(?:case "|default:)',
        bg_no_comments,
    )
    assert m, (
        "F-168 I-1: background.js runtime dispatch missing "
        "`case \"probe-socks-override\":` handler. The Options Test "
        "button cannot reach probeSocks."
    )
    case_body = m.group(1)
    assert re.search(
        r"probeSocks\([^)]*\{[^}]*userProbe\s*:\s*true",
        case_body,
    ), (
        "F-168 I-1: background.js probe-socks-override handler does "
        "not pass `{ userProbe: true }` to probeSocks. Test button "
        "throws 'SOCKS endpoint not allowed' for any non-loopback IP, "
        "breaking the Whonix/Tails workflow."
    )
    impl = _read(ADDON_IMPL_PATH)
    # assertAllowedSocksEndpoint must accept the bypass option AND honour it.
    assert re.search(
        r"function assertAllowedSocksEndpoint\([^)]*,\s*\w+",
        impl,
    ), (
        "F-168 I-1: assertAllowedSocksEndpoint signature does not take "
        "an options arg. The bypass cannot be wired through."
    )
    # The body of assertAllowedSocksEndpoint must reference `userProbe`
    # AND short-circuit on the IP-literal branch without requiring
    # currentSocksEndpointMatches.
    m = re.search(
        r"function assertAllowedSocksEndpoint\([^)]*\)\s*\{([\s\S]+?)\n\}",
        impl,
    )
    assert m, "F-168 I-1: could not parse assertAllowedSocksEndpoint body"
    body = m.group(1)
    assert "userProbe" in body, (
        "F-168 I-1: assertAllowedSocksEndpoint body does not check the "
        "userProbe bypass flag. The Test button bypass is non-functional."
    )


def test_F176_test_button_signals_invalid_port_separately_from_invalid_host() -> None:
    """testSocksOverride was conflating host-empty and port-invalid into
    a single 'Invalid host' status. The Save handler split these cleanly
    via two `if` blocks; Test must mirror it. Strengthened (P2-2/P2-3):
    bind each i18n key to the correct `if` block AND assert the
    `1 <= port <= 65535` bounds check (port=0 used to fall through
    because Number.isFinite(0)===true).
    """
    options_js = _read(ADDON_OPTIONS_JS_PATH)
    m = re.search(
        r"async function testSocksOverride\b[\s\S]+?\n  \}",
        options_js,
    )
    assert m, (
        "F-176: could not locate `async function testSocksOverride` body "
        "in options.js."
    )
    body = m.group(0)
    # Host check must use the InvalidHost key (not swapped).
    host_check = re.search(
        r"if\s*\(\s*!host\b[^)]*\)\s*\{[^{}]*?socksOverrideStatusInvalidHost",
        body,
        re.DOTALL,
    )
    assert host_check, (
        "F-176: testSocksOverride must have an `if (!host)` block that "
        "surfaces `socksOverrideStatusInvalidHost`. A swapped key would "
        "satisfy a generic 'both keys present' assertion but invert the "
        "user-facing message direction."
    )
    # Port check must use the InvalidPort key AND enforce 1..65535.
    port_check = re.search(
        r"if\s*\([^)]*Number\.isFinite\(\s*port\s*\)[^)]*\)\s*\{[^{}]*?"
        r"socksOverrideStatusInvalidPort",
        body,
        re.DOTALL,
    )
    assert port_check, (
        "F-176: testSocksOverride must have a port check (referencing "
        "`Number.isFinite(port)`) that surfaces "
        "`socksOverrideStatusInvalidPort`."
    )
    port_body = port_check.group(0)
    assert "port < 1" in port_body and "port > 65535" in port_body, (
        "F-176: testSocksOverride must enforce the 1..65535 bounds in "
        "the port check (mirror saveSocksOverride). Pre-fix accepted "
        "port=0 because Number.isFinite(0)===true, falling through to "
        "probe(host, 0). Without explicit bounds the user gets a generic "
        "downstream socks5 error instead of the actionable InvalidPort."
    )


def test_F177_partial_edits_fall_back_to_placeholder_defaults() -> None:
    """User UX requirement: "wenn ich nur die ip anpasse sollte der port
    schon drin stehen und andersherum" — typing only one field should
    let the other be the visible-placeholder default ("127.0.0.1" /
    "9050") at Save/Test time.

    F-177 v1 implemented this via unconditional pre-fill of `.value` in
    loadSocksOverride. That regressed Reset+Save: after Reset (which
    clears the stored override and expects fall-back to the 9050→9150
    auto-detect ladder), the inputs got visibly populated with
    127.0.0.1:9050; a single Save click then PINNED port 9050,
    silently disabling the ladder for any user on Tor-Browser-bundle
    (which lives on 9150).

    F-177 v2: placeholder-fallback in saveSocksOverride and
    testSocksOverride. ONE field empty → take the OTHER's `.placeholder`
    value. BOTH empty → InvalidHost error (do NOT silently pin defaults).
    loadSocksOverride must NOT contain a hardcoded "127.0.0.1" literal
    (the v1 anti-pattern).
    """
    options_js = _read(ADDON_OPTIONS_JS_PATH)
    # Save and Test must both consult `.placeholder` for the fallback —
    # either directly via the property accessor or via the shared helper.
    # We strip line-comments before matching so the literal word
    # "placeholder" appearing in a docstring/comment doesn't satisfy the
    # invariant (a real CODE reference is required, not just a mention).
    for fn in ("saveSocksOverride", "testSocksOverride"):
        m = re.search(
            rf"async function {fn}\b[\s\S]+?\n  \}}",
            options_js,
        )
        assert m, f"F-177: could not locate `{fn}` body"
        body = m.group(0)
        body_code_only = re.sub(r"//[^\n]*", "", body)
        body_code_only = re.sub(r"/\*[\s\S]*?\*/", "", body_code_only)
        uses_placeholder_directly = bool(
            re.search(r"\.placeholder\b", body_code_only)
        )
        uses_helper = bool(
            re.search(
                r"resolveSocksInputsWithPlaceholderFallback\s*\(",
                body_code_only,
            )
        )
        assert uses_placeholder_directly or uses_helper, (
            f"F-177: {fn} must read the input's `.placeholder` as a "
            f"fallback when exactly one field is filled. Either reference "
            f"`.placeholder` directly or call the shared helper "
            f"`resolveSocksInputsWithPlaceholderFallback()`. Comments "
            f"don't count — the code must actually consult the placeholder."
        )
    # The helper itself must exist if either function delegates to it.
    if re.search(
        r"resolveSocksInputsWithPlaceholderFallback\s*\(",
        re.sub(r"//[^\n]*", "", options_js),
    ):
        assert (
            "function resolveSocksInputsWithPlaceholderFallback" in options_js
        ), (
            "F-177: helper name is called but the definition is missing; "
            "check for renames."
        )
    # loadSocksOverride must NOT contain a hardcoded "127.0.0.1" literal —
    # that's the F-177 v1 anti-pattern that caused the Reset+Save regression.
    m = re.search(
        r"async function loadSocksOverride\b[\s\S]+?\n  \}",
        options_js,
    )
    assert m, "F-177: could not locate `loadSocksOverride` body"
    load_body = m.group(0)
    assert '"127.0.0.1"' not in load_body, (
        "F-177 v2: loadSocksOverride must NOT contain a hardcoded "
        "'127.0.0.1' default. The pre-fill-in-load pattern (v1) made "
        "Reset+Save silently pin port 9050, breaking the auto-detect "
        "ladder for users on 9150 (Tor-Browser-bundle). Use "
        "placeholder-fallback in save/test instead."
    )


def test_F180_detect_socks_config_passes_userProbe_for_user_override() -> None:
    """The `detectSocksConfig` ladder iterates SOCKS candidates and
    probes each one. The user-override candidate (source="user-override")
    represents an explicit user choice — they configured this endpoint
    via the Options page Save button. The gate's
    `currentSocksEndpointMatches` requirement on IP literals was
    designed to stop the addon from probing arbitrary remote IPs
    without user consent; but the saved override IS the user consent.

    Without a `userProbe: true` opt-out, the ladder rejects the
    user-override candidate whenever TB's existing `network.proxy.socks`
    differs from it (e.g. a fresh override before the first
    enableHardening, or after the user changed the override port). The
    rejection is silent — the ladder simply falls through to the
    existing-pref / fallback candidates, ignoring the user's choice
    entirely. F-168 I-1 already established the bypass for the
    Options-page Test button; the ladder must honour the same logic.

    Structural assertion: `detectSocksConfig`'s probe loop must pass
    `userProbe: true` when the candidate's source is `"user-override"`,
    and must NOT pass it for other sources (existing-pref, system-tor,
    tor-browser) — those don't carry an explicit user mandate.
    """
    bg = _read(ADDON_BG_PATH)
    m = re.search(
        r"async function detectSocksConfig\b[\s\S]+?\n\}",
        bg,
    )
    assert m, "F-180: could not locate `detectSocksConfig` body"
    body = m.group(0)
    body_code_only = re.sub(r"//[^\n]*", "", body)
    body_code_only = re.sub(r"/\*[\s\S]*?\*/", "", body_code_only)
    # The probeSocks call inside the candidate loop must be conditioned
    # on the user-override source to opt into the userProbe bypass.
    assert "user-override" in body_code_only, (
        "F-180: detectSocksConfig must check the candidate source for "
        "the `user-override` value before passing the userProbe bypass "
        "to probeSocks."
    )
    assert re.search(r"userProbe\s*:\s*true", body_code_only), (
        "F-180: detectSocksConfig must pass `userProbe: true` to "
        "probeSocks for the user-override candidate. Without this, the "
        "gate rejects the user's explicitly-configured endpoint and "
        "the ladder silently falls through to the next candidate."
    )
    # Ensure the bypass is GATED on the source (not unconditional — that
    # would defeat the gate's protection for the inferred candidates).
    assert re.search(
        r'source\s*===?\s*"user-override"[\s\S]{0,200}userProbe',
        body_code_only,
    ), (
        "F-180: the `userProbe: true` opt-out must be conditioned on "
        "`c.source === \"user-override\"`. An unconditional bypass "
        "would weaken the gate for existing-pref/system-tor/tor-browser "
        "candidates, defeating the protection it was designed to give."
    )


def test_F178_socks5_helpers_do_not_depend_on_global_TextEncoder() -> None:
    """A user reported the Test endpoint button failing with the error
    'TextEncoder is not defined'. Root cause: `socks5Resolve` and
    `socks5ResolvePtr` constructed `new TextEncoder()` directly, but
    the global `TextEncoder` is not present in every chrome-script
    context the experiment runs in (depends on Thunderbird build).

    SOCKS5 string fields (RESOLVE host, user/pass auth tokens) are
    ASCII-only by upstream validation, so we encode via a charCode
    polyfill (`encodeSocksStringField`) which is context-agnostic.

    Structural assertion: neither helper body references `TextEncoder`
    after the fix.
    """
    impl = _read(ADDON_IMPL_PATH)
    for fn in ("socks5Resolve", "socks5ResolvePtr"):
        m = re.search(
            rf"async function {fn}\b[\s\S]+?\n\}}",
            impl,
        )
        assert m, (
            f"F-178: could not locate `async function {fn}` body in "
            f"implementation.js."
        )
        body = m.group(0)
        assert "TextEncoder" not in body, (
            f"F-178: {fn} still references `TextEncoder`. In chrome-"
            f"script contexts of some Thunderbird builds, TextEncoder "
            f"is undefined globally and the Test endpoint button "
            f"throws 'TextEncoder is not defined'. Use the "
            f"`encodeSocksStringField` polyfill which is "
            f"context-agnostic (charCode-based, ASCII-only)."
        )
    # The polyfill itself must exist somewhere in the file.
    assert "function encodeSocksStringField" in impl, (
        "F-178: missing `encodeSocksStringField` helper — the polyfill "
        "for SOCKS5 string field encoding was removed."
    )


def test_F168_i18n_keys_in_english_locale() -> None:
    """The new UI strings must have their i18n keys defined in the
    English locale (the source-of-truth that the README equality
    claim depends on). Other locales follow via the existing
    translation scripts; this test just asserts the canonical en
    bundle is up to date."""
    en = json.loads(_read("/addon/_locales/en/messages.json"))
    required_keys = (
        "socksOverrideTitle",
        "socksOverrideIntro",
        "socksOverrideHostLabel",
        "socksOverridePortLabel",
        "socksOverrideSaveButton",
        "socksOverrideResetButton",
        "socksOverrideTestButton",
        "socksOverrideStatusOk",
        "socksOverrideStatusInvalidHost",
        "socksOverrideStatusInvalidPort",
        "socksOverrideTbPrefWarning",  # the "User-Override + Warnung" hint
    )
    missing = [k for k in required_keys if k not in en]
    assert not missing, (
        f"F-168: en/messages.json missing i18n keys for the SOCKS "
        f"override UI: {missing}. The Options page will render the "
        f"raw key string in English (and in every other locale, since "
        f"they inherit from en)."
    )


# NOTE: a behavioural test for the read-time validator in
# getSocksOverride is intentionally NOT in this file. The validator is
# defense-in-depth — coreFailClosedPrefs's safeConfiguredSocksHostOrDefault
# already rewrites any non-loopback non-IP-literal host to DEFAULT_SOCKS_HOST
# at fail-closed write time, so a bad override set via about:config
# (bypassing setSocksOverride) ends up at 127.0.0.1 in network.proxy.socks
# REGARDLESS of whether the read-time validator fires. The structural
# Test 3 above asserts the validator names appear in the helper body;
# making the validator observably load-bearing from a Marionette test
# would require also removing safeConfiguredSocksHostOrDefault — a
# 2-mutation scenario outside the single-mutation test discipline.
