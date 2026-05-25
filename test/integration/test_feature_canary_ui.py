"""Options-page canary UI: badge classification + HTML/JS contract.

Three layers:
1. options.html declares the canary section (badge, button, detail table).
2. options.js wires to the right runtime message and reads the right fields.
3. The classifyCanary function maps every result shape to the right level —
   verified by running the function inside TB's JS engine via Marionette.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from helpers.tb_client import TBClient


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


def _read(path: str) -> str:
    with open(path) as f:
        return f.read()


def _read_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


# --- static contract: options.html ---

def test_options_html_has_canary_section() -> None:
    html = _read("/addon/ui/options.html")
    for needle in [
        'id="canary-badge"',
        'id="canary-host-input"',
        'id="canary-reveal-ips"',
        'id="run-self-test"',
        'id="canary-detail"',
        'class="badge unknown"',
    ]:
        assert needle in html, f"options.html missing: {needle}"


def test_options_html_has_theme_help_and_i18n_sections() -> None:
    html = _read("/addon/ui/options.html")
    for needle in [
        'meta name="color-scheme"',
        'id="theme-controls"',
        'data-theme-choice="system"',
        'data-theme-choice="light"',
        'data-theme-choice="dark"',
        'id="help"',
        'id="help-mode-controls"',
        'data-help-mode="tldr"',
        'data-help-mode="nerd"',
        "data-i18n=",
    ]:
        assert needle in html, f"options.html missing: {needle}"


def test_options_html_has_tor_test_mode_section() -> None:
    html = _read("/addon/ui/options.html")
    for needle in [
        'id="run-tor-test"',
        'id="tor-test-badge"',
        'id="tor-test-spinner"',
        'id="tor-test-status"',
        'id="tor-test-detail"',
        'id="tor-test-endpoint"',
        'data-i18n="torTestIntro"',
    ]:
        assert needle in html, f"options.html missing Tor test mode: {needle}"


# --- static contract: options.js ---

def test_options_js_uses_run_self_test_command() -> None:
    js = _read("/addon/ui/options.js")
    assert '"run-self-test"' in js, "options.js must send cmd=run-self-test"
    assert "canaryHostInput.value" in js, "options.js must use the chosen canary host"
    assert "maskIp" in js, "options.js must mask raw IPs by default"
    assert "canary-reveal-ips" in js, "options.js must allow explicit raw-IP reveal"
    # Reads the new canary result fields
    for field in ["tor_ips", "system_ip", "system_ips", "leak_detected"]:
        assert field in js, f"options.js does not read field: {field}"


def test_options_js_redacts_sensitive_command_log_fields() -> None:
    js = _read("/addon/ui/options.js")
    assert "function redactResultForLog" in js
    assert "function redactSelfTestForLog" in js
    assert "JSON.stringify(redactResultForLog(r))" in js
    assert "JSON.stringify(r)" not in js
    for needle in [
        "tor_ip_count",
        "system_ip: maskIp",
        "system_ptr_present",
        '"origins"',
        '"logins"',
        "probes_count",
        '"<configured>"',
    ]:
        assert needle in js, f"options.js log redaction missing: {needle}"


def test_options_js_handles_all_four_badge_levels() -> None:
    js = _read("/addon/ui/options.js")
    for level in ["ok", "warn", "leak", "error", "unknown"]:
        assert f'"{level}"' in js or f"'{level}'" in js, (
            f"options.js does not produce badge level: {level}"
        )


def test_options_js_wires_theme_help_and_i18n() -> None:
    js = _read("/addon/ui/options.js")
    for needle in [
        "THEME_STORAGE_KEY",
        "HELP_MODE_STORAGE_KEY",
        "applyI18n",
        "browser.i18n.getMessage",
        "browser.i18n.getUILanguage",
        "applyTheme",
        "normalizeTheme",
        "renderHelp",
        "HELP_SECTIONS",
        "data-theme-choice",
        "data-help-mode",
        "readPrefsFailed",
    ]:
        assert needle in js, f"options.js missing: {needle}"


def test_options_js_routes_message_id_changes_through_background() -> None:
    js = _read("/addon/ui/options.js")
    assert '"get-message-id-fqdn"' in js
    assert '"save-message-id-fqdn"' in js
    assert "browser.onionbird.setPref" not in js
    assert "browser.onionbird.applyHardeningToAllIdentities" not in js


def test_background_does_not_apply_message_id_changes_while_inactive() -> None:
    bg = _read("/addon/background.js")
    start = bg.index("async function saveMessageIdFqdnPrefs")
    end = bg.index("async function getStoredSnapshot")
    fn = bg[start:end]
    assert "hardeningActive = !!(await getStoredSnapshot())" in fn
    assert "applyHardeningToAllIdentities" in fn
    assert "inactive: true" in fn


def test_options_js_wires_tor_test_mode() -> None:
    js = _read("/addon/ui/options.js")
    for needle in [
        '"run-tor-test"',
        "runTorTest",
        "renderTorTest",
        "classifyTorTest",
        "formatTorTestProbes",
        "tor-test-badge",
        "tor-test-detail",
        "torTestOk",
        "torTestNoTor",
    ]:
        assert needle in js, f"options.js missing Tor test mode: {needle}"


def test_background_exposes_non_mutating_tor_test_mode() -> None:
    bg = _read("/addon/background.js")
    assert '"run-tor-test"' in bg
    assert 'TOR_TEST_HOST = "example.com"' in bg
    assert "runTorReadinessTest" in bg
    start = bg.index("async function runTorReadinessTest")
    end = bg.index("async function readCurrentSocksConfig")
    fn = bg[start:end]
    assert "detectSocksConfig" in fn
    assert "changedPrefs: false" in fn
    assert "publicSocksProbe" in fn
    assert "applyPrefs" not in fn
    assert "enableHardening" not in fn
    assert "check.torproject.org" not in fn


def test_background_canary_guidance_is_cross_platform() -> None:
    bg = _read("/addon/background.js")
    assert "/etc/resolv.conf" not in bg
    assert "Route system DNS" in bg


def test_locale_files_cover_options_help() -> None:
    locales = {}
    for lang in ["en", "de", "es"]:
        p = Path(f"/addon/_locales/{lang}/messages.json")
        assert p.exists(), f"missing locale file: {p}"
        locales[lang] = _read_json(str(p))

    base_keys = set(locales["en"])
    for lang, messages in locales.items():
        assert set(messages) == base_keys, f"{lang} locale keys drift from en"
        for key, value in messages.items():
            assert value.get("message"), f"{lang}:{key} has no message"

    for key in [
        "themeSystem",
        "themeLight",
        "themeDark",
        "helpTldrDoesTitle",
        "helpTldrDoesNotTitle",
        "helpTldrTorbirdy1",
        "helpTldrExperiments1",
        "helpNerdDoesTitle",
        "helpNerdDoesNotTitle",
        "helpNerdTorbirdy2",
        "helpNerdExperiments3",
        "readPrefsFailed",
        "torTestTitle",
        "torTestIntro",
        "runTorTestButton",
        "torTestOk",
        "torTestNoTor",
        "torTestSourceExistingPref",
    ]:
        assert key in base_keys, f"missing required i18n key: {key}"


def test_manifests_use_localized_name_and_description() -> None:
    mv2 = _read_json("/addon/manifest.json")
    mv3 = _read_json("/addon/manifest.mv3.json")
    for manifest in [mv2, mv3]:
        assert manifest["name"] == "__MSG_extensionName__"
        assert manifest["description"] == "__MSG_extensionDescription__"
        assert manifest["default_locale"] == "en"


# --- classifyCanary behaviour: parametrised on real TB JS engine ---
#
# T-077: do NOT redefine classifyCanary in the test. Load the REAL
# addon/ui/options.js into TB's JS engine the same way
# test_fuzz_inputs.py does (module.exports pattern), then call the
# addon's own classifyCanary. A drift between the test's mental
# model and the addon's behaviour now surfaces — pre-T-077 the
# test passed regardless of what the addon actually did.


def _read_options_js() -> str:
    with open("/addon/ui/options.js") as f:
        return f.read()


CLASSIFY_JS = r"""
const [source, result] = arguments;
const module = { exports: {} };
const browser = {
  i18n: {
    getMessage(key) { return key; },
    getUILanguage() { return "en-US"; },
  },
};
const load = new Function(
  "module", "browser", "document", "localStorage", "confirm",
  `${source}\nreturn module.exports;`
);
const app = load(module, browser, undefined, undefined, undefined);
return app.classifyCanary(result);
"""


@pytest.mark.parametrize(
    "result,expected_level",
    [
        (None, "unknown"),
        (
            {
                "tor_ips": ["1.2.3.4"],
                "system_ip": "1.2.3.4",
                "leak_detected": False,
                "error": None,
            },
            "ok",
        ),
        (
            {
                "tor_ips": ["1.2.3.4", "5.6.7.8"],
                "system_ip": "5.6.7.8",
                "leak_detected": False,
                "error": None,
            },
            "ok",
        ),
        (
            {
                "tor_ips": ["1.2.3.4"],
                "system_ip": "8.8.8.8",
                "system_ips": ["8.8.8.8", "1.2.3.4"],
                "leak_detected": False,
                "error": None,
            },
            "ok",
        ),
        (
            {
                "tor_ips": ["1.2.3.4"],
                "system_ip": "192.168.1.1",
                "leak_detected": False,
                "error": None,
            },
            "warn",
        ),
        (
            {
                "tor_ips": ["1.2.3.4"],
                "system_ip": "8.8.8.8",
                "leak_detected": True,
                "error": None,
            },
            "leak",
        ),
        (
            {
                "tor_ips": [],
                "system_ip": None,
                "leak_detected": False,
                "error": "socks5: refused",
            },
            "error",
        ),
        (
            {
                "tor_ips": ["1.2.3.4"],
                "system_ip": None,
                "leak_detected": False,
                "error": "system: timeout",
            },
            "warn",
        ),
    ],
)
def test_classify_canary_levels(tb: TBClient, result, expected_level: str) -> None:
    out = tb.exec_chrome(CLASSIFY_JS, args=[_read_options_js(), result])
    assert out["level"] == expected_level, (
        f"classifyCanary({json.dumps(result)}) -> {out}; expected level={expected_level}"
    )


# --- F-179: code-review round-2 — non-SOCKS options.js polish ---


def test_F179_run_tor_test_error_path_does_not_fabricate_host() -> None:
    """`runTorTest`'s catch branch used to fabricate `host: "example.com"`
    when the runtime dispatch threw — no probe had actually run, but the
    rendered UI then showed "example.com" as the host that was tested.
    A user reading that result would wrongly conclude the addon probes
    example.com unconditionally. Fix: pass `host: null` so renderTorTest
    surfaces "—" for the host field.
    """
    import re
    js = _read("/addon/ui/options.js")
    m = re.search(
        r"async function runTorTest\b[\s\S]+?\n  \}",
        js,
    )
    assert m, "F-179: could not locate `runTorTest` body"
    body = m.group(0)
    # Strip comments so the change-rationale comment doesn't satisfy the
    # invariant (we want the CODE to be free of "example.com").
    body_code_only = re.sub(r"//[^\n]*", "", body)
    body_code_only = re.sub(r"/\*[\s\S]*?\*/", "", body_code_only)
    assert '"example.com"' not in body_code_only, (
        "F-179: runTorTest must NOT pass a hardcoded `host: \"example.com\"` "
        "in the dispatch-failure fallback result — no probe ran, so the "
        "host field should render as `—` (pass null/empty)."
    )


def test_F179_render_canary_null_checks_every_dom_lookup() -> None:
    """`renderCanary` used to dereference `badge.className`, `detail.hidden`,
    and several `document.getElementById(...).textContent` calls without
    null-checking. If any element was removed from the HTML the JS
    threw and took the whole Options page down. `renderTorTest` (the
    sister function) already guards every lookup; renderCanary now must
    too.
    """
    import re
    js = _read("/addon/ui/options.js")
    m = re.search(
        r"function renderCanary\b[\s\S]+?\n\}",
        js,
    )
    assert m, "F-179: could not locate `renderCanary` body"
    body = m.group(0)
    # Strip comments so unrelated mentions don't satisfy the invariant.
    body_code_only = re.sub(r"//[^\n]*", "", body)
    body_code_only = re.sub(r"/\*[\s\S]*?\*/", "", body_code_only)
    # Anti-pattern: an unguarded chain `document.getElementById("x").y = ...`
    # The `.textContent =` or `.hidden =` immediately after the call is
    # exactly the pre-fix pattern. Post-fix the textContent writes route
    # through a `setText`-style helper or have explicit `if (el)` guards.
    bad = re.findall(
        r"document\.getElementById\([^)]+\)\.(?:textContent|hidden|className)\s*=",
        body_code_only,
    )
    assert not bad, (
        f"F-179: `renderCanary` still has unguarded "
        f"`document.getElementById(...).{{textContent|hidden|className}} = ...` "
        f"patterns ({len(bad)} found). Wrap each lookup in an `if (el)` "
        f"guard (or route through a small helper) so a missing element "
        f"doesn't take the page down. Mirror `renderTorTest`'s guards."
    )


def test_F179_enable_disable_handlers_null_guard_dispatch_result() -> None:
    """The enable/disable click handlers read `r.ok` directly. If the
    background dispatch returns `undefined` (no listener, service worker
    unloaded mid-call, etc.), `r.ok` throws TypeError BEFORE the catch
    block can surface a useful error. Null-guard with `r && r.ok`.
    """
    import re
    js = _read("/addon/ui/options.js")
    # Locate the two handlers and check their body bodies for the guard.
    for needle in ("enable-hardening", "disable-hardening"):
        m = re.search(
            rf'cmd:\s*"{needle}"[\s\S]+?\n    \}}',
            js,
        )
        assert m, f"F-179: could not locate handler invoking `{needle}`"
        block = m.group(0)
        # Pre-fix pattern: `r.ok ?` without a preceding `r &&`. Match the
        # specific ternary construction; allow either `r && r.ok` or
        # `r?.ok` as acceptable forms.
        assert re.search(r"r\s*&&\s*r\.ok\b|r\?\.ok\b", block), (
            f"F-179: the `{needle}` handler must null-guard the dispatch "
            f"result (e.g. `r && r.ok ?`) — pre-fix `r.ok` threw "
            f"TypeError when r was undefined, bypassing the catch and "
            f"leaving the buttons disabled until reload (the `finally` "
            f"would still run but the user-visible error path is broken)."
        )


def test_F179_data_i18n_elements_have_no_element_children() -> None:
    """`applyI18n()` does `el.textContent = t(key)` for every
    `[data-i18n]` element. `textContent` replaces ALL children, so if any
    `data-i18n` element ever gets element children (a nested span, an
    icon, a placeholder input, etc.) those children get silently
    deleted at page load. The codebase currently respects this
    invariant — all data-i18n elements are leaf-text — but there's no
    test guarding against a future regression. This is that test.
    """
    import re
    html = _read("/addon/ui/options.html")
    # Find each [data-i18n] element. For each, extract the inner block
    # up to its matching closing tag and assert it contains no child
    # element start tag. Approximation good enough for this codebase
    # (no SVG with self-closing-but-non-leaf elements).
    pattern = re.compile(
        r"<([a-zA-Z][a-zA-Z0-9]*)[^>]*\bdata-i18n=\"([^\"]+)\"[^>]*>"
        r"([\s\S]*?)"
        r"</\1>",
    )
    violations = []
    for m in pattern.finditer(html):
        tag, key, inner = m.group(1), m.group(2), m.group(3)
        # Skip self-closing or empty.
        if not inner.strip():
            continue
        # Reject any nested element start tag.
        if re.search(r"<[a-zA-Z]", inner):
            violations.append((tag, key))
    assert not violations, (
        f"F-179: every `data-i18n` element MUST contain only text "
        f"(no element children) — `applyI18n()` writes `el.textContent` "
        f"which silently clobbers any nested elements. Violations: "
        f"{violations}. If a section needs i18n on a parent that wraps "
        f"other elements, put `data-i18n` on a leaf `<span>` instead."
    )
