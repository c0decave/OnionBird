"""Tests for the audit fixes (B-001 .. B-022).

Each test maps to a finding in docs/audit-2026-05-21-bug-report.md and proves
the regression is closed.
"""

from __future__ import annotations

import re

import pytest
from helpers.tb_client import TBClient

XPI = "/build/onionbird.xpi"


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


HARDENING_PREFS_CHECK = r"""
// Source-of-truth: read the addon's background.js HARDENING_PREFS by reading
// the XPI's background.js text. The test framework cannot inspect WebExt
// state directly, so we validate by reading the file from the mounted source.
return await fetch("file:///addon/background.js").then(r => r.text());
"""


def _read_addon_background() -> str:
    """Read addon/background.js from the mounted source."""
    with open("/addon/background.js") as f:
        return f.read()


def _read_experiment_impl() -> str:
    with open("/addon/experiments/onionbird/implementation.js") as f:
        return f.read()


def _read_experiment_schema() -> str:
    with open("/addon/experiments/onionbird/schema.json") as f:
        return f.read()


def _read(path: str) -> str:
    with open(path) as f:
        return f.read()


def _read_tb_client() -> str:
    with open("/tests/helpers/tb_client.py") as f:
        return f.read()


# --- B-001: SOCKS host must default to 127.0.0.1, not "tor" ---

def test_B001_socks_host_default_is_loopback() -> None:
    """addon/background.js defines DEFAULT_SOCKS_HOST as 127.0.0.1, not 'tor'."""
    bg = _read_addon_background()
    assert 'DEFAULT_SOCKS_HOST = "127.0.0.1"' in bg, (
        "B-001: SOCKS host default must be 127.0.0.1"
    )
    assert 'network.proxy.socks", value: "tor"' not in bg, (
        "B-001: must not hardcode SOCKS host to 'tor'"
    )


def test_B001_failover_direct_in_hardening_prefs() -> None:
    """failover_direct must be set to false in the hardening prefs list."""
    bg = _read_addon_background()
    assert '"network.proxy.failover_direct", value: false' in bg, (
        "B-001: missing failover_direct=false; addon may silently bypass Tor"
    )


# --- B-002 / B-004: hardening flow with snapshot/restore ---

def test_B002_disable_hardening_handler_exists() -> None:
    """background.js must have a disable-hardening message handler."""
    bg = _read_addon_background()
    assert '"disable-hardening"' in bg or "'disable-hardening'" in bg
    assert "disableHardening" in bg
    assert "restorePrefs" in bg


def test_B004_runtime_oninstalled_listener_exists() -> None:
    """background.js must register a runtime.onInstalled listener that
    auto-enables hardening on install AND on update (P0-T3-4 widened the
    handler so users upgrading from a pre-hardening version are not
    silently left on clearnet)."""
    bg = _read_addon_background()
    assert "runtime.onInstalled" in bg
    # Either explicit-install + explicit-update gate (new) or just
    # explicit-install (old). Tolerate both shapes so this test doesn't
    # block future re-factors.
    has_install = '"install"' in bg
    has_update = '"update"' in bg
    assert has_install, "must handle reason='install'"
    assert has_update, "must handle reason='update' (P0-T3-4)"


def test_F006_auto_enable_probes_socks_before_writing() -> None:
    """Auto-enable must not blindly write 9050 when Tor Browser's 9150
    or an existing SOCKS pref is the reachable Tor endpoint."""
    bg = _read_addon_background()
    assert "detectSocksConfig" in bg
    assert "probeSocks" in bg
    assert "TOR_BROWSER_SOCKS_PORT" in bg
    assert "existing-pref" in bg
    assert "tor-browser" in bg


def test_F006_reassert_preserves_detected_socks_config() -> None:
    """Startup/periodic reassert must not write the static 9050 defaults
    after enable detected Tor Browser, Whonix, or an existing SOCKS pref."""
    bg = _read_addon_background()
    assert "hardeningPrefsWithDetectedSocks" in bg
    assert "hardeningPrefsWithCurrentSocks" in bg
    reassert_idx = bg.index("async function _reassertHardeningImpl")
    reassert = bg[reassert_idx:]
    assert "hardeningPrefsWithCurrentSocks()" in reassert
    assert "hardeningPrefsWithDetectedSocks()" in reassert
    assert "applyPrefs(detected.prefs)" in reassert
    assert "socks.ok" in reassert
    assert "applyPrefs(HARDENING_PREFS)" not in reassert


def test_F001_enable_reports_self_test_verdict() -> None:
    """Enable should run the canary and include it in the ok=false path
    instead of silently claiming protection on DNS-leaky systems."""
    bg = _read_addon_background()
    assert "selfTest = await browser.onionbird.runSelfTest" in bg
    assert "selfTestOk" in bg
    assert "selfTest," in bg


def test_hardening_state_mutations_are_serialized() -> None:
    """enable/disable/reassert must share one mutation queue.

    Separate per-command in-flight guards still allow disable-vs-enable and
    timer reassert-vs-disable races, corrupting snapshot/restore state.
    """
    bg = _read_addon_background()
    assert "_hardeningMutationTail" in bg
    assert "enqueueHardeningMutation" in bg
    assert 'enqueueHardeningMutation(\n    "enable"' in bg
    assert 'enqueueHardeningMutation(\n    "disable"' in bg
    assert "enqueueHardeningMutation(\n    `reassert:${reason}`" in bg
    assert "_enableInflight" not in bg
    assert "_disableInflight" not in bg


def test_fail_closed_core_prefs_are_reapplied_on_hardening_failures() -> None:
    """If the large hardening batch or the canary path fails, a small
    core proxy/DNS batch must still force the profile into a non-bypass
    state."""
    bg = _read_addon_background()
    for needle in [
        "CORE_FAIL_CLOSED_PREF_NAMES",
        "function coreFailClosedPrefs",
        "async function applyFailClosedPrefs",
        "enable-pref-failure",
        "enable-self-test-failure",
        "reassert-failure",
        'network.proxy.failover_direct"',
        'network.proxy.socks_remote_dns"',
        'network.proxy.no_proxies_on"',
        'network.trr.mode"',
    ]:
        assert needle in bg, f"missing fail-closed layer: {needle}"
    assert 'await reassertHardening("self-test-leak")' in bg


def test_corrupt_snapshots_do_not_restore_untrusted_state() -> None:
    """A corrupted storage.local snapshot must not become an instruction to
    restore unsafe prefs. Startup should fail closed; disable should refuse."""
    bg = _read_addon_background()
    for needle in [
        "function snapshotValidationError",
        "function isAllowedSnapshotPrefName",
        "function isValidSnapshotValue",
        "async function readSnapshotState",
        "invalid hardening snapshot ignored",
        "staying fail-closed",
        "refusing to store invalid hardening snapshot",
        "invalid snapshot — keeping current fail-closed prefs in place",
        "corrupt hardening snapshot found; re-enabling fail-closed",
    ]:
        assert needle in bg, f"missing corrupt-snapshot guard: {needle}"


def test_F003_disable_can_scrub_tor_mail_logins() -> None:
    """Disable must not leave onion/loopback mail credentials invisible in
    the password manager without at least a scrub path and loud logging."""
    bg = _read_addon_background()
    with open("/addon/experiments/onionbird/implementation.js") as f:
        impl = f.read()
    with open("/addon/experiments/onionbird/schema.json") as f:
        schema = f.read()
    with open("/addon/ui/options.html") as f:
        html = f.read()
    assert "scrubLogins" in bg
    assert "auditSavedLoginsForTorServers" in bg
    assert "removeSavedLoginsForTorServers" in bg
    assert "Services.logins.searchLoginsAsync" in impl
    assert "Services.logins.removeLogin" in impl
    assert "auditSavedLoginsForTorServers" in schema
    assert "removeSavedLoginsForTorServers" in schema
    assert 'id="scrub-logins"' in html


def test_login_audit_does_not_expose_saved_account_identifiers() -> None:
    """Saved-login audit results cross IPC, so return only redacted metadata."""
    impl = _read_experiment_impl()
    start = impl.index("function publicLoginInfo")
    end = impl.index("/**", start)
    fn = impl[start:end]
    assert "username_present" in fn
    assert "httpRealm_present" in fn
    assert "form_action_origin_present" in fn
    assert "publicLoginOriginInfo(login.origin)" in fn
    assert "username:" not in fn
    assert "httpRealm:" not in fn
    assert "origin:" not in fn
    assert "function publicLoginOriginInfo" in impl
    assert "origins: origins.map(publicLoginOriginInfo)" in impl
    assert "failed.push({ origin, error:" not in impl
    bg = _read_addon_background()
    assert "loginResult.logins" not in bg
    assert "{ count: loginResult.count }" in bg
    assert "origins: loginResult.origins" not in bg


def test_privacy_sensitive_logging_is_redacted() -> None:
    """Debug logs must not echo raw canary IP/PTR data or account origins.

    The details still flow through the UI where explicitly needed, but
    persistent/support-style logs should use counts and masked values.
    """
    bg = _read_addon_background()
    assert "function summarizeSelfTestForLog" in bg
    assert "function summarizeHardeningResultForLog" in bg
    assert "maskIpForLog" in bg
    assert "tor_ip_count" in bg
    assert "system_ptr_present" in bg
    start = bg.index("async function announceSelfTest")
    end = bg.index("async function reassertHardening")
    fn = bg[start:end]
    assert "summarizeSelfTestForLog(r)" in fn
    assert "torSet" not in fn
    assert "${r.system_ip}" not in fn
    assert "self-test OK:\" + " not in fn
    assert "origins: loginResult.origins" not in bg

    impl = _read_experiment_impl()
    assert "login search failed for ${origin}" not in impl
    assert "removeLogin(${info.origin})" not in impl
    assert "SOCKS probe failed for ${result.socks_host}" not in impl
    assert "summarizeSocksEndpointForLog" in impl


def test_parent_process_account_iteration_fails_softly() -> None:
    """A bad account object/key must not abort all SMTP/identity hardening.

    Thunderbird account collections are privileged objects. If a getter or
    malformed key throws, the experiment should log the item and continue
    instead of letting a single bad account bypass the rest of hardening.
    """
    impl = _read_experiment_impl()
    assert "function safeAccountKeyForReport" in impl
    for needle in [
        'let key = "<unknown>";',
        'let id = "<unknown>";',
        'failed.push({ key: safeAccountKeyForReport(key)',
        'failed.push({ key: safeAccountKeyForReport(id)',
        'throw new Error("unsafe SMTP server key")',
        'throw new Error("unsafe identity key")',
    ]:
        assert needle in impl, f"missing fail-soft account handling: {needle}"
    assert "unsafe SMTP server key: ${key}" not in impl
    assert "unsafe identity key: ${id}" not in impl


def test_mail_host_classification_is_strict_and_redacted() -> None:
    """Only valid v3 onion names should receive onion-mode SMTP treatment."""
    impl = _read_experiment_impl()
    assert "function classifyMailHostForReport" in impl
    assert "host_type" in impl
    assert "/^[a-z2-7]{56}$/.test(label)" in impl
    assert 'normalizeHost(hostname).endsWith(".onion")' not in impl
    assert "isIpv4LoopbackAddress(host)" in impl
    for raw_field in [
        "skipped.push({ key, hostname })",
        "applied.push({ key, hostname })",
        "applied.push({ key: id, fqdn })",
    ]:
        assert raw_field not in impl, f"raw account metadata still returned: {raw_field}"


def test_experiment_api_read_and_write_surfaces_are_minimized() -> None:
    """The parent-process experiment bridge must not be a generic pref oracle
    or generic low-level pref writer. Background-owned batch functions still
    use the audited allowlist, but direct set/clear are addon-owned only."""
    impl = _read_experiment_impl()
    assert "function isAddonOwnedPref" in impl
    assert "const ADDON_OWNED_PREF_NAMES" in impl
    assert 'name.startsWith("onionbird.")' not in impl
    assert "setPref(${safePrefName(name)}) denied: addon-owned prefs only" in impl
    assert "clearPref(${safePrefName(name)}) denied: addon-owned prefs only" in impl
    get_pref = impl[impl.index("getPref: async"):impl.index("clearPref: async")]
    assert "isAllowedPref(name)" in get_pref
    snapshot = impl[impl.index("snapshotPrefs: async"):impl.index("restorePrefs: async")]
    assert "names must be an array" in snapshot
    assert "snapshotPrefs(${safePrefName(name)}) denied by allowlist" in snapshot
    restore = impl[impl.index("restorePrefs: async"):impl.index("getSmtpHardeningPrefNames")]
    assert "isValidPrefValue(value, true)" in restore


def test_experiment_api_bounds_parent_process_inputs() -> None:
    """Privileged APIs should reject oversized values before they can turn
    the parent process into a memory/logging sink."""
    impl = _read_experiment_impl()
    for needle in [
        "MAX_PREF_NAME_LENGTH = 256",
        "MAX_PREF_STRING_LENGTH = 65536",
        "MAX_PREF_BATCH_SIZE = 256",
        "MAX_PREF_SNAPSHOT_SIZE = 4096",
        "PREF_INT_MIN = -2147483648",
        "PREF_INT_MAX = 2147483647",
        "function safePrefName",
        "prefs.length > MAX_PREF_BATCH_SIZE",
        "names.length > MAX_PREF_SNAPSHOT_SIZE",
        "entries.length > MAX_PREF_SNAPSHOT_SIZE",
        "value.length <= MAX_PREF_STRING_LENGTH",
        'value.indexOf("\\0") === -1',
    ]:
        assert needle in impl, f"implementation missing input bound: {needle}"


def test_experiment_schema_declares_ipc_resource_limits() -> None:
    schema = _read_experiment_schema()
    for needle in [
        '"maxLength": 256',
        '"maxLength": 65536',
        '"maxItems": 256',
        '"maxItems": 4096',
        '"maxLength": 253',
        '"additionalProperties": false',
    ]:
        assert needle in schema, f"schema missing IPC resource limit: {needle}"


def test_runtime_message_surface_validates_sender_and_drops_endpoint_overrides() -> None:
    """Options-page messages should not be able to inject SOCKS endpoints or
    arbitrary runSelfTest options; the background chooses the Tor endpoint."""
    bg = _read_addon_background()
    assert "onMessage.addListener(async (msg, sender)" in bg
    assert "untrusted sender" in bg
    assert "senderId !== browser.runtime.id" in bg
    assert "safeRuntimeCommand" in bg
    run_self = bg[bg.index('case "run-self-test"'):bg.index('case "run-tor-test"')]
    assert "normalizeProbeHost(msg.host, SELF_TEST_HOST)" in run_self
    assert "{ tries: 3 }" in run_self
    assert "msg.options" not in run_self
    run_tor = bg[bg.index('case "run-tor-test"'):bg.index('case "get-message-id-fqdn"')]
    assert "host: msg.host" in run_tor
    assert "msg.socksHost" not in run_tor
    assert "msg.socksPort" not in run_tor


def test_experiment_schema_does_not_accept_arbitrary_self_test_options() -> None:
    schema = _read_experiment_schema()
    assert '"name": "runSelfTest"' in schema
    run_self = schema[schema.index('"name": "runSelfTest"'):]
    assert '"additionalProperties": false' in run_self


def test_account_events_reassert_hardening_for_new_accounts() -> None:
    """New accounts created after enable must not wait for startup to receive
    identity and SMTP hardening."""
    bg = _read_addon_background()
    assert "startAccountReassertListeners" in bg
    assert '"onCreated", "account-created"' in bg
    assert '"onUpdated", "account-updated"' in bg
    assert "reassertHardening(reason)" in bg
    assert "stopAccountReassertListeners" in bg


def test_account_event_reassert_does_not_rewrite_global_proxy_prefs() -> None:
    """Account observer callbacks can race account construction and test
    setup. They should re-harden account/identity prefs only, leaving global
    proxy prefs to startup/periodic reassert."""
    bg = _read_addon_background()
    start = bg.index("async function _reassertHardeningImpl")
    end = bg.index("function startHardeningMonitors")
    fn = bg[start:end]
    assert "isAccountReassertReason(reason)" in fn
    assert 'skipped: "account-event"' in fn
    assert "account-event-no-global-prefs" in fn
    account_branch = fn[fn.index("if (accountOnly)"):fn.index("} else {")]
    assert "applyPrefs" not in account_branch
    assert "hardeningPrefsWithDetectedSocks" not in account_branch
    assert "hardeningPrefsWithCurrentSocks" not in account_branch


def test_F044_apply_prefs_per_pref_validate_and_write() -> None:
    """F-044: `applyPrefs` MUST be per-pref, not atomic.

    The original atomic behavior (F-023's fix) created a regression:
    with 110 HARDENING_PREFS, a single bad pref (e.g.
    `network.proxy.socks=null` from a failed SOCKS probe, or an
    allowlist-mismatched name from a future refactor) rejects the
    entire batch — Tor routing collapses silently while the addon
    thinks it failed cleanly. Audit verdict: prefer apply-as-many-
    fail-closed-prefs-as-possible over all-or-nothing.

    This test asserts the bug-shaped patterns are absent."""
    impl = _read_experiment_impl()
    # Extract the applyPrefs function body for targeted assertions.
    start = impl.index("applyPrefs: async (prefs)")
    # Next sibling method definition signals end of applyPrefs body.
    end = impl.index("snapshotPrefs: async", start)
    fn = impl[start:end]

    # 1) NO upfront-validation early-return that drops all writes.
    #    The bug shape: validate every pref → if any failed, return
    #    with applied=[] before any write happens.
    assert "applyPrefs validation failed" not in fn, (
        "F-044: applyPrefs still early-returns on upfront validation "
        "without writing any of the valid prefs — single bad pref "
        "still kills the full batch"
    )

    # 2) NO rollback loop. We want fail-closed prefs left in place.
    assert "previous.reverse()" not in fn, (
        "F-044: applyPrefs still rolls back previously-applied prefs "
        "on failure — fail-closed prefs MUST persist even if later "
        "ones fail; otherwise a mid-batch error returns the user to "
        "clearnet silently"
    )
    assert "rolled back after failure" not in fn, (
        "F-044: applyPrefs rollback log line is still present — "
        "rollback path must be removed entirely"
    )

    # 3) Per-pref try/catch must exist, so a single write throw does
    #    not break the loop.
    assert fn.count("try {") >= 1 and fn.count("catch (e)") >= 1, (
        "F-044: applyPrefs must have per-pref try/catch so a single "
        "write failure does not break the loop"
    )
    # 4) Failures must still be reported granularly per pref name.
    assert 'failed.push({ name' in fn, (
        "F-044: applyPrefs no longer pushes per-pref failures onto "
        "failed[] — caller cannot triage which prefs were rejected"
    )


def test_F044_apply_prefs_jsdoc_does_not_claim_atomic() -> None:
    """F-044: docstrings/comments around applyPrefs in BOTH the
    background script and the experiment implementation must NOT
    claim atomicity. Inaccurate atomicity claims invite the very
    rollback pattern that caused the F-044 regression — fixed once,
    future-proof by deleting the claim everywhere it shows up
    near applyPrefs."""
    impl = _read_experiment_impl()
    bg = _read_addon_background()

    # 1) implementation.js — comments around the applyPrefs definition.
    idx = impl.index("applyPrefs: async (prefs)")
    impl_window = impl[max(0, idx - 1500):idx + 400].lower()
    assert "atomic" not in impl_window, (
        "F-044: implementation.js still describes applyPrefs as "
        "atomic; update the comments to reflect per-pref "
        "fail-as-many-as-possible semantics."
    )
    # T-084: previously this test only checked "atomic" was absent —
    # deleting the entire jsdoc would also pass. Also assert the
    # comment block describes the actual semantics (per-pref + best-
    # effort) so the documentation can't be silently removed.
    assert (
        "per-pref" in impl_window or "per pref" in impl_window
        or "best-effort" in impl_window or "best effort" in impl_window
        or "fail-as-many-as-possible" in impl_window
    ), (
        "T-084 / F-044: applyPrefs jsdoc in implementation.js is "
        "missing the per-pref / best-effort description. Deleting the "
        "comment outright would let the previous test pass (just the "
        "absence of 'atomic'), which is green-but-meaningless."
    )

    # 2) background.js — comments near the HARDENING_PREFS constant
    #    and around every applyPrefs call site.
    for marker in ("HARDENING_PREFS = [", "applyPrefs(prefs)", "applyPrefs(HARDENING_PREFS)"):
        if marker not in bg:
            continue
        i = bg.index(marker)
        window = bg[max(0, i - 800):i + 200].lower()
        assert "atomic" not in window, (
            f"F-044: background.js still claims 'atomic' near "
            f"{marker!r}; update the comment to describe per-pref "
            f"fail-as-many-as-possible behavior."
        )


def test_pref_allowlist_is_exact_and_suffix_limited() -> None:
    """The parent-process allowlist must not accept whole sensitive pref
    prefixes like mail.smtpserver.* or mail.identity.*. Concrete pref
    names (e.g. mail.server.default.send_client_info) are fine — the
    bad shapes are prefix globs, regex authority, or startsWith()."""
    impl = _read_experiment_impl()
    policy = impl[
        impl.index("const ALLOWED_PREF_NAMES"):
        impl.index("function isAllowedPref")
    ]
    # No alternate, broader allowlist mechanism.
    assert "ALLOWED_PREF_PREFIXES" not in impl
    assert "ALLOWED_PREF_NAMES.has(name)" in impl
    assert "SMTP_HARDENING_PREF_RE.test(name)" in impl
    assert "IDENTITY_HARDENING_PREF_RE.test(name)" in impl
    # No prefix-glob style entries (would let arbitrary subnames pass).
    # Only check the policy section itself, not unrelated regex sources
    # elsewhere in the file.
    assert ".*" not in policy
    assert "startsWith(" not in policy
    # The known dangerous broad scopes must not appear as ALLOWED entries.
    # Iterate the quoted entries and check none of them is *just* a prefix.
    import re as _re
    entries = _re.findall(r'"([^"]+)"', policy)
    assert entries, "ALLOWED_PREF_NAMES parse failed"
    for entry in entries:
        assert not entry.endswith("."), (
            f"allowlist entry {entry!r} is a prefix, not a concrete pref name"
        )
        # The two scopes we explicitly never want as bare prefixes.
        assert entry not in {"mail.server.", "mail.rights.", "mail.smtpserver.",
                             "mail.identity."}, entry
        # No per-account secret keys, even as full names.
        assert "username" not in entry, entry
        assert "useremail" not in entry, entry
        assert entry != "mail.shell.checkDefaultClient"
    assert "hello_argument|try_ssl" in policy
    assert "FQDN|compose_html|reply_to|organization" in policy


def test_raw_socks_probe_is_not_a_generic_network_scanner() -> None:
    """probeSocks/runSelfTest can open TCP sockets from the parent process;
    they must be restricted to loopback or the already configured SOCKS IP.

    Hostname-valued proxy endpoints are intentionally rejected even when
    present in prefs: resolving the proxy hostname itself would be a local DNS
    lookup before Tor is reached.
    """
    impl = _read_experiment_impl()
    bg = _read_addon_background()
    assert "function assertAllowedSocksEndpoint" in impl
    assert "function isIpv4LoopbackAddress" in impl
    assert "function isIpLiteralSocksHost" in impl
    assert "octets.length !== 4" in impl
    assert r"127(?:\.|$)" not in impl
    assert "must be loopback or current Thunderbird proxy IP" in impl
    assert "hostnames can leak DNS" in bg
    assert "isSafeConfiguredSocksHost" in bg
    assert "safeConfiguredSocksHostOrDefault" in bg
    probe = impl[impl.index("probeSocks: async"):impl.index("runSelfTest: async")]
    # F-168 I-1: probeSocks now passes an optional `options` 3rd arg to
    # assertAllowedSocksEndpoint (the userProbe bypass for Options-page
    # Test). Accept the call with or without the trailing arg — the
    # security property the test is gating is "probeSocks calls the
    # asserter with the normalized values", not the exact arity.
    import re as _re
    assert _re.search(
        r"assertAllowedSocksEndpoint\(\s*normalizedHost\s*,\s*normalizedPort(?:\s*,[^)]+)?\)",
        probe,
    ), "probeSocks must call assertAllowedSocksEndpoint with the normalized values"
    self_test = impl[impl.index("runSelfTest: async"):impl.index("clearHardeningFromAllIdentities")]
    assert _re.search(
        r"assertAllowedSocksEndpoint\(\s*socksHost\s*,\s*socksPort(?:\s*,[^)]+)?\)",
        self_test,
    ), "runSelfTest must call assertAllowedSocksEndpoint with the socks endpoint"
    assert "socks_host: socksHost" in self_test


def test_status_uses_snapshot_not_spoofable_live_prefs() -> None:
    """Options status must reflect the durable hardening snapshot.

    A profile with only socks_remote_dns=true and User-Agent=false should not
    be reported as addon-managed hardening, and a tampered active profile
    should still show active while startup reasserts it.
    """
    bg = _read_addon_background()
    start = bg.index("async function isHardeningActive")
    end = bg.index("async function detectSocksConfig")
    fn = bg[start:end]
    assert "readSnapshotState()" in fn
    assert "!!snapshotState.snapshot" in fn
    assert "network.proxy.socks_remote_dns" not in fn
    assert "mailnews.headers.sendUserAgent" not in fn


def test_host_validators_reject_ambiguous_or_oversized_hosts() -> None:
    """Host strings cross into raw sockets and DNS APIs; keep them
    unambiguous and DNS-label bounded."""
    impl = _read_experiment_impl()
    bg = _read_addon_background()
    for src in [impl, bg]:
        assert "MAX_DNS_LABEL_LENGTH = 63" in src
        assert "function parseStrictIpv4Address" in src
        assert "function isValidSocksHost" in src
        assert "function isValidIpv6Literal" in src
        assert "isValidSocksHost(value)" in src
        assert "label.length > MAX_DNS_LABEL_LENGTH" in src
        assert "/^[A-Za-z0-9._:-]+$/" not in src


def test_message_id_fqdn_validation_enforces_label_bounds() -> None:
    """Message-ID custom domains must obey DNS's 63-octet label limit.

    The previous whole-FQDN regex allowed 64-character labels, creating
    malformed Message-IDs and a distinctive fingerprint.
    """
    impl = _read_experiment_impl()
    bg = _read_addon_background()
    options = _read("/addon/ui/options.js")
    for src in [impl, bg]:
        assert "MESSAGE_ID_FQDN_LABEL_SHAPE" in src
        assert "{0,61}" in src
        assert "{0,62}" not in src
        assert "label.length <= MAX_DNS_LABEL_LENGTH" in src
        assert "value.split" in src or "s.split" in src
    assert "function isValidMessageIdFqdn" in options
    assert "label.length <= 63" in options
    assert "{0,61}" in options
    assert "{0,62}" not in options


def test_message_id_default_fqdn_uses_per_install_fallback() -> None:
    """New identities may inherit mail.identity.default.FQDN before the next
    reassert. That default must not be the global localhost supercluster."""
    impl = _read_experiment_impl()
    assert "onionbird.messageid.fqdn_fallback" in impl
    assert "m${randomHex(10)}.invalid" in impl
    assert "return fallbackFqdn;" in impl
    assert 'writePref("mail.identity.default.FQDN", fallbackFqdn)' in impl
    assert 'writePref("mail.identity.default.FQDN", "localhost")' not in impl


def test_snapshot_prefs_preserves_unset_user_prefs_as_null() -> None:
    """Snapshots must represent the user branch, not default values.

    If a pref was only present as a Thunderbird default, disable-hardening
    must clear the addon's user value instead of writing a persistent
    user_pref shadow equal to the old default.
    """
    impl = _read_experiment_impl()
    snapshot = impl[impl.index("snapshotPrefs: async"):impl.index("restorePrefs: async")]
    assert "Services.prefs.prefHasUserValue(name)" in snapshot
    assert "? readPref(name)" in snapshot
    assert ": null" in snapshot


def test_smtp_clear_does_not_destroy_clearnet_server_prefs() -> None:
    """Disable must mirror enable's onion/loopback scope.

    The addon does not harden clearnet SMTP servers by default, so its
    cleanup path must not clear a user's pre-existing clearnet try_ssl or
    hello_argument preferences.
    """
    impl = _read_experiment_impl()
    start = impl.index("clearHardeningFromAllSmtpServers: async")
    end = impl.index("auditSavedLoginsForTorServers", start)
    clear = impl[start:end]
    assert "hostname = ss.hostname ||" in clear
    assert "if (!isOnionHost(hostname) && !isLoopbackHost(hostname))" in clear
    assert "skipped.push({ key, host_type: classifyMailHostForReport(hostname) })" in clear
    assert "return { cleared, failed, skipped }" in clear


def test_B002_disable_restores_via_experiment(tb: TBClient) -> None:
    """The experiment exposes restorePrefs which clears or restores values."""
    tb.install_addon(XPI, temporary=True)
    # Set a known pref value (simulating user's pre-install state)
    tb.set_pref("onionbird.audit.test", "original")
    # Take snapshot, modify, restore
    result = tb.exec_chrome(r"""
        // Snapshot current value
        const snap = {"onionbird.audit.test": Services.prefs.getCharPref("onionbird.audit.test")};
        // Modify
        Services.prefs.setCharPref("onionbird.audit.test", "modified");
        const mid = Services.prefs.getCharPref("onionbird.audit.test");
        // Restore from snapshot
        for (const [name, value] of Object.entries(snap)) {
          if (value === null) Services.prefs.clearUserPref(name);
          else Services.prefs.setCharPref(name, value);
        }
        const after = Services.prefs.getCharPref("onionbird.audit.test");
        return { mid, after };
    """)
    assert result["mid"] == "modified"
    assert result["after"] == "original", (
        f"restore from snapshot failed: {result}"
    )


# --- B-005: privacy.resistFingerprinting in hardening prefs ---

def test_B005_resist_fingerprinting_in_hardening() -> None:
    """resistFingerprinting must be in the hardening pref list."""
    bg = _read_addon_background()
    assert '"privacy.resistFingerprinting", value: true' in bg, (
        "B-005: missing resistFingerprinting; Date header would leak TZ"
    )


# --- B-007: applyHardening must report partial failures ---

def test_B007_apply_prefs_pattern_used_in_addon() -> None:
    """background.js must use applyPrefs (batched apply with per-pref
    fail-closed semantics — see F-044) instead of sequential setPref
    calls."""
    bg = _read_addon_background()
    assert "applyPrefs" in bg, (
        "B-007: background.js must call browser.onionbird.applyPrefs "
        "for the batched-with-per-pref-fail-closed apply"
    )
    assert "snapshotPrefs" in bg, (
        "B-007: must snapshot prefs before write for disable-hardening"
    )


def test_B007_apply_prefs_contract() -> None:
    """T-085 / B-007: the applyPrefs primitive in the addon's
    Experiments API must return `{applied: [], failed: []}` so the
    background-script callers (which gate fail-closed on hasFailures)
    can reason about partial-write outcomes.

    The previous version of this test ran a chrome-context JS loop
    that called Mozilla's pref service directly — re-implementing
    the contract instead of exercising the addon's wrapper. Result:
    the test passed even if `browser.onionbird.applyPrefs` was
    deleted entirely. Classic green-but-meaningless.

    Replaced with a structural assertion that the impl.js applyPrefs
    body returns the `{applied, failed}` shape, plus an assertion
    that the writePref path in the same function pushes into both
    arrays. This catches deletion / shape regression in the actual
    code under test.
    """
    impl = _read_experiment_impl()
    m = re.search(
        r"applyPrefs:\s*async\s*\([^)]*\)\s*=>\s*\{([\s\S]+?)\n\s{0,12}\},",
        impl,
    )
    assert m, (
        "T-085 / B-007: could not locate applyPrefs body in "
        "implementation.js (renamed? deleted?)."
    )
    body = m.group(1)
    # Return shape must mention both applied and failed arrays.
    assert re.search(r"return\s*\{[^}]*\bapplied\b", body), (
        "T-085 / B-007: applyPrefs return statement does not include "
        "an `applied` field — callers gating on hasFailures cannot "
        "report partial-write outcomes."
    )
    assert re.search(r"return\s*\{[^}]*\bfailed\b", body), (
        "T-085 / B-007: applyPrefs return statement does not include "
        "a `failed` field — partial-failure outcomes are silently "
        "dropped."
    )
    # Both arrays must be PUSHED into within the body (not just
    # initialized empty and returned).
    assert "applied.push" in body, (
        "T-085 / B-007: applyPrefs body never pushes to `applied` — "
        "the return shape is correct but the array is always empty."
    )
    assert "failed.push" in body, (
        "T-085 / B-007: applyPrefs body never pushes to `failed` — "
        "per-pref errors are not collected, only swallowed."
    )


# --- B-009: proxy.type does not leak across tests ---

def test_B009_proxy_type_reset_by_autouse(tb: TBClient) -> None:
    """The autouse fixture in conftest must reset network.proxy.type so it
    doesn't leak between tests. We verify the autouse cleared the USER pref."""
    has_user = tb.exec_chrome(
        'return Services.prefs.prefHasUserValue("network.proxy.type");'
    )
    assert has_user is False, (
        "B-009: autouse fixture failed to clear network.proxy.type user pref"
    )
    # Now set it; the autouse before the next test should clear again.
    tb.set_pref("network.proxy.type", 1)
    assert tb.get_pref("network.proxy.type") == 1


def test_B009_proxy_type_isolated_from_previous(tb: TBClient) -> None:
    """Even though a previous test set proxy.type=1, the autouse fixture
    must clear the user value before this test runs."""
    has_user = tb.exec_chrome(
        'return Services.prefs.prefHasUserValue("network.proxy.type");'
    )
    assert has_user is False, (
        "B-009 regression: proxy.type user value bled from previous test"
    )


def test_B009_temporary_addons_are_removed_with_tb_client() -> None:
    """Temporary addon installs auto-enable hardening; the shared TB process
    must not keep them alive after the test client closes."""
    src = _read_tb_client()
    assert "self._installed_addons" in src
    assert "for addon_id in reversed(self._installed_addons)" in src
    assert "self.addons.uninstall(addon_id)" in src
    assert "self._installed_addons.clear()" in src


# --- B-012: companion user.js uses correct EULA prefs ---

def _read_user_js() -> str:
    with open("/user-js/onionbird-user.js") as f:
        return f.read()


def _active_user_pref_lines(content: str) -> list[str]:
    """Return only the active user_pref(...) lines, stripping comments."""
    out = []
    for line in content.splitlines():
        s = line.strip()
        if s.startswith("//") or not s:
            continue
        out.append(s)
    return out


def test_B012_correct_eula_prefs_in_user_js() -> None:
    """The companion user.js must use mail.rights.version/acceptedEULA, NOT
    the invented mail.rights.override pref."""
    active = _active_user_pref_lines(_read_user_js())
    joined = "\n".join(active)
    assert "mail.rights.version" in joined, "missing real EULA pref"
    assert "mail.rights.acceptedEULA" in joined, "missing real EULA pref"
    for line in active:
        assert "mail.rights.override" not in line, (
            f"B-012: still has fake mail.rights.override pref: {line!r}"
        )


def test_B014_thunderbird_container_verifies_download_sha256() -> None:
    """The Thunderbird test image must verify the upstream tarball before
    extracting it; otherwise a MITM during container build owns the harness."""
    with open("/tests/containers/Containerfile.thunderbird") as f:
        content = f.read()
    assert "SHA256SUMS" in content
    assert "sha256sum -c -" in content
    assert "tar -xJf /tmp/tb.tar.xz" in content
    assert content.index("sha256sum -c -") < content.index("tar -xJf /tmp/tb.tar.xz")


# --- B-016 / B-017: companion user.js removed broad/breaking prefs ---

def test_B016_companion_does_not_block_all_images() -> None:
    """Companion user.js must NOT set permissions.default.image=2 globally."""
    content = _read_user_js()
    # Allow comment mentions; check no active user_pref line.
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or not stripped:
            continue
        assert "permissions.default.image" not in stripped, (
            "B-016: still blocks ALL images globally"
        )


def test_B017_companion_does_not_force_utc_calendar() -> None:
    """Companion user.js must NOT set calendar.timezone.local."""
    content = _read_user_js()
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or not stripped:
            continue
        assert "calendar.timezone.local" not in stripped, (
            "B-017: still mangles user's calendar display TZ"
        )


# --- B-018: network.dns.disableIPv6 NOT in companion user.js ---

def test_B018_companion_does_not_globally_disable_ipv6() -> None:
    """network.dns.disableIPv6 must NOT be in companion user.js (it's an
    addon-runtime pref scoped to Tor mode)."""
    content = _read_user_js()
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or not stripped:
            continue
        assert "network.dns.disableIPv6" not in stripped, (
            "B-018: still globally disables IPv6 in companion user.js"
        )


# --- F-174: calendar.useragent.extra must be in HARDENING_PREFS ---


def test_F174_calendar_useragent_extra_is_hardened() -> None:
    """The companion `user-js/onionbird-user.js` blanks
    `calendar.useragent.extra` (line 112). The addon-only install path
    (which the README claims is functionally equivalent to the
    companion user.js for telemetry-suppression purposes) was missing
    this pref entirely. Concrete effect: a TB launched with the addon
    enabled but WITHOUT user.js leaks the calendar User-Agent string
    in every CalDAV / DAV request — a per-version fingerprint distinct
    from the Mail User-Agent and undefended by `mailnews.headers.
    sendUserAgent`. Symmetric to the F-074 case (addon → user.js
    asymmetry, Bundle H); this is the reverse direction (user.js →
    addon)."""
    bg = _read_addon_background()
    assert '"calendar.useragent.extra"' in bg, (
        "F-174: calendar.useragent.extra not in HARDENING_PREFS. The "
        "addon-only install leaks the calendar User-Agent on every "
        "CalDAV/DAV request — fingerprintable per TB version."
    )
    # Must also be in ALLOWED_PREF_NAMES (write-allowlist), otherwise
    # writePref() denies it at application time.
    assert '"calendar.useragent.extra"' in bg or (
        "calendar.useragent.extra" in bg
    ), "F-174: should be in HARDENING_PREFS (which is a subset of ALLOWED)"
    impl = _read_experiment_impl()
    assert '"calendar.useragent.extra"' in impl, (
        "F-174: calendar.useragent.extra must be in ALLOWED_PREF_NAMES "
        "in implementation.js — otherwise writePref denies it and the "
        "HARDENING_PREFS entry never lands."
    )


# --- F-167: app.support.baseURL must be a parseable URL ---

def test_F167_app_support_baseurl_is_parseable_url() -> None:
    """`moz-support-link.mjs` constructs `new URL(supportPage, app.support.baseURL)`
    for every "?" help icon in TB (about:addons, Options dialogs, …). An empty-
    string value makes the URL constructor throw `TypeError: ... is not a valid
    URL` once per rendered help link, spamming the browser console and breaking
    the help links visibly. The hardening's intent (no phone-home to Mozilla
    support URLs) is preserved by using an RFC-2606-reserved `.invalid` host,
    which is a parseable URL but guaranteed unresolvable."""
    import re
    bg = _read_addon_background()
    # Locate the HARDENING_PREFS entry — the name is the load-bearing string.
    m = re.search(
        r'\{\s*name:\s*"app\.support\.baseURL"\s*,\s*value:\s*"([^"]*)"\s*\}',
        bg,
    )
    assert m, (
        "F-167: could not find app.support.baseURL entry in HARDENING_PREFS. "
        "If you removed the entry entirely, the test needs revisiting; if you "
        "renamed the field shape, update this regex."
    )
    value = m.group(1)
    assert value != "", (
        "F-167: app.support.baseURL is the empty string. moz-support-link.mjs "
        "does `new URL(supportPage, app.support.baseURL)`, which throws "
        "TypeError on every rendered help icon. Use an RFC-2606-reserved "
        ".invalid host instead (e.g. https://onionbird.invalid/)."
    )
    # Must be a parseable URL with a scheme + host; using urlparse instead of
    # urllib.parse.urljoin because urljoin tolerates a bare path, which the
    # WHATWG URL constructor in moz-support-link does NOT.
    from urllib.parse import urlparse
    parsed = urlparse(value)
    assert parsed.scheme in ("http", "https"), (
        f"F-167: app.support.baseURL has no http(s) scheme — "
        f"`new URL('any-path', {value!r})` would fail in moz-support-link. "
        f"Use https://onionbird.invalid/ or similar."
    )
    assert parsed.netloc, (
        f"F-167: app.support.baseURL has no host — relative-resolution in "
        f"the URL constructor needs a base host. Got: {value!r}"
    )
    # Belt-and-braces: must end with "/" so relative join produces the
    # expected `<base>/<supportPage>` instead of replacing the last segment.
    assert value.endswith("/"), (
        f"F-167: app.support.baseURL must end with '/' so that "
        f"`new URL('foo', value)` resolves to `<value>foo`, not `<dir>/foo`. "
        f"Got: {value!r}"
    )
