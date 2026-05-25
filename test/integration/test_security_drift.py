"""Bundle H (P1) — security drift findings (F-074 / F-076 / F-077 /
F-080 / F-081 / F-082).

These are correctness / robustness regressions in the hardening
lifecycle. None opens a fresh leak path the size of a P0, but
each weakens trust in a measurable way:

  F-074 — install-user-js.sh writes worse-fingerprint
          `localhost.localdomain` per-identity, contradicting the
          addon's documented default of `from_domain`.
  F-076 — `onionbird.messageid.fqdn_fallback` per-install random
          value survives addon disable AND uninstall.
  F-077 — `_enableHardeningImpl` corrupt-snapshot branch re-
          snapshots from the HARDENED state, making `disable` a
          silent permanent no-op for any user whose snapshot ever
          corrupts.
  F-080 — stale leak verdict race: `recordLeakVerdict({state:
          "clean"})` is written AFTER `startHardeningMonitors`, so
          a send fired in that window sees the stale `leak_detected`
          verdict from the previous session.
  F-081 — auto-enable on install with no Tor reachable: addon
          silently fail-closes prefs but emits no notification.
          The send-block then cancels every send with no path
          for the user to recognise "Tor isn't running" without
          opening Options.
  F-082 — atn-sign.sh mints a fresh JWT inside every polling-loop
          iteration; the secret is re-exported into a new Python
          process env each time. Reduce to one JWT mint with
          `exp = now + 290` (just under ATN's 300 cap).
"""

from __future__ import annotations

import re
from pathlib import Path


def _resolve_repo() -> Path:
    for cand in (Path("/repo"), Path(__file__).resolve().parent.parent.parent):
        if (cand / "addon" / "background.js").exists():
            return cand
    return Path("/repo")


REPO = _resolve_repo()


# ---- F-074 ----


def test_F074_install_user_js_does_not_write_legacy_torbirdy_fqdn() -> None:
    """install-user-js.sh used to emit per-identity
    `mail.identity.<key>.FQDN = "localhost.localdomain"` — the
    TorBirdy "supercluster fingerprint" mode the README explicitly
    flags as worst. Users on the install-user-js.sh-only path
    (a documented option) got the worse mode.
    Acceptable fix: drop the per-identity FQDN write from the
    shell script entirely (the addon owns it once installed) OR
    change to a per-install random `.invalid` shape."""
    p = REPO / "scripts" / "install-user-js.sh"
    if not p.exists():
        import pytest
        pytest.skip("install-user-js.sh not mounted")
    body = p.read_text(encoding="utf-8")
    # Bug shape: writing the literal "localhost.localdomain" into a
    # mail.identity.<id>.FQDN pref line.
    bug_re = re.compile(
        r"mail\.identity\.[^\s\"]+\.FQDN[\"\s=,]+[\"']localhost\.localdomain[\"']",
        re.IGNORECASE,
    )
    m = bug_re.search(body)
    assert not m, (
        f"F-074: install-user-js.sh still writes "
        f"`mail.identity.*.FQDN = localhost.localdomain` per "
        f"identity. That is the TorBirdy supercluster fingerprint "
        f"the README explicitly calls out as worst. Match: "
        f"{m.group(0)!r}. Either drop the write (the addon owns "
        f"this pref once installed) or switch to a per-install "
        f"random `.invalid` shape."
    )


# ---- F-076 ----


def test_F076_disable_clears_addon_owned_message_id_prefs() -> None:
    """ADDON_OWNED_PREF_NAMES (`onionbird.messageid.fqdn_*`)
    survive `disable` and even `uninstall` today — `_disableHardeningImpl`
    only restores HARDENING_PREFS via the snapshot path and never
    touches the addon's own prefs. The per-install random
    `m<10hex>.invalid` value is a forensic fingerprint that
    outlives the user's explicit "remove this addon" gesture.
    Fix: `_disableHardeningImpl` must clear ADDON_OWNED_PREF_NAMES
    (via a new experiment-API method)."""
    bg = (REPO / "addon" / "background.js").read_text(encoding="utf-8")
    impl = (REPO / "addon" / "experiments" / "onionbird" / "implementation.js").read_text(encoding="utf-8")

    # The experiment API must expose a clear-addon-owned helper.
    assert any(
        marker in impl
        for marker in (
            "clearAddonOwnedPrefs",
            "clearMessageIdPrefs",
            "ADDON_OWNED_PREF_NAMES",
        )
    ), (
        "F-076: implementation.js does not expose a "
        "clearAddonOwnedPrefs / clearMessageIdPrefs helper that "
        "would let disable wipe the per-install fqdn_fallback "
        "etc."
    )
    # _disableHardeningImpl must call it (anchor by name).
    disable_body = bg[bg.index("async function _disableHardeningImpl"):]
    disable_body = disable_body[: disable_body.index("\nasync function ")]
    assert any(
        marker in disable_body
        for marker in (
            "clearAddonOwnedPrefs",
            "clearMessageIdPrefs",
            "fqdn_fallback",
        )
    ), (
        "F-076: _disableHardeningImpl does not clear the addon-"
        "owned message-id prefs (onionbird.messageid.fqdn_*). "
        "The per-install random fallback value survives disable "
        "→ forensic fingerprint."
    )


# ---- F-077 ----


def test_F077_enable_does_not_snapshot_from_hardened_state() -> None:
    """If the snapshot in storage.local is corrupt but the on-disk
    prefs are still at the hardened values (extension upgrade with
    a bad JSON, storage rollback), the previous corrupt-snapshot
    handling re-snapshotted from the live (hardened) state. That
    snapshot then becomes the "original" — and `disable` happily
    "restores" to the hardened values forever, making disable a
    silent permanent no-op.
    The fix shape: when the snapshot is corrupt (not just absent),
    refuse to take a new snapshot from the live branch. Acceptable
    end-states: a comment + code path that explicitly handles
    corrupt-snapshot differently from absent-snapshot."""
    bg = (REPO / "addon" / "background.js").read_text(encoding="utf-8")
    # Anchor: ensureHardeningSnapshot or _enableHardeningImpl must
    # reference snapshotState.corrupt or the F-077 anchor.
    target_funcs = ("ensureHardeningSnapshot", "_enableHardeningImpl")
    found_guard = False
    for fn_name in target_funcs:
        idx = bg.find(f"async function {fn_name}") if fn_name.startswith("_") else bg.find(f"async function {fn_name}")
        if idx < 0:
            continue
        end = bg.find("\nasync function ", idx + 1)
        fn = bg[idx:end] if end > 0 else bg[idx:]
        if (
            "snapshotState.corrupt" in fn
            or "F-077" in fn
            or "corrupt-snapshot" in fn
        ):
            found_guard = True
            break
    assert found_guard, (
        "F-077: neither ensureHardeningSnapshot nor "
        "_enableHardeningImpl explicitly handles the "
        "corrupt-snapshot case differently from the "
        "no-snapshot case. A user whose snapshot ever corrupts "
        "ends up with the live hardened state captured as the "
        "snapshot, and disable becomes a silent permanent no-op."
    )


# ---- F-080 ----


def test_F080_clean_verdict_written_before_monitors_start() -> None:
    """`recordLeakVerdict({state:"clean"})` was written AFTER
    `startHardeningMonitors()`, which kicks off the periodic
    canary timer. A user clicking Send in the millisecond window
    between monitors-on and verdict-clean-write inherited the
    stale verdict from the previous session.
    Fix: write an `inconclusive` (= still-blocking) verdict
    BEFORE startHardeningMonitors so the listener fails closed
    during the transition; write `clean` only after the
    `ok` confirmation, but make sure it precedes monitor start.
    Acceptable end-states: the success-path verdict write
    appears before startHardeningMonitors() in source, OR an
    explicit transition-phase verdict (`inconclusive` /
    `enable-in-progress`) is written before."""
    bg = (REPO / "addon" / "background.js").read_text(encoding="utf-8")
    # Anchor on the _enableHardeningImpl function body.
    idx = bg.index("async function _enableHardeningImpl")
    end = bg.index("\nasync function ", idx)
    fn = bg[idx:end]
    monitor_pos = fn.find("startHardeningMonitors()")
    verdict_pos = fn.find('recordLeakVerdict')
    if monitor_pos < 0 or verdict_pos < 0:
        raise AssertionError(
            "F-080: could not locate startHardeningMonitors() or "
            "recordLeakVerdict() call in _enableHardeningImpl"
        )
    # Either:
    #   (a) recordLeakVerdict precedes startHardeningMonitors, OR
    #   (b) an explicit transition-phase write happens before
    #       startHardeningMonitors (look for 'enable-in-progress'
    #       or 'inconclusive' near the top of the function).
    transition_marker = (
        "enable-in-progress" in fn[:monitor_pos]
        or "F-080" in fn[:monitor_pos]
    )
    assert verdict_pos < monitor_pos or transition_marker, (
        f"F-080: recordLeakVerdict (offset {verdict_pos}) is "
        f"AFTER startHardeningMonitors (offset {monitor_pos}) and "
        f"no transition-phase verdict is written before. A send "
        f"in the millisecond window sees a stale verdict from a "
        f"previous session."
    )


# ---- F-081 ----


def test_F081_auto_enable_emits_notification_on_socks_failure() -> None:
    """On first-install with no Tor reachable, auto-enable runs
    `applyFailClosedPrefs` but emits NO notification. Combined
    with the new compose.onBeforeSend send-block (F-043), every
    send now silently cancels with no path for the user to
    recognise "Tor isn't running" without opening Options.
    Acceptable fix: at least one of these anchors must appear in
    background.js — `notifications.create` call (requires the
    `notifications` permission in both manifests) OR an explicit
    `F-081` marker comment documenting the deliberate deferral
    rationale."""
    bg = (REPO / "addon" / "background.js").read_text(encoding="utf-8")
    has_notification = "browser.notifications.create" in bg or "notifications.create" in bg
    has_deferred_marker = "F-081" in bg
    assert has_notification or has_deferred_marker, (
        "F-081: auto-enable / first-install has no notification "
        "code path AND no F-081 marker documenting why. A user "
        "with no Tor running gets silent send-cancels and no "
        "actionable hint to fix it."
    )
    # If we have notifications.create, the manifest must declare
    # the `notifications` permission too — else the API is unavailable.
    if has_notification:
        import json
        for mf in ("manifest.json", "manifest.mv3.json"):
            p = REPO / "addon" / mf
            m = json.loads(p.read_text(encoding="utf-8"))
            assert "notifications" in m.get("permissions", []), (
                f"F-081: {mf} missing `notifications` permission "
                f"but background.js calls browser.notifications.create. "
                f"The API will be unavailable at runtime."
            )


# ---- Bundle I (P1) — security correctness ----


def test_F075_apply_identity_hardening_skips_clearnet_identities() -> None:
    """README's "Where OnionBird is materially better" claim AND
    the options-page disableHelp string both promise mixed-mode
    coexistence: "Clearnet accounts that were intentionally
    bypassed keep working normally". The SMTP-side path honours
    onion-only gating (`applyHardeningToAllSmtpServers(true)`)
    but the identity-side path used to harden EVERY identity
    unconditionally — wiping reply_to / organization / vCard /
    signature on clearnet identities the user intentionally kept
    outside Tor mode.

    Acceptable end-states:
      (a) `applyHardeningToAllIdentities` accepts an
          `{onlyOnionIdentities: true}` option, OR
      (b) the function body explicitly looks up each identity's
          bound SMTP server (`identity.smtpServerKey` →
          `outgoing.servers`) and skips when the bound server is
          not onion/loopback."""
    impl = (REPO / "addon" / "experiments" / "onionbird" / "implementation.js").read_text(encoding="utf-8")
    # Anchor on the function-definition syntax, not the bare symbol —
    # comments anywhere in the file that mention the function by name
    # (e.g. the F-166 incident write-up in randomHex) would otherwise
    # become the new first-occurrence and silently shift this slice
    # off the actual function body.
    import re as _re
    m = _re.search(r"applyHardeningToAllIdentities\s*:\s*async\b", impl)
    assert m, "F-075: applyHardeningToAllIdentities function definition not found in implementation.js"
    fn = impl[m.start():m.start() + 4500]
    anchors = (
        "onlyOnionIdentities",
        "smtpServerKey",
        "identity-onion-only",
        "F-075",
    )
    assert any(a in fn for a in anchors), (
        "F-075: applyHardeningToAllIdentities has no gating on "
        "clearnet identities. It will wipe reply_to / organization "
        "/ vCard / signature on every identity, contradicting the "
        "README mixed-mode promise. Anchor names looked for: "
        f"{anchors}"
    )


def test_F078_inconclusive_verdict_schedules_fast_retry() -> None:
    """The compose.onBeforeSend listener treats `state==="inconclusive"`
    as block (fail-closed, correct). But the canary that produced
    the verdict only re-runs every 10 minutes — a transient hiccup
    (laptop wakeup, short circuit reset) blocks every send for up
    to 10 min with no in-compose-window remedy.

    Acceptable fix: after writing an inconclusive verdict,
    `announceSelfTest` schedules a faster retry (within ~30 s) up
    to a few times before backing off to the normal interval.

    Acceptable end-states: announceSelfTest body references
    `setTimeout` with a short delay near the inconclusive branch,
    OR a per-process retry-count variable, OR an explicit F-078
    marker comment."""
    bg = (REPO / "addon" / "background.js").read_text(encoding="utf-8")
    idx = bg.index("async function announceSelfTest")
    end = bg.index("\nasync function ", idx)
    fn = bg[idx:end]
    anchors = (
        "F-078",
        "setTimeout",
        "INCONCLUSIVE_RETRY",
        "_inconclusiveRetries",
        "retry",
    )
    assert any(a in fn for a in anchors), (
        "F-078: announceSelfTest has no fast-retry path on "
        "inconclusive. A transient verdict blocks every send for "
        "the full 10 min interval with no compose-window remedy. "
        f"Anchor names looked for: {anchors}"
    )


# ---- F-082 ----


def test_F082_atn_sign_mints_jwt_once_for_polling_loop() -> None:
    """atn-sign.sh used to mint a fresh JWT inside every polling
    iteration (60 polls × 5s = 60 process exec()s with the
    secret in env). The JWT's lifetime can comfortably cover the
    whole polling window — mint once with `exp = now + 290`
    (just under ATN's 300 cap) and pass the secret on stdin
    instead of env to reduce the process-env-exposed-secret
    surface from 60-ish PIDs to 1.

    Acceptable end-state: at least the mint_jwt invocation
    pattern is not repeated inside the polling loop, OR the
    secret is passed via stdin (env-cleared subshell) where
    used."""
    p = REPO / "scripts" / "atn-sign.sh"
    if not p.exists():
        import pytest
        pytest.skip("atn-sign.sh not mounted")
    body = p.read_text(encoding="utf-8")
    # Locate the polling loop (the `for attempt in $(seq 1 60)` block).
    m = re.search(r"for attempt in \$\(seq 1 60\)[\s\S]+?done", body)
    if not m:
        # If polling was refactored away entirely, that also closes
        # F-082 (no loop, no per-iteration mint).
        return
    loop_body = m.group(0)
    # Inside the loop body, mint_jwt must NOT be re-invoked.
    assert "$(mint_jwt)" not in loop_body and "JWT=$(mint_jwt)" not in loop_body, (
        "F-082: atn-sign.sh polling loop still re-mints the JWT "
        "every iteration. Mint once outside the loop with "
        "`exp = now + 290` so the JWT covers the full polling "
        "window; reduces secret-in-process-env exposure from "
        "60 PIDs to 1."
    )
