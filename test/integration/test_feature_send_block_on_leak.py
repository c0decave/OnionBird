"""Application-layer send-block when the canary detected a leak.

The audit flagged this as a P0 gap: when the addon's self-test canary
returns `leak_detected=true`, the addon previously only logged the
warning and re-asserted hardening. There was NO application-layer
refusal of outgoing sends — Mozilla's transport-level
`network.proxy.failover_direct=false` was the sole barrier.

Bundle 6 adds:
1. A persisted leak verdict in `storage.local` under key
   `onionbird.leakVerdict`, written by `recordLeakVerdict` from the
   self-test path.
2. A `browser.compose.onBeforeSend` listener that returns
   `{cancel: true, cancelMessage: ...}` when the verdict is
   `leak_detected` — TB displays the cancelMessage in the compose
   notification bar, refusing the send visibly to the user.

These tests are structural: they verify the wiring is in place. End-
to-end verification of the cancel behavior requires opening a compose
window with content, attempting a send, and inspecting the notification
bar — non-trivial to drive through Marionette and added to follow-up.
Structural tests catch the failure modes that matter most for a P0
gap (someone deletes the listener / forgets the manifest permission /
breaks the storage key constant).
"""

from __future__ import annotations

import json
import re


def _read_source(rel: str) -> str:
    with open(f"/addon/{rel}", encoding="utf-8") as f:
        return f.read()


def _read_manifest(name: str) -> dict:
    return json.loads(_read_source(name))


def test_manifest_declares_compose_permission_mv2() -> None:
    """Without the `compose` permission, `browser.compose.onBeforeSend`
    is `undefined` and the addon's send-block silently no-ops."""
    m = _read_manifest("manifest.json")
    assert "compose" in m.get("permissions", []), (
        f"MV2 manifest missing 'compose' permission: {m.get('permissions')}"
    )


def test_manifest_declares_compose_permission_mv3() -> None:
    m = _read_manifest("manifest.mv3.json")
    assert "compose" in m.get("permissions", []), (
        f"MV3 manifest missing 'compose' permission: {m.get('permissions')}"
    )


def test_built_xpi_contains_compose_permission() -> None:
    """Regression guard: ensure the XPI bundler doesn't strip the
    permission. The build pipeline transforms manifest.mv3.json →
    manifest.json for the MV3 XPI; this test confirms both XPIs ship
    with `compose` declared."""
    import zipfile
    for xpi in ("/build/onionbird.xpi", "/build/onionbird-mv3.xpi"):
        with zipfile.ZipFile(xpi) as z:
            m = json.loads(z.read("manifest.json").decode())
        assert "compose" in m.get("permissions", []), (
            f"{xpi}: 'compose' missing from packaged permissions"
        )


def test_background_registers_compose_onbeforesend() -> None:
    """The send-block must wire compose.onBeforeSend in background.js.
    Without this registration the addon has no application-layer say
    over outgoing sends — only Mozilla's failover_direct safety net."""
    bg = _read_source("background.js")
    assert "browser.compose.onBeforeSend.addListener" in bg, (
        "background.js does not register the compose.onBeforeSend "
        "listener — application-layer send-block disabled"
    )


def test_background_declares_leak_verdict_storage_key() -> None:
    """The verdict storage key is a load-bearing constant — if it
    drifts between the writer (recordLeakVerdict) and the reader
    (compose.onBeforeSend), the block silently no-ops."""
    bg = _read_source("background.js")
    assert 'LEAK_VERDICT_KEY = "onionbird.leakVerdict"' in bg, (
        "LEAK_VERDICT_KEY constant missing or renamed in background.js"
    )
    # readLeakVerdict and recordLeakVerdict must both reference it.
    assert bg.count("LEAK_VERDICT_KEY") >= 3, (
        f"LEAK_VERDICT_KEY referenced only "
        f"{bg.count('LEAK_VERDICT_KEY')} times — expected one definition "
        f"plus reader + writer + onBeforeSend usage"
    )


def test_background_records_leak_verdict_in_self_test_path() -> None:
    """When the canary detects a leak, the verdict must be persisted
    BEFORE the re-assert is attempted. Otherwise a crash between
    detection and re-assert would leave the compose-block unprimed."""
    bg = _read_source("background.js")
    # Find the announceSelfTest function body
    m = re.search(
        r"async function announceSelfTest\(\)\s*\{([\s\S]+?)\n\}\n",
        bg,
    )
    assert m, "could not locate announceSelfTest function in background.js"
    body = m.group(1)
    assert "leak_detected" in body
    # recordLeakVerdict must appear in the leak branch.
    assert "recordLeakVerdict" in body, (
        "announceSelfTest does not call recordLeakVerdict — leak "
        "verdicts never persist, compose-block has nothing to read"
    )


def test_compose_onbeforesend_returns_cancel_for_leak() -> None:
    """The onBeforeSend listener must return {cancel: true} when the
    verdict is leak_detected. Without that, TB proceeds with the send
    even though the listener fired."""
    bg = _read_source("background.js")
    # Find the listener body
    m = re.search(
        r"browser\.compose\.onBeforeSend\.addListener\(\s*async[\s\S]+?\}\);",
        bg,
    )
    assert m, "compose.onBeforeSend listener body not parseable"
    listener_body = m.group(0)
    assert "cancel: true" in listener_body, (
        "onBeforeSend does not return cancel:true on leak"
    )
    assert "leak_detected" in listener_body, (
        "onBeforeSend does not check the leak_detected state"
    )
    assert "cancelMessage" in listener_body, (
        "onBeforeSend does not supply a cancelMessage — user sees no "
        "explanation when their send is refused"
    )


def test_clean_verdict_does_not_block() -> None:
    """A clean verdict must NOT trigger send-block. Only an explicit
    state==='clean' is recognised as safe."""
    bg = _read_source("background.js")
    m = re.search(
        r"browser\.compose\.onBeforeSend\.addListener\(\s*async[\s\S]+?\}\);",
        bg,
    )
    assert m
    listener_body = m.group(0)
    assert 'state === "clean"' in listener_body, (
        "onBeforeSend listener does not short-circuit on clean verdict"
    )


# ---- F-042: leak verdict lifecycle on enable/disable ----


def _slice(body: str, start: str, end: str) -> str:
    i = body.index(start)
    j = body.index(end, i)
    return body[i:j]


def test_disable_clears_leak_verdict_key_from_storage() -> None:
    """F-042: `_disableHardeningImpl` must remove `LEAK_VERDICT_KEY`
    alongside `STORAGE_KEY`. Otherwise a stale `leak_detected` verdict
    survives disable → re-enable, blocking every send for up to 10
    minutes until the next periodic canary fires; a stale `clean`
    verdict in the opposite case bypasses the send-block on the next
    session before the first canary completes."""
    bg = _read_source("background.js")
    disable_body = _slice(
        bg,
        "async function _disableHardeningImpl",
        "\nasync function ",
    )
    # The disable path must reference LEAK_VERDICT_KEY in a remove call.
    assert "LEAK_VERDICT_KEY" in disable_body, (
        "_disableHardeningImpl never references LEAK_VERDICT_KEY — "
        "stale verdict will leak across enable/disable cycles (F-042)"
    )
    assert re.search(
        r"storage\.local\.remove\(\s*\[[^\]]*LEAK_VERDICT_KEY[^\]]*\]\s*\)",
        disable_body,
    ), (
        "_disableHardeningImpl does not remove LEAK_VERDICT_KEY via "
        "storage.local.remove([..., LEAK_VERDICT_KEY, ...]) (F-042)"
    )


def test_enable_writes_clean_verdict_at_end_of_success_path() -> None:
    """F-042: `_enableHardeningImpl` must explicitly write a `clean`
    verdict at the end of its success path. Without this, a stale
    `leak_detected` verdict from a previous session (or a partial
    crash before disable cleared it) silently blocks every send
    after re-enable until the periodic self-test fires up to 10
    minutes later — the user sees a green Options-page status while
    every send is being cancelled at the compose-window notification
    bar with no actionable explanation."""
    bg = _read_source("background.js")
    enable_body = _slice(
        bg,
        "async function _enableHardeningImpl",
        "\nasync function ",
    )
    # Must call recordLeakVerdict with state:"clean" somewhere in the
    # success path (after socks.ok && selfTestOk has been confirmed).
    assert re.search(
        r'recordLeakVerdict\(\s*\{\s*state:\s*"clean"',
        enable_body,
    ), (
        "_enableHardeningImpl does not call "
        'recordLeakVerdict({state: "clean", ...}) on success — stale '
        "verdict from a prior session will keep blocking sends (F-042)"
    )


# ---- F-043: readLeakVerdict must fail-CLOSED when hardening is active ----


def test_onbeforesend_fails_closed_on_missing_or_unknown_verdict() -> None:
    """F-043: When hardening is active, the compose.onBeforeSend
    listener must cancel the send for ANY verdict that is not
    explicitly `state==='clean'` — including null (storage error,
    storage key never written), `inconclusive`, or any unrecognised
    string. The previous implementation short-circuited on `!verdict`
    and treated unknown states as pass-through, which means a typo
    in `recordLeakVerdict`, a storage corruption, or simply a fresh
    install before the first canary fires all permit clearnet sends
    while the user believes the addon is protecting them."""
    bg = _read_source("background.js")
    m = re.search(
        r"browser\.compose\.onBeforeSend\.addListener\(\s*async[\s\S]+?\}\);",
        bg,
    )
    assert m, "compose.onBeforeSend listener not found"
    listener_body = m.group(0)

    # The listener MUST gate fail-closed-vs-pass-through on whether
    # hardening is active. The exact API used to read that state may
    # change across bundles (isHardeningActive wrapper, or direct
    # readSnapshotState consultation — the latter is what F-072
    # adopted because it preserves the corrupt-marker that lets the
    # listener distinguish "storage error" from "addon disabled").
    # Either is acceptable; "no gate at all" is not.
    gate_anchors = (
        "isHardeningActive",
        "readSnapshotState",
        "snapshotState.snapshot",
        "snapshotState.corrupt",
    )
    assert any(a in listener_body for a in gate_anchors), (
        "compose.onBeforeSend listener does not gate on any "
        f"hardening-active anchor (looked for {list(gate_anchors)}) — "
        "cannot distinguish 'addon disabled' from 'addon enabled but "
        "verdict missing' (F-043) or 'storage error, unknown state' "
        "(F-072)."
    )

    # The listener MUST NOT short-circuit on `!verdict` alone — that
    # is the fail-open bug. Concretely: there should be no
    # `if (!verdict || verdict.state === "clean") return;` pattern
    # that returns without checking isHardeningActive first.
    fail_open_pattern = re.compile(
        r"if\s*\(\s*!\s*verdict\s*\|\|\s*verdict\.state\s*===\s*\"clean\"\s*\)\s*\{?\s*return\b"
    )
    assert not fail_open_pattern.search(listener_body), (
        "compose.onBeforeSend still contains the fail-OPEN early "
        "return `if (!verdict || verdict.state === \"clean\") return` — "
        "this lets a null/garbled verdict bypass the send-block (F-043)"
    )


def test_readleakverdict_distinguishes_missing_from_clean() -> None:
    """F-043 lower-level: readLeakVerdict must NOT collapse the
    'storage threw' case into the same null return as the 'storage
    succeeded but key absent' case without also logging the storage
    error. A silent catch makes storage-corruption regressions
    invisible during incident triage."""
    bg = _read_source("background.js")
    rv = _slice(bg, "async function readLeakVerdict", "\n}\n")
    assert "console.error" in rv or "console.warn" in rv, (
        "readLeakVerdict swallows storage errors without logging — "
        "storage corruption becomes invisible to triage (F-043)"
    )


# ---- F-072: readSnapshotState must not propagate storage errors ----
#
# Happy path: storage works → snapshot returned normally (covered by
#   the existing send_block + enable/disable test families).
# Sad path:   storage throws → readSnapshotState catches and returns a
#   corrupt-marker with reason="storage-error". The compose listener
#   must treat that case as fail-CLOSED and cancel the send. F-043
#   closed the symmetric hole in readLeakVerdict; F-072 is the same
#   pattern in readSnapshotState that the previous bundle missed.
# Edge:       snapshot exists but JSON shape is invalid → existing
#   corrupt-marker already handles this. We assert the storage-error
#   branch is distinguishable from the shape-invalid branch so triage
#   tooling can tell them apart.


def test_F072_readsnapshotstate_catches_storage_error() -> None:
    """SAD path: storage.local.get throws → readSnapshotState must
    catch and return a corrupt-marker, NOT propagate. The previous
    behaviour let the throw propagate through isHardeningActive,
    through Promise.all in the compose.onBeforeSend listener, and
    out as a rejected Promise — which TB treats as `undefined` from
    the listener, meaning NO cancel → the send proceeds (fail-OPEN).
    This is the exact symmetric bug to F-043 (readLeakVerdict)."""
    bg = _read_source("background.js")
    fn = _slice(bg, "async function readSnapshotState", "\nasync function ")

    # The storage call must be wrapped in try/catch.
    assert "try {" in fn and "catch" in fn, (
        "F-072: readSnapshotState does not try/catch around "
        "browser.storage.local.get — a storage error propagates to "
        "the compose.onBeforeSend listener and TB receives undefined "
        "(send proceeds, fail-OPEN)"
    )
    # The catch must produce a corrupt-marker with a distinct reason
    # (so triage can tell storage-error from shape-invalid).
    assert "storage-error" in fn or "storage_error" in fn, (
        "F-072: readSnapshotState catch block does not produce a "
        '"storage-error" reason tag — incident triage cannot '
        "distinguish a transient storage throw from a malformed "
        "snapshot."
    )
    # The catch must log loudly so the storage hiccup surfaces in
    # the browser console.
    assert "console.error" in fn or "console.warn" in fn, (
        "F-072: readSnapshotState catch silently swallows the "
        "storage error — operator never sees the cause."
    )


def test_F072_onbeforesend_cancels_on_storage_error() -> None:
    """EDGE path: when readSnapshotState cannot determine whether
    hardening is active (storage error), the listener MUST cancel
    the send. Treating storage uncertainty as 'addon disabled' would
    let every send through whenever storage hiccups, which is the
    100%-Tor mandate violation F-072 exists to close."""
    bg = _read_source("background.js")
    listener_m = re.search(
        r"browser\.compose\.onBeforeSend\.addListener\(\s*async[\s\S]+?\}\);",
        bg,
    )
    assert listener_m, "compose.onBeforeSend listener not found"
    body = listener_m.group(0)

    # The listener must consult readSnapshotState (or a wrapper that
    # returns the corrupt-marker shape), not just isHardeningActive
    # — otherwise it cannot tell "addon disabled" from "storage
    # error".
    assert "readSnapshotState" in body or "snapshotState" in body, (
        "F-072: compose.onBeforeSend listener does not consult "
        "readSnapshotState — it cannot distinguish 'addon truly "
        "disabled' from 'storage error, unknown state' and therefore "
        "cannot fail-CLOSED on the latter."
    )

    # There must be a fail-CLOSED branch for the storage-uncertain
    # case.
    assert "storage-error" in body or "storage_error" in body or "storageError" in body or "snapshotState.corrupt" in body, (
        "F-072: compose.onBeforeSend listener has no branch that "
        "explicitly cancels on a storage-uncertain readSnapshotState "
        "result. Without this branch, a storage hiccup silently "
        "permits every send (fail-OPEN)."
    )


# ---- F-073: Message-ID FQDN must NOT leak the user's onion domain ----
#
# Happy: clearnet from-domain (e.g. "gmail.com") → Message-ID uses it
#   (current behaviour preserved; user blends with the provider's
#   regular users).
# Sad:   onion from-domain (e.g. "alice@<v3>.onion") → Message-ID uses
#   the random m<hex>.invalid fallback (NEW: previously, the onion
#   domain was put into every outbound header, disclosing the
#   onion-mailbox identity to every recipient).
# Edge:  multi-label onion (e.g. "alice@sub.<v3>.onion") → same
#   fallback (the isOnionHost helper accepts subdomains too).


def test_F073_pickfqdn_guards_against_onion_from_domain() -> None:
    """SAD path: pickFqdn must NOT return an onion domain as the
    Message-ID FQDN even when from_domain mode is selected and the
    identity's email lives on an onion. Currently `pickFqdn` checks
    only `isValidMessageIdFqdn(dom)` which accepts a v3 onion
    (valid multi-label DNS shape, ASCII chars). Result: a user who
    sets up an onion mailbox gets `<uuid@<v3>.onion>` in every
    outbound Message-ID — discloses the onion mailbox to every
    recipient and to anyone scraping Received chains. Direct
    violation of the 100%-Tor mandate at the application layer."""
    impl = _read_source("experiments/onionbird/implementation.js")
    # Locate the pickFqdn function body.
    pf_m = re.search(
        r"function\s+pickFqdn\s*\([^\)]*\)\s*\{([\s\S]+?)\n\s{10}\}",
        impl,
    )
    assert pf_m, "F-073: pickFqdn function body not parseable"
    body = pf_m.group(1)

    # The from-domain branch must consult isOnionHost on the
    # extracted domain — otherwise a `.onion` mailbox flows through
    # into the Message-ID header.
    assert "isOnionHost" in body, (
        "F-073: pickFqdn does not call isOnionHost on the from-domain "
        "before returning it. An onion-mailbox user gets their onion "
        "address printed in every outbound Message-ID — the bytes go "
        "via Tor but the application-layer header leaks the secret."
    )


def test_F073_pickfqdn_falls_through_to_fallback_on_onion() -> None:
    """EDGE: the onion-guard must fall through to `fallbackFqdn`
    (the per-install random `m<hex>.invalid` value), NOT silently
    drop the identity's hardening or return a hardcoded constant.
    The fallback path is the same one that runs when from_domain
    mode is selected on an identity with no valid from-address —
    we want onion-from-addresses to take exactly that same path,
    not invent a new one."""
    impl = _read_source("experiments/onionbird/implementation.js")
    pf_m = re.search(
        r"function\s+pickFqdn\s*\([^\)]*\)\s*\{([\s\S]+?)\n\s{10}\}",
        impl,
    )
    assert pf_m
    body = pf_m.group(1)
    # The function still returns fallbackFqdn as its final fallback.
    assert "fallbackFqdn" in body, (
        "F-073: pickFqdn no longer references fallbackFqdn — the "
        "onion-guard must fall THROUGH to the existing fallback "
        "path, not invent a new return value."
    )


def test_F073_happy_path_clearnet_from_domain_still_works() -> None:
    """HAPPY: the pre-existing from_domain behaviour for clearnet
    domains (the addon's flagship mode, "blend with the provider's
    regular users") must continue to work. The fix is a guarded
    rejection of onion domains, not a regression that drops the
    from_domain mode entirely."""
    impl = _read_source("experiments/onionbird/implementation.js")
    pf_m = re.search(
        r"function\s+pickFqdn\s*\([^\)]*\)\s*\{([\s\S]+?)\n\s{10}\}",
        impl,
    )
    assert pf_m
    body = pf_m.group(1)
    # The clearnet from-domain return path must still exist (the
    # `return dom` after isValidMessageIdFqdn).
    assert "isValidMessageIdFqdn" in body and "return dom" in body, (
        "F-073: pickFqdn no longer returns the clearnet from-domain "
        "(`return dom` path missing). The from_domain mode is the "
        "addon's default — fixing the onion-leak must not break the "
        "common clearnet case."
    )
