"""Disable-hardening cleanup invariants (F-169 follow-up).

The disable-hardening path has three categories of cleanup:
  1. Restoration of TB prefs from the snapshot (the user's pre-hardening
     state).
  2. Forensic-marker scrub: addon-owned prefs (`onionbird.*`),
     storage.local snapshot, leak verdict.
  3. Process-state: stopHardeningMonitors, DNS cache flush.

Until F-169 surfaced, (2) was gated behind `if (ok)` where `ok` requires
*all* of (1) to succeed. A single failed pref restore (out of 110+
HARDENING_PREFS) left the user's `onionbird.socks.host` (e.g. Whonix
gateway IP) persistently visible in about:config — a "this user runs
Whonix" forensic fingerprint surviving the explicit disable gesture.
Same fault re-opens the F-076 hole (per-install random fallback FQDN).

The fix moves the forensic-scrub calls outside the `if (ok)` gate
(each in its own try/catch — they're restoration-independent).
"""
from __future__ import annotations


def test_F169_addon_owned_prefs_cleared_independent_of_restore_ok() -> None:
    """clearAddonOwnedPrefs must NOT be gated by `if (ok)` — it's a
    forensic-marker scrub that has to run on every disable regardless
    of whether a particular pref restore happened to fail. Source-level
    assertion: locate the `if (ok)` block in `_disableHardeningImpl`
    and verify the clearAddonOwnedPrefs call is OUTSIDE that block.
    """
    with open("/addon/background.js", encoding="utf-8") as f:
        bg = f.read()
    # Slice _disableHardeningImpl body.
    start = bg.index("async function _disableHardeningImpl")
    body = bg[start:start + 6000]
    # Find the position of `clearAddonOwnedPrefs()` call.
    cap = body.find("browser.onionbird.clearAddonOwnedPrefs()")
    assert cap > 0, (
        "F-169: clearAddonOwnedPrefs call not found in _disableHardeningImpl"
    )
    # Find the position of `if (ok) {` in the same function.
    if_ok = body.find("if (ok) {")
    assert if_ok > 0, "F-169: could not locate `if (ok) {` block"
    # Find the matching closing brace of the `if (ok)` block. Scan
    # forward from if_ok, count braces.
    depth = 0
    block_end = None
    for i in range(if_ok + len("if (ok) {") - 1, len(body)):
        ch = body[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                block_end = i
                break
    assert block_end, "F-169: could not find end of `if (ok)` block"
    assert not (if_ok < cap < block_end), (
        "F-169: clearAddonOwnedPrefs() is inside the `if (ok)` gate at "
        f"offset {cap} (block: {if_ok}..{block_end}). A single failed "
        "pref restore lets the user's onionbird.socks.host (Whonix "
        "gateway IP, etc.) persist in about:config — forensic "
        "fingerprint surviving the explicit disable gesture."
    )


def test_F169_storage_local_scrubbed_independent_of_restore_ok() -> None:
    """The storage.local.remove([STORAGE_KEY, LEAK_VERDICT_KEY]) call
    on disable must also run regardless of restore-ok. A stale snapshot
    in storage breaks the disable invariant (re-enable would re-snapshot
    from a corrupted state) and a stale leak verdict re-opens the F-042
    fail-closed window. Same gate as F-169 above."""
    with open("/addon/background.js", encoding="utf-8") as f:
        bg = f.read()
    start = bg.index("async function _disableHardeningImpl")
    body = bg[start:start + 6000]
    rm = body.find("storage.local.remove([STORAGE_KEY, LEAK_VERDICT_KEY]")
    assert rm > 0, (
        "F-169: storage.local.remove([STORAGE_KEY, LEAK_VERDICT_KEY]) "
        "not found in _disableHardeningImpl"
    )
    if_ok = body.find("if (ok) {")
    assert if_ok > 0
    depth = 0
    block_end = None
    for i in range(if_ok + len("if (ok) {") - 1, len(body)):
        ch = body[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                block_end = i
                break
    assert not (if_ok < rm < block_end), (
        "F-169: storage.local.remove([STORAGE_KEY, LEAK_VERDICT_KEY]) "
        f"is inside the `if (ok)` gate at offset {rm} (block: "
        f"{if_ok}..{block_end}). A failed pref restore leaves a stale "
        "snapshot + leak verdict — re-enable would re-snapshot a "
        "corrupted state and the F-042 fail-closed window re-opens."
    )
