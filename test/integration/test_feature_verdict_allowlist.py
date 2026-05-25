"""F-083: verdict-state must be on a fixed allowlist.

`recordLeakVerdict(verdict)` previously accepted any object as the
verdict argument and persisted it verbatim to `storage.local`.
Consumers (the compose.onBeforeSend listener) gate on
`verdict.state === "clean"` and treat anything else as fail-closed,
which is correct policy — but the WRITE side never validated the
state value or the object shape. Forward-compat risk:

  - A future bug or storage corruption could write `state:
    "leak_detected_but_actually_no_problem_promise"` and the listener
    would fail-closed (good in this direction), but a typo in the
    "clean" branch (`state: "clena"`) would silently start blocking
    every send forever — no test would catch the typo at write time.
  - Verdict objects with unexpected extra fields (PII, very large
    payloads from a malformed canary result) get persisted to
    storage.local where they survive disable → re-enable cycles.

Fix: a fixed VALID_VERDICT_STATES set + a normalize-shape function
that drops unexpected keys + rejects unknown state strings (returns
null, which the read-side treats as fail-closed).
"""
from __future__ import annotations

import re


def _read(p: str) -> str:
    with open(p, encoding="utf-8") as f:
        return f.read()


def test_F083_verdict_state_allowlist_defined() -> None:
    """background.js must declare a fixed set of accepted verdict
    state strings, and `recordLeakVerdict` must consult it before
    persisting."""
    bg = _read("/addon/background.js")
    assert re.search(
        r"const\s+(VALID_VERDICT_STATES|LEAK_VERDICT_STATES)\s*=\s*new\s+Set\(\[",
        bg,
    ), (
        "F-083: no VALID_VERDICT_STATES allowlist defined in "
        "background.js. recordLeakVerdict accepts arbitrary state "
        "strings; a typo in 'clean' silently starts blocking every "
        "send forever."
    )
    # All 4 currently-used states must be in the set.
    for state in ("clean", "leak_detected", "inconclusive", "enable-in-progress"):
        assert f'"{state}"' in bg, (
            f"F-083: state {state!r} written by recordLeakVerdict but "
            f"not declared in any allowlist."
        )


def test_F087_canary_anchor_host_set_has_multiple_targets() -> None:
    """F-087: the periodic canary's probe host was hardcoded to
    `check.torproject.org`. A passive observer who sees TB-shaped
    traffic resolving check.torproject.org via Tor every N minutes
    can identify the user as an OnionBird/t0raddon canary source —
    even though the resolution itself goes via Tor, the periodicity
    + the fixed target are themselves a fingerprint.

    Fix: a small pool of canary anchor hosts that the addon rotates
    through. Each anchor is a target whose DNS-via-Tor resolution
    being requested doesn't itself imply anything OnionBird-specific
    (the Tor Project's own check service is the canonical
    `check.torproject.org`; common DoH/DoT testbed names work too).
    Rotation defends against the "same target every interval"
    fingerprint without changing the correctness property (the
    verdict still depends on `system_ip ∈ tor_ips` for whichever
    target fired).
    """
    bg = _read("/addon/background.js")
    assert re.search(
        r"const\s+CANARY_ANCHOR_HOSTS?\s*=\s*\[",
        bg,
    ), (
        "F-087: no CANARY_ANCHOR_HOSTS rotation list defined. Canary "
        "probes always hit check.torproject.org — fingerprint risk."
    )
    # The fallback host (SELF_TEST_HOST) must still be in the rotation
    # so the wire-level test continues to verify against a known-Tor-
    # adjacent target.
    assert '"check.torproject.org"' in bg
    # Rotation must have multiple entries — a 1-element rotation is
    # the bug.
    m = re.search(
        r"const\s+CANARY_ANCHOR_HOSTS?\s*=\s*\[([^\]]+)\]",
        bg,
    )
    assert m, "F-087: could not parse rotation list"
    entries = [e.strip() for e in m.group(1).split(",") if e.strip()]
    assert len(entries) >= 3, (
        f"F-087: rotation list has only {len(entries)} entry/entries; "
        f"need >=3 for meaningful jitter. Body: {m.group(1)!r}"
    )
    # Rotation must be CONSUMED — a dead declaration is the bug class
    # we're explicitly avoiding. announceSelfTest is the periodic canary
    # entry point, so it must reference either the helper picker or the
    # list directly.
    m2 = re.search(
        r"async function announceSelfTest\(\)\s*\{([\s\S]+?)\n\}",
        bg,
    )
    assert m2, "F-087: could not locate announceSelfTest body"
    body = m2.group(1)
    assert (
        "pickCanaryAnchorHost" in body
        or "CANARY_ANCHOR_HOSTS" in body
    ), (
        "F-087: announceSelfTest body does NOT reference the rotation "
        "list or its picker — the periodic canary still hammers a fixed "
        "host. Body:\n{body[:400]}"
    )


def test_F088_atn_sign_redacts_jwt_in_output() -> None:
    """F-088: atn-sign.sh exposes JWT credentials to logs in two ways
    that the script should defend against:
      - bash -x / SHELLOPTS=xtrace prints every $JWT expansion to stderr
      - curl error output can include the request-as-sent, exposing the
        Authorization: JWT header.

    Fix has two parts:
      1. `set +x` at script top to defend against xtrace invocation.
      2. A redact_secrets sanitizer for output paths that touch error
         responses (which can echo the request body / headers back)."""
    sh = _read("/scripts/atn-sign.sh")
    # Explicit set +x defends against bash -x wrapping.
    assert re.search(r"^set\s+\+x\b", sh, re.MULTILINE), (
        "F-088: atn-sign.sh does not `set +x` explicitly — a wrapper "
        "invoking it with `bash -x` would print every $JWT expansion "
        "to stderr."
    )
    # Sanitizer function defined.
    assert re.search(r"^redact_secrets\(\)\s*\{", sh, re.MULTILINE), (
        "F-088: atn-sign.sh has no redact_secrets() function. Any "
        "curl error output that includes the JWT bearer header lands "
        "verbatim in CI logs."
    )


def test_F083_record_leak_verdict_validates_state() -> None:
    """recordLeakVerdict body must call into the allowlist (or call a
    helper that does) before persisting."""
    bg = _read("/addon/background.js")
    m = re.search(
        r"async function recordLeakVerdict\([^)]*\)\s*\{([\s\S]+?)\n\}",
        bg,
    )
    assert m, "F-083: could not locate recordLeakVerdict body"
    body = m.group(1)
    # Either inline check or a normalizer call.
    assert (
        "VALID_VERDICT_STATES" in body
        or "LEAK_VERDICT_STATES" in body
        or "normalizeLeakVerdict" in body
    ), (
        "F-083: recordLeakVerdict body does not consult the verdict-"
        "state allowlist before persisting. A typo writer (e.g. "
        "{state: 'clena'}) lands in storage.local and the read-side "
        "treats it as non-clean → silent block-every-send forever."
    )
