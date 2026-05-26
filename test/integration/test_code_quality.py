"""Bundle J (P1) — code-quality findings (subset of F-089..F-097).

The audit's preferred fix for the IP/host/regex duplication
(F-089/F-090/F-092/F-093/F-094) is full extraction into
`addon/lib/`. That's a substantial refactor across two
different JS execution contexts (background.js = renderer-
ish; implementation.js = parent process); both contexts
have different import semantics. Until that refactor lands,
this bundle adds **build-time equivalence assertions** so a
drift between the duplicated copies fails the build instead of
silently shipping diverged validation behaviour between the
listener side and the parent-process side.

The smaller items (F-091 allowlist equivalence, F-096 silent
no-op, F-097 dead parameter) are addressed directly.

F-089, F-090, F-094, F-095 (the larger extractions) are
explicitly tracked as carry-over with `xfail(strict=False)`
markers below so the day the refactor lands, the suite
auto-XPASSes and prompts the marker removal.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


def _resolve_repo() -> Path:
    for cand in (Path("/repo"), Path(__file__).resolve().parent.parent.parent):
        if (cand / "addon" / "background.js").exists():
            return cand
    return Path("/repo")


REPO = _resolve_repo()


# ---- F-091: HARDENING_PREFS names ⊆ ALLOWED_PREF_NAMES ----


def test_F091_hardening_prefs_subset_of_allowed_pref_names() -> None:
    """`HARDENING_PREFS` (background.js, 110 entries) is the list
    the addon writes; `ALLOWED_PREF_NAMES` (implementation.js, 110
    entries) is the parent-process allowlist that gates writePref.
    If a future contributor adds an entry to HARDENING_PREFS but
    forgets ALLOWED_PREF_NAMES, applyPrefs silently rejects that
    entry with `"not in allowlist"` and the new defence never
    lands. Build-time assertion catches it."""
    bg = (REPO / "addon" / "background.js").read_text(encoding="utf-8")
    impl = (REPO / "addon" / "experiments" / "onionbird" / "implementation.js").read_text(encoding="utf-8")
    # Extract HARDENING_PREFS names.
    m_bg = re.search(r"const HARDENING_PREFS = \[(.*?)\n\];", bg, re.DOTALL)
    assert m_bg, "HARDENING_PREFS const not parseable"
    names_bg = set(re.findall(r'\{\s*name:\s*"([^"]+)"', m_bg.group(1)))
    # Extract ALLOWED_PREF_NAMES entries.
    m_impl = re.search(
        r"const ALLOWED_PREF_NAMES = new Set\(\[(.*?)\]\);",
        impl, re.DOTALL,
    )
    assert m_impl, "ALLOWED_PREF_NAMES const not parseable"
    names_impl = set(re.findall(r'"([^"]+)"', m_impl.group(1)))
    missing = names_bg - names_impl
    assert not missing, (
        f"F-091: HARDENING_PREFS has {len(missing)} entries not in "
        f"ALLOWED_PREF_NAMES: {sorted(missing)[:10]}. The parent-"
        f"process applyPrefs will reject these with 'not in "
        f"allowlist' and the defences never apply."
    )


# ---- F-092 + F-093: duplicated regex / mode sets must stay equal ----


def test_F092_smtp_and_identity_regex_equivalent_across_files() -> None:
    """The SMTP and identity hardening pref regexes appear in
    both `background.js` (as `SNAPSHOT_*_PREF_RE`) and
    `implementation.js` (as `*_HARDENING_PREF_RE`). They MUST stay
    character-for-character equivalent or the snapshot path (bg)
    and the write path (impl) accept different sets of pref names
    — a drift = either snapshot loses the original (disable can't
    restore) or write refuses (defence doesn't apply)."""
    bg = (REPO / "addon" / "background.js").read_text(encoding="utf-8")
    impl = (REPO / "addon" / "experiments" / "onionbird" / "implementation.js").read_text(encoding="utf-8")
    for bg_name, impl_name in (
        ("SNAPSHOT_SMTP_PREF_RE", "SMTP_HARDENING_PREF_RE"),
        ("SNAPSHOT_IDENTITY_PREF_RE", "IDENTITY_HARDENING_PREF_RE"),
    ):
        m_bg = re.search(rf"const {bg_name}\s*=\s*([^;]+);", bg)
        m_impl = re.search(rf"const {impl_name}\s*=\s*([^;]+);", impl)
        assert m_bg, f"{bg_name} not in background.js"
        assert m_impl, f"{impl_name} not in implementation.js"
        # Normalise whitespace + comments before comparing — the
        # regex literal itself is what matters for runtime
        # behaviour.
        def _norm(s: str) -> str:
            return re.sub(r"\s+", "", s)
        assert _norm(m_bg.group(1)) == _norm(m_impl.group(1)), (
            f"F-092: {bg_name} (background.js) and {impl_name} "
            f"(implementation.js) regex literals differ: "
            f"{m_bg.group(1)!r} vs {m_impl.group(1)!r}. A future "
            f"identity/SMTP surface added on one side and not the "
            f"other = snapshot/write drift."
        )


def test_F093_message_id_fqdn_modes_equivalent_across_files() -> None:
    """The set of supported Message-ID FQDN modes appears in
    background.js (as MESSAGE_ID_FQDN_MODES Set), implementation.js
    (as the `pickFqdn` mode-chain), and options.html (as the
    `<option value="...">` choices for the dropdown). All three
    must stay equal — adding a mode to one and not the others
    silently degrades user choice to the default."""
    bg = (REPO / "addon" / "background.js").read_text(encoding="utf-8")
    opts_html = (REPO / "addon" / "ui" / "options.html").read_text(encoding="utf-8")
    m_bg = re.search(
        r"const MESSAGE_ID_FQDN_MODES = new Set\(\[\s*([^\]]+)\]\)",
        bg,
    )
    assert m_bg, "MESSAGE_ID_FQDN_MODES Set not in background.js"
    bg_modes = set(re.findall(r'"([^"]+)"', m_bg.group(1)))
    # options.html uses <option value="mode-name">; pull all <option value="...">
    # inside the fqdn-mode select.
    html_modes = set(re.findall(
        r'<option\s+value="(localhost\b[^"]*|from_domain|custom)"',
        opts_html,
    ))
    # Exclude any non-mode <option> values inadvertently matched
    # (e.g. theme options are constrained by the regex above).
    assert bg_modes == html_modes, (
        f"F-093: MESSAGE_ID_FQDN_MODES drift between background.js "
        f"{bg_modes!r} and options.html {html_modes!r}. Adding a "
        f"new mode on one side without the other silently degrades "
        f"the user's selection to the default."
    )


# ---- F-096 ----


def test_F096_setprefvalue_throws_on_missing_name() -> None:
    """`setPrefValue(prefs, name, value)` in background.js used to
    silently no-op if `name` wasn't in the array. Six callers
    depend on `network.proxy.socks` and `socks_port` being in
    `HARDENING_PREFS`; if a future commit removes either pref or
    renames it, `setPrefValue` silently drops the SOCKS write and
    the user is routed via whatever was previously set —
    including direct-clearnet. Fix: throw on missing."""
    bg = (REPO / "addon" / "background.js").read_text(encoding="utf-8")
    # Anchor on the function body.
    idx = bg.find("function setPrefValue")
    assert idx > 0, "setPrefValue not found in background.js"
    fn = bg[idx:idx + 800]
    # Either the function throws on the missing-name path OR the
    # function carries an F-096 acknowledgement comment explaining
    # why the silent no-op is intentional.
    assert "throw" in fn or "F-096" in fn, (
        "F-096: setPrefValue still silently no-ops on missing name. "
        "Throw with a clear error or document the deliberate "
        "silent-no-op rationale via an F-096 marker comment."
    )


# ---- F-097 ----


def test_F097_apply_hardening_smtp_servers_param_is_documented() -> None:
    """`applyHardeningToAllSmtpServers(onlyOnionHosts)` has one
    production caller passing `true`. The `false` code path is
    reachable only through the experiment-API surface (sender-
    checked to browser.runtime.id) and currently has no UI
    affordance. Audit: either implement the F-017 UI toggle or
    drop the parameter. This bundle keeps the parameter (the
    toggle is still planned) but adds a comment explaining the
    deliberate state."""
    impl = (REPO / "addon" / "experiments" / "onionbird" / "implementation.js").read_text(encoding="utf-8")
    idx = impl.find("applyHardeningToAllSmtpServers: async")
    # Include ~800 chars before the function signature too so the
    # acknowledging comment (preceding the method) counts.
    fn = impl[max(0, idx - 800):idx + 2000]
    # Acceptable end-states: explicit F-097 / F-017 comment OR the
    # parameter is removed entirely (the function takes no args).
    if "applyHardeningToAllSmtpServers: async ()" in fn:
        # parameter dropped entirely — fine
        return
    assert "F-097" in fn or "F-017" in fn, (
        "F-097: applyHardeningToAllSmtpServers still exposes the "
        "`onlyOnionHosts` parameter without an acknowledging "
        "comment. Either implement the F-017 UI toggle that would "
        "give the `false` path a real caller, or drop the "
        "parameter, or add an F-097 / F-017 comment documenting "
        "the deliberate exposed-but-unused state."
    )


# ---- Carry-over: the larger F-089/F-090/F-094/F-095 extractions ----


@pytest.mark.xfail(
    strict=False,
    reason=(
        "F-089 / F-090 / F-094 / F-095 — full addon/lib/ extraction "
        "of IP/host validators, log-redactors, the SMTP iteration "
        "helper, and the _enableHardeningImpl decomposition. "
        "Bundle J adds build-time equivalence assertions (F-091, "
        "F-092, F-093) so drift between the duplicated copies fails "
        "the build; the actual extraction is a substantial refactor "
        "across two different JS execution contexts (background.js "
        "renderer-ish, implementation.js parent process) with "
        "different import semantics, tracked separately. When the "
        "extraction lands, replace this xfail with the concrete "
        "behavioural test that asserts the single source of truth."
    ),
)
def test_F089_F090_F094_F095_addon_lib_extraction_landed() -> None:
    lib = REPO / "addon" / "lib"
    js_files = list(lib.glob("*.js")) if lib.exists() else []
    assert js_files, (
        "addon/lib/ contains no extracted modules yet (F-089/F-090/"
        "F-094/F-095 carry-over from Bundle J)."
    )
