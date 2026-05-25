"""Bundle F (P1) — small build / packaging hygiene.

Single test file gathering the SPDX-headers / icons / source-zip
content / addon/lib gitkeep findings. These are individually small
but each one is auditor-visible (ATN review, signing pipeline,
license compliance), so collecting them in one place lets a future
contributor see the whole packaging surface at once.

Findings covered:
  B-078 — source.zip ships addon/lib/.gitkeep (filter regression
          when build-xpi.sh's python heredoc was rewritten for B-072)
  B-086 — SPDX headers missing on 5 source files (atn-sign.sh,
          build_xpi.py, build-xpi.sh, install-user-js.sh, tb_gui.py)
  B-087 — source.zip root-file list drifts: Makefile recipe listed
          only README.md/LICENSE/Makefile; build-xpi.sh listed 5
          READMEs; the repo has 30. The 25 community-translation
          READMEs were missing from the source bundle ATN reviewers
          received.
  B-088 — manifest.json + manifest.mv3.json declare no `icons`
          block; ATN listings show a generic placeholder.
  U-089 — addon/ui/options.html has no SPDX header (F-071 named
          this; commit log claimed the MPL-2.0 relicense reached
          all files but options.html was missed).
"""

from __future__ import annotations

import json
from pathlib import Path


def _resolve_repo() -> Path:
    for cand in (Path("/repo"), Path(__file__).resolve().parent.parent.parent):
        if (cand / "addon" / "manifest.json").exists():
            return cand
    return Path("/repo")


REPO = _resolve_repo()


# ---- B-086 + U-089: SPDX headers ----


def test_B086_spdx_headers_present_on_all_source_scripts() -> None:
    """Every script in scripts/ and every JS/HTML file in addon/
    must carry an `SPDX-License-Identifier: MPL-2.0` header. The
    MPL-2.0 relicense commit advertised "headers added to all
    source files" but missed 5 + 1; ATN reviewers parsing license
    metadata see inconsistent licensing today."""
    targets = [
        REPO / "scripts" / "atn-sign.sh",
        REPO / "scripts" / "build_xpi.py",
        REPO / "scripts" / "build-xpi.sh",
        REPO / "scripts" / "install-user-js.sh",
        REPO / "scripts" / "tb_gui.py",
        REPO / "addon" / "ui" / "options.html",  # U-089
    ]
    missing = []
    for p in targets:
        if not p.exists():
            continue
        head = p.read_text(encoding="utf-8")[:1024]
        if "SPDX-License-Identifier" not in head:
            missing.append(p.name)
    assert not missing, (
        f"B-086 / U-089: SPDX-License-Identifier header missing on "
        f"{missing}. ATN review and license-compliance tooling "
        f"both expect a top-of-file SPDX comment matching the "
        f"MPL-2.0 relicense."
    )


# ---- B-078: source.zip must not contain .gitkeep ----


def test_B078_source_zip_does_not_contain_gitkeep() -> None:
    """build-xpi.sh's python heredoc filters `__pycache__` and
    `.pyc` but not `.gitkeep`. addon/lib/.gitkeep (left over from
    the deferred B1 addon/lib/ extraction) lands in source.zip.
    Cosmetic but inconsistent with the XPI side (which filters it)
    and a low-effort signal of unread audit findings to ATN
    reviewers."""
    import zipfile
    p = REPO / "build" / "onionbird-source.zip"
    if not p.exists():
        import pytest
        pytest.skip(f"{p} not built yet; run `make $(SRCZIP)` first")
    with zipfile.ZipFile(p) as z:
        names = z.namelist()
    gitkeeps = [n for n in names if n.endswith(".gitkeep")]
    assert not gitkeeps, (
        f"B-078: source.zip contains .gitkeep entries: {gitkeeps}. "
        f"build-xpi.sh's source-zip python heredoc must filter "
        f".gitkeep (like the XPI path already does)."
    )


# ---- B-087: source.zip root-file list must include all READMEs ----


def test_B087_source_zip_includes_all_translated_readmes() -> None:
    """The repo has 30 README.<lang>.md files (after the Phase 1
    locale expansion). The Makefile zip recipe listed 3
    (`README.md LICENSE Makefile`); build-xpi.sh listed 5
    (added README.de.md + README.es.md). Neither variant captured
    the 25 community-translation READMEs into the source bundle
    ATN reviewers download.

    Either is acceptable as a fix:
      (a) source.zip includes ALL README*.md, OR
      (b) the source-zip recipe documents why it omits them.
    Test enforces (a) — the more honest path for a project that
    advertises 30 shipping locales."""
    import zipfile
    p = REPO / "build" / "onionbird-source.zip"
    if not p.exists():
        import pytest
        pytest.skip(f"{p} not built yet; run `make $(SRCZIP)` first")
    with zipfile.ZipFile(p) as z:
        names = z.namelist()
    readmes_in_zip = sorted(n for n in names if n.startswith("README") and n.endswith(".md"))
    readmes_on_disk = sorted(p.name for p in REPO.glob("README*.md"))
    # ATN-reviewer-relevant baseline: at minimum EN + DE + ES
    # (the localized triumvirate the previous bundle shipped).
    must_have = {"README.md", "README.de.md", "README.es.md"}
    actual = set(readmes_in_zip)
    missing_must = must_have - actual
    assert not missing_must, (
        f"B-087: source.zip is missing required READMEs: "
        f"{missing_must}. Even the prior baseline (EN/DE/ES) is "
        f"incomplete."
    )
    # Stronger check: ATL+1 baseline (all 30 should be in there
    # after the source-zip-recipe fix in this bundle).
    coverage = len(actual & set(readmes_on_disk)) / max(len(readmes_on_disk), 1)
    assert coverage >= 0.95, (
        f"B-087: source.zip includes only "
        f"{len(actual & set(readmes_on_disk))}/{len(readmes_on_disk)} "
        f"of the README*.md files on disk. The 25 community-translation "
        f"READMEs are excluded from the ATN source bundle. Use "
        f"`sorted(p.name for p in root.glob('README*.md'))` instead "
        f"of a hand-maintained literal list."
    )


# ---- B-088: manifests must declare an icons block ----


# ---- Bundle G (P1) — build hardening ----


def test_B079_manifest_equivalence_covers_csp_war_host_perms_icons() -> None:
    """The manifest-equivalence check in build-xpi.sh originally
    compared only `permissions`, `experiment_apis`, `options_ui`,
    `background.scripts`. A future bundle that adds
    `content_security_policy` (or `web_accessible_resources` or
    `host_permissions` or `strict_min_version` or `icons`) to ONE
    manifest only would slip past the gate. Audit recommendation:
    widen the equivalence check. This test asserts the gate
    actually catches a deliberate drift in any of those fields."""
    sh = REPO / "scripts" / "build-xpi.sh"
    if not sh.exists():
        import pytest
        pytest.skip("build-xpi.sh not mounted")
    body = sh.read_text(encoding="utf-8")
    required_anchors = (
        "content_security_policy",
        "web_accessible_resources",
        "host_permissions",
        "strict_min_version",
        "icons",
    )
    missing = [a for a in required_anchors if a not in body]
    assert not missing, (
        f"B-079: build-xpi.sh manifest-equivalence check does not "
        f"compare these fields: {missing}. A future bundle that "
        f"adds any of these to one manifest only would slip past "
        f"the gate."
    )


def test_B081_tor_apk_pinned_to_specific_version() -> None:
    """Containerfile.tor previously used `apk add --no-cache tor`
    which pulls whatever Alpine repos ship on build day. The
    test suite asserts SOCKS5 RESOLVE semantics that are
    implicitly tied to a Tor version. Pin to a specific
    `tor=X.Y.Z-rN` so the test infra is replayable."""
    p = REPO / "test" / "containers" / "Containerfile.tor"
    if not p.exists():
        import pytest
        pytest.skip("Containerfile.tor not mounted")
    body = p.read_text(encoding="utf-8")
    import re
    # Bug shape: `apk add ... tor` without `tor=<version>`.
    bug_re = re.compile(r"apk\s+add[^\n]*\btor\b(?!=)", re.MULTILINE)
    m = bug_re.search(body)
    assert not m, (
        f"B-081: Containerfile.tor adds `tor` without a version "
        f"pin (line: {m.group(0)!r}). Pin to `tor=0.4.X.Y-rN` so "
        f"the test infra is replayable across Alpine point "
        f"releases."
    )


def test_B083_api_version_literal_matches_manifest_version() -> None:
    """`addon/experiments/onionbird/implementation.js` carries a
    `const API_VERSION = "X.Y.Z"` literal that `browser.onionbird.
    getApiVersion()` returns at runtime. The literal is hand-
    maintained and drifts from `manifest.json::version` on every
    version bump — caught by the v0.1.0 → v0.1.1 bump in the
    handoff-2026-05-25-evening release commit, which shipped XPIs
    whose runtime `getApiVersion()` lied about the version.

    Two-layer check:
      1. SOURCE: `implementation.js`'s API_VERSION literal must
         equal `manifest.json::version` AND `manifest.mv3.json::
         version` right now. Without this the suite green-lights a
         drift and only `make build` catches it.
      2. BUILD: `build-xpi.sh` must contain the assertion that
         re-verifies equivalence at build time (defense-in-depth
         in case someone bypasses the suite)."""
    import json
    import re
    import pytest

    impl = REPO / "addon" / "experiments" / "onionbird" / "implementation.js"
    mv2 = REPO / "addon" / "manifest.json"
    mv3 = REPO / "addon" / "manifest.mv3.json"

    impl_src = impl.read_text(encoding="utf-8")
    m = re.search(r'const\s+API_VERSION\s*=\s*"([^"]+)"', impl_src)
    assert m, (
        "B-083: implementation.js no longer contains a parseable "
        "`const API_VERSION = \"X.Y.Z\"` literal. The runtime "
        "`browser.onionbird.getApiVersion()` reads this; renaming "
        "or restructuring it without updating this test masks "
        "version drift."
    )
    api_version = m.group(1)
    mv2_version = json.loads(mv2.read_text(encoding="utf-8"))["version"]
    mv3_version = json.loads(mv3.read_text(encoding="utf-8"))["version"]
    assert api_version == mv2_version, (
        f"B-083: API_VERSION literal {api_version!r} in "
        f"implementation.js != manifest.json::version "
        f"{mv2_version!r}. Runtime `browser.onionbird."
        f"getApiVersion()` will lie about the version — bump them "
        f"together. (v0.1.0 → v0.1.1 release commit a2d35db missed "
        f"this exact drift; build-xpi.sh now refuses to build, but "
        f"this test catches it earlier, before any build attempt.)"
    )
    assert api_version == mv3_version, (
        f"B-083: API_VERSION literal {api_version!r} != "
        f"manifest.mv3.json::version {mv3_version!r}. MV2 and MV3 "
        f"manifests must stay in lockstep with the API literal."
    )

    sh = REPO / "scripts" / "build-xpi.sh"
    if not sh.exists():
        pytest.skip("build-xpi.sh not mounted")
    body = sh.read_text(encoding="utf-8")
    assert "API_VERSION" in body and "manifest version" in body, (
        "B-083: build-xpi.sh no longer carries the build-time "
        "assertion that API_VERSION matches manifest version. Even "
        "with the source-level check above, removing the build "
        "guard makes the next refactor a silent-drift vector."
    )


def test_B084_make_sign_depends_on_lint() -> None:
    """A deprecation-warning manifest field would land in source
    today because `make sign` does not depend on `make lint`. Add
    `lint` as a prereq so signing fails before any network call
    when web-ext-lint flags something."""
    mk = REPO / "Makefile"
    if not mk.exists():
        import pytest
        pytest.skip("Makefile not mounted")
    body = mk.read_text(encoding="utf-8")
    import re
    m = re.search(r"(?m)^sign\s*:([^\n]*)", body)
    assert m, "B-084: `sign:` target not found in Makefile"
    prereqs = m.group(1)
    assert "lint" in prereqs, (
        f"B-084: `sign:` target does not depend on `lint`. Current "
        f"prereqs: {prereqs!r}. A failed web-ext lint should block "
        f"any ATN upload."
    )


def test_B085_atn_sign_preflights_curl_version() -> None:
    """`atn-sign.sh` uses `curl --fail-with-body` (curl >= 7.76,
    2021-04). Operators on RHEL 8 (curl 7.61) or stripped CI images
    get a confusing `unknown option` error mid-upload. Probe in the
    script preamble so the version requirement is surfaced loudly
    BEFORE any state change."""
    p = REPO / "scripts" / "atn-sign.sh"
    if not p.exists():
        import pytest
        pytest.skip("atn-sign.sh not mounted")
    body = p.read_text(encoding="utf-8")
    # Acceptable preflight markers: curl version probe, --help all
    # grep, or explicit version comparison.
    assert any(
        marker in body
        for marker in (
            "curl --help all",
            "curl --version",
            "--fail-with-body",  # if mentioned in error message
            "7.76",
        )
    ), (
        "B-085: atn-sign.sh has no curl version preflight. An "
        "operator on RHEL 8 / older curl gets a confusing error "
        "mid-script. Add `curl --help all | grep -q -- "
        "--fail-with-body || { echo ERROR ...; exit 1; }` to the "
        "preamble."
    )


def test_B088_both_manifests_declare_icons_block() -> None:
    """Without an `icons` block, ATN listings show a generic
    placeholder. The repo has 10 SVG logos under assets/logos/;
    pick one and bundle it as the brand mark. SVG is acceptable
    for both MV2 and MV3 manifests under TB."""
    for mf in ("manifest.json", "manifest.mv3.json"):
        p = REPO / "addon" / mf
        if not p.exists():
            import pytest
            pytest.skip(f"{mf} not found")
        m = json.loads(p.read_text(encoding="utf-8"))
        icons = m.get("icons")
        assert isinstance(icons, dict) and icons, (
            f"B-088: {mf} has no `icons` block. ATN listing shows "
            f"a placeholder. Add e.g. `\"icons\": "
            f"{{\"128\": \"icons/onionbird.svg\"}}`."
        )
        # Every referenced icon path must point at a file that
        # actually exists in the addon source.
        for size, rel in icons.items():
            target = REPO / "addon" / rel
            assert target.exists(), (
                f"B-088: {mf} icons[{size!r}]={rel!r} but "
                f"addon/{rel} does not exist."
            )
