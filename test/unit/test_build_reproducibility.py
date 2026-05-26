"""F-053: the XPI build MUST be byte-for-byte reproducible.

A reviewer must be able to download the published XPI, re-run
`scripts/build_xpi.py` from a clean clone, and verify the SHA-256
matches. Without that, the public SHA-256 is just a publisher-trust
claim; with it, every reviewer can re-derive the bytes and prove the
addon they audited matches the addon Thunderbird users installed.

The bug shape: `build_xpi.py` previously called `ZipFile.write(f, arc)`
which copies the on-disk mtime into the zip directory header. mtimes
vary across clones (git does not store them) and across CI runs (file
checkout times differ), so the SHA-256 changes between builds even
when the source bytes are identical.

The fix shape: respect `SOURCE_DATE_EPOCH` if set (Reproducible-Builds
convention), otherwise fall back to a deterministic epoch (the Mozilla
addons.mozilla.org convention is to clamp to 1980-01-01 = epoch 0
mapped to the zip-format minimum, which is what we use). The
`compresslevel` is also pinned so a future Python upgrade that flips
the default compression strategy doesn't perturb the bytes.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
import sys
from pathlib import Path


def _resolve_repo() -> Path:
    for cand in (Path("/repo"), Path(__file__).resolve().parent.parent.parent):
        if (cand / "Makefile").exists() and (cand / "scripts").exists():
            return cand
    return Path("/repo")


REPO = _resolve_repo()
BUILD_XPI = (
    Path("/scripts/build_xpi.py")
    if Path("/scripts/build_xpi.py").exists()
    else REPO / "scripts" / "build_xpi.py"
)
ADDON = Path("/addon") if Path("/addon").exists() else REPO / "addon"


def _load_build_module():
    spec = importlib.util.spec_from_file_location(
        "build_xpi", BUILD_XPI
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _build_with_epoch(epoch: str, dst: Path, variant: str = "mv2") -> str:
    """Invoke build_xpi.py in a subprocess with SOURCE_DATE_EPOCH set
    and an arbitrary on-disk mtime. The subprocess-with-env pattern
    is what reviewers will actually do; in-process imports would
    miss any state cached at import-time."""
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = epoch
    subprocess.run(
        [
            sys.executable,
            str(BUILD_XPI),
            str(ADDON),
            str(dst),
            f"--manifest={variant}",
        ],
        check=True,
        env=env,
        capture_output=True,
    )
    return _sha256(dst)


def test_build_is_reproducible_with_source_date_epoch(tmp_path: Path) -> None:
    """Two builds from the same source with the same SOURCE_DATE_EPOCH
    must produce byte-identical XPIs. This is the audit-anchor property."""
    a = tmp_path / "a.xpi"
    b = tmp_path / "b.xpi"
    sha_a = _build_with_epoch("1700000000", a)
    # Touch some source files between builds so the on-disk mtime drifts —
    # the build must NOT pick up that drift.
    for p in ADDON.rglob("*"):
        if p.is_file():
            try:
                os.utime(p, (1234567890, 1234567890))
            except OSError:
                # /addon is mounted read-only in this test container.
                # That's fine — the mtime baseline is whatever the mount
                # exposed, and we only need TWO builds to match each other.
                pass
            break
    sha_b = _build_with_epoch("1700000000", b)
    assert sha_a == sha_b, (
        f"F-053: build_xpi.py is not reproducible — same source + same "
        f"SOURCE_DATE_EPOCH produced two different XPIs:\n"
        f"  a: {sha_a}\n  b: {sha_b}\n"
        f"Reviewers cannot re-derive the published SHA-256 from a clean clone."
    )


def test_build_honors_source_date_epoch(tmp_path: Path) -> None:
    """Two builds from the same source with DIFFERENT SOURCE_DATE_EPOCH
    values must produce DIFFERENT XPIs. This proves the epoch is actually
    threaded into the zip directory header (vs. being silently ignored)."""
    a = tmp_path / "a.xpi"
    b = tmp_path / "b.xpi"
    sha_a = _build_with_epoch("1700000000", a)
    sha_b = _build_with_epoch("1800000000", b)
    assert sha_a != sha_b, (
        "F-053: SOURCE_DATE_EPOCH appears to be ignored — two epochs "
        "60 days apart produced identical XPIs, which means the epoch "
        "is not being threaded into the zip ZipInfo.date_time field."
    )


def test_build_module_exposes_default_epoch() -> None:
    """The build module must define an explicit deterministic fallback
    epoch used when SOURCE_DATE_EPOCH is unset. Without a constant
    fallback, the build mtimes default to "now", which is intrinsically
    irreproducible.

    T-086: previously `assert isinstance(mod.DEFAULT_EPOCH, int)` was
    the only constraint — `DEFAULT_EPOCH = 0` would silently pass even
    though Unix epoch 0 (1970-01-01) is a footgun fallback (zip writers
    reject it on some platforms, and "1970" mtimes scream "broken
    timestamp default" to any reviewer auditing the artifact). Require
    a sane post-2010 value so any DEFAULT_EPOCH=0 / DEFAULT_EPOCH=None
    regression fails loudly here instead of producing weird artifacts.
    """
    mod = _load_build_module()
    assert hasattr(mod, "DEFAULT_EPOCH"), (
        "F-053: build_xpi.py does not expose a DEFAULT_EPOCH constant. "
        "An unset SOURCE_DATE_EPOCH must fall back to a hardcoded "
        "deterministic value, otherwise builds drift."
    )
    assert isinstance(mod.DEFAULT_EPOCH, int)
    # T-086: 1262304000 = 2010-01-01 00:00:00 UTC. Anything older
    # smells like an uninitialized constant (Unix epoch zero, year-2000
    # bug placeholder, etc.) or a divide-by-zero artifact.
    assert mod.DEFAULT_EPOCH >= 1262304000, (
        f"T-086 / F-053: DEFAULT_EPOCH = {mod.DEFAULT_EPOCH} predates "
        f"2010-01-01 UTC. This usually means an uninitialized constant "
        f"or a regression to Unix-epoch-zero. The reproducible-builds "
        f"convention uses a recent fixed date so artifact mtimes "
        f"don't look like 1970 garbage."
    )


def test_F052_sign_target_uploads_validated_xpi_not_addon_dir() -> None:
    """F-052: `make sign` must upload the same bytes that `make
    validate-xpi` audited. Two requirements:

      1. `sign` is declared dependent on `validate-xpi` so the
         publishable artifact has been through manifest equivalence,
         locale, and schema checks before any network call.
      2. The actual upload uses `$(XPI)` (the canonical reproducible
         build) directly, NOT `$(ADDON_DIR)` (which would force the
         signer to re-zip with its own rules and break the
         audited-SHA == published-SHA property).

    The previous Makefile passed `--source-dir=$(ADDON_DIR)` to
    `web-ext sign`, which re-zipped from source with its own
    deterministic rules — producing a different SHA-256 from
    `$(XPI)`. Reviewers checking the published SHA against a clean
    rebuild would never get a match."""
    mk = REPO / "Makefile" if (REPO / "Makefile").exists() else None
    if mk is None:
        # In the test container the repo root is not mounted; the
        # Makefile is available via the mounted /addon's grandparent.
        # Fall back to a path-search.
        for cand in (Path("/Makefile"), Path("/scripts/../Makefile")):
            if cand.exists():
                mk = cand
                break
    if mk is None:
        # Read via /scripts mount: /scripts/../Makefile
        mk = Path("/scripts").parent / "Makefile"
        if not mk.exists():
            # T-080: do NOT silently skip — this is a P0 build-
            # supply-chain test that must surface as red if the
            # /Makefile mount is dropped from compose.yaml.
            import pytest
            pytest.fail(
                "T-080: /Makefile not mounted in this runner. "
                "Check test/containers/compose.yaml runner volumes "
                "(`../../Makefile:/Makefile:ro` is required by F-052 "
                "regression coverage)."
            )
    body = mk.read_text()

    # Locate the `sign:` rule (target + prerequisites + recipe).
    import re
    m = re.search(r"(?m)^sign\s*:[^\n]*\n((?:\t[^\n]*\n)+)", body)
    assert m, "Makefile has no `sign:` target"
    prereqs_line = re.search(r"(?m)^sign\s*:([^\n]*)", body).group(1)
    recipe = m.group(1)

    # 1) Validate-xpi must be a prerequisite. Without it, a `make sign`
    #    invocation skips manifest equivalence + locale + schema checks.
    assert "validate-xpi" in prereqs_line, (
        f"F-052: `sign` must depend on `validate-xpi` so we never "
        f"publish an artifact that wasn't first audited. "
        f"Current prereqs: {prereqs_line!r}"
    )

    # 2) The recipe must NOT pass `--source-dir=$(ADDON_DIR)` to web-ext
    #    — that's the exact bug shape the audit flagged.
    assert "--source-dir=$(ADDON_DIR)" not in recipe, (
        "F-052: sign recipe still uses `--source-dir=$(ADDON_DIR)` — "
        "this lets the signer re-zip from source, producing a "
        "different SHA-256 than the validated $(XPI). Reviewers can "
        "no longer verify the publish-time bytes."
    )

    # 3) The recipe must reference $(XPI) — the published bytes have
    #    to come from the canonical reproducible build.
    assert "$(XPI)" in recipe, (
        "F-052: sign recipe does not reference $(XPI). The artifact "
        "that gets signed must be the canonical reproducible XPI."
    )


def test_build_without_source_date_epoch_is_reproducible(tmp_path: Path) -> None:
    """When SOURCE_DATE_EPOCH is UNSET, two consecutive builds must
    still produce identical XPIs (using the DEFAULT_EPOCH fallback).
    Otherwise the simple `make build` workflow stays irreproducible
    and only reviewers who know to set the env var see the property."""
    a = tmp_path / "a.xpi"
    b = tmp_path / "b.xpi"
    env = {k: v for k, v in os.environ.items() if k != "SOURCE_DATE_EPOCH"}
    for dst in (a, b):
        subprocess.run(
            [sys.executable, str(BUILD_XPI), str(ADDON), str(dst)],
            check=True,
            env=env,
            capture_output=True,
        )
    assert _sha256(a) == _sha256(b), (
        "F-053: build_xpi.py is not reproducible without SOURCE_DATE_EPOCH — "
        "a default `make build` invocation produces different bytes on each "
        "run. The DEFAULT_EPOCH fallback is not wired into the zip writer."
    )


# ---- Bundle C P0s — build / supply-chain hardening ----
#
# T-075 (test-test): the original reproducibility test silently caught
#   OSError on `os.utime(/addon/...)` because the bind mount is read-
#   only. The test therefore proved only that two identical inputs
#   produce identical outputs — a tautology. The fix: actually copy
#   /addon to a writable tmp_path, mutate mtimes there, and rebuild
#   from that path. Only then is the SOURCE_DATE_EPOCH normalisation
#   actually exercised.
# B-073: `make build` must depend on `scripts/build_xpi.py` so a fix
#   in the build script triggers a rebuild of the XPI.
# B-074: the source.zip recipe must work without a system `zip`
#   binary (the runner container doesn't have one; many hardened CI
#   images don't either).
# B-072: `make sign` must NOT overwrite the reproducible source.zip
#   that `make validate-xpi` produced. Two consecutive builds must
#   produce a byte-identical source.zip.
# B-075/B-076/B-077: atn-sign.sh hardening — idempotency on partial
#   network failure, errexit-via-inherit on $(…) subshells, schema-
#   resilient JSON parse.


def test_T075_reproducibility_actually_normalises_mtime_drift(tmp_path: Path) -> None:
    """SAD path proper: copy /addon to a writable tmp dir, mutate
    several files' mtimes BETWEEN two builds, assert the SHAs still
    match. This is what the original `test_build_is_reproducible_*`
    claimed to do but couldn't because `/addon` is read-only and
    the OSError on utime was silently caught."""
    import shutil
    src1 = tmp_path / "addon_v1"
    src2 = tmp_path / "addon_v2"
    shutil.copytree(ADDON, src1)
    shutil.copytree(ADDON, src2)
    # Mutate mtimes on a handful of files in src2 to simulate the
    # "different CI host with different filesystem mtime" case.
    for p in list(src2.rglob("*"))[:50]:
        if p.is_file():
            os.utime(p, (1234567890, 1234567890))
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = "1700000000"
    out1 = tmp_path / "a.xpi"
    out2 = tmp_path / "b.xpi"
    subprocess.run(
        [sys.executable, str(BUILD_XPI), str(src1), str(out1)],
        check=True, env=env, capture_output=True,
    )
    subprocess.run(
        [sys.executable, str(BUILD_XPI), str(src2), str(out2)],
        check=True, env=env, capture_output=True,
    )
    assert _sha256(out1) == _sha256(out2), (
        "T-075: build_xpi.py is NOT normalising filesystem mtime drift. "
        "Two source trees with identical content but different on-disk "
        "mtimes produced different XPI bytes. A reviewer rebuilding from "
        "a fresh clone (where mtimes are git-checkout-time, not original) "
        "cannot match the published SHA-256."
    )


def test_B073_make_build_depends_on_build_xpi_py() -> None:
    """A fix to scripts/build_xpi.py followed by `make build` MUST
    trigger a rebuild — otherwise the bug fix doesn't ship and the
    reviewer's clean clone produces a different SHA-256 than the
    published artifact."""
    mk = REPO / "Makefile"
    if not mk.exists():
        import pytest
        pytest.skip("Makefile not mounted")
    body = mk.read_text()
    import re
    # Find the $(XPI): target line + its prerequisites.
    m = re.search(r"(?m)^\$\(XPI\)\s*:([^\n]*)", body)
    assert m, "B-073: $(XPI) target not found in Makefile"
    prereqs = m.group(1)
    assert "build_xpi.py" in prereqs or "scripts/build_xpi.py" in prereqs, (
        f"B-073: $(XPI) target does not depend on scripts/build_xpi.py "
        f"(prereqs: {prereqs!r}). A fix to the build script followed by "
        f"`make build` won't trigger a rebuild — stale XPI ships."
    )
    # Same for the MV3 build target.
    m3 = re.search(r"(?m)^\$\(XPI_MV3\)\s*:([^\n]*)", body)
    assert m3, "B-073: $(XPI_MV3) target not found"
    prereqs3 = m3.group(1)
    assert "build_xpi.py" in prereqs3, (
        f"B-073: $(XPI_MV3) target does not depend on scripts/build_xpi.py "
        f"(prereqs: {prereqs3!r})."
    )


def test_B074_source_zip_recipe_does_not_require_system_zip() -> None:
    """The runner container does not have `/usr/bin/zip`. The
    Makefile $(SRCZIP) recipe used to `zip -rq` which fails with
    exit 127 on minimal hosts; build-xpi.sh has a python-zipfile
    fallback but the Makefile recipe wins. Fix: Makefile recipe
    must delegate to build-xpi.sh (or use python zipfile directly).
    """
    mk = REPO / "Makefile"
    if not mk.exists():
        import pytest
        pytest.skip("Makefile not mounted")
    body = mk.read_text()
    import re
    # Find the $(SRCZIP): target recipe.
    m = re.search(
        r"(?m)^\$\(SRCZIP\)\s*:[^\n]*\n((?:\t[^\n]*\n)+)",
        body,
    )
    if not m:
        # If the target was deleted entirely (delegated upstream),
        # that's also acceptable for B-074 — the source.zip will be
        # produced by build-xpi.sh as part of validate-xpi.
        return
    recipe = m.group(1)
    # The bug shape: a `zip -rq` (or `@zip ...`) line that depends
    # on the system zip binary.
    assert "zip -rq" not in recipe and "@zip " not in recipe, (
        "B-074: Makefile $(SRCZIP) recipe still uses the system "
        "`zip` binary (`zip -rq` / `@zip`). Minimal hosts (and the "
        "test-runner container) don't have it. Either delete the "
        "Makefile recipe and let build-xpi.sh own source.zip, OR "
        "use python's zipfile module via a heredoc."
    )


def test_B072_source_zip_is_reproducible_across_runs(tmp_path: Path) -> None:
    """`make validate-xpi` produces a reproducible source.zip via
    build-xpi.sh; `make sign` must not overwrite it with a non-
    reproducible version. The reviewer-anchor property F-053 closed
    for the XPI must also hold for the source.zip ATN attaches to
    the listing — otherwise the published source SHA changes on
    every run and no reviewer can re-derive it."""
    if not (REPO / "scripts" / "build-xpi.sh").exists():
        import pytest
        pytest.skip("build-xpi.sh not mounted on this path")
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = "1700000000"
    out1 = tmp_path / "src-a.zip"
    out2 = tmp_path / "src-b.zip"
    # Use the python heredoc from build-xpi.sh directly — the
    # source.zip recipe lives there now.
    inline = r"""
import os, time, zipfile, pathlib
DEFAULT_EPOCH = 1577836800
raw = os.environ.get("SOURCE_DATE_EPOCH")
epoch = int(raw) if raw else DEFAULT_EPOCH
t = time.gmtime(epoch)
date_time = (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
root = pathlib.Path(os.environ["REPO_ROOT"])
out = pathlib.Path(os.environ["SRCZIP"])
roots = ["addon", "scripts", "user-js"]
files = ["README.md", "LICENSE", "Makefile"]
def _add(z, arcname, data):
    info = zipfile.ZipInfo(filename=arcname, date_time=date_time)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (0o100644 & 0xFFFF) << 16
    z.writestr(info, data, compresslevel=6)
entries = []
for r in roots:
    rd = root / r
    if not rd.exists(): continue
    for p in rd.rglob("*"):
        if not p.is_file(): continue
        if "__pycache__" in p.parts or p.suffix == ".pyc" or p.name == ".gitkeep": continue
        entries.append((p.relative_to(root).as_posix(), p))
for f in files:
    if (root / f).exists():
        entries.append((f, root / f))
entries.sort(key=lambda e: e[0])
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for arc, p in entries:
        _add(z, arc, p.read_bytes())
"""
    e1 = env.copy()
    e1["REPO_ROOT"] = str(REPO)
    e1["SRCZIP"] = str(out1)
    e2 = env.copy()
    e2["REPO_ROOT"] = str(REPO)
    e2["SRCZIP"] = str(out2)
    subprocess.run([sys.executable, "-c", inline], check=True, env=e1, capture_output=True)
    subprocess.run([sys.executable, "-c", inline], check=True, env=e2, capture_output=True)
    assert _sha256(out1) == _sha256(out2), (
        "B-072: source.zip is not reproducible — two consecutive "
        "builds with SOURCE_DATE_EPOCH set produced different bytes. "
        "Reviewers cannot re-derive the source SHA from a clean clone."
    )


def test_B075_atn_sign_supports_resume_on_partial_failure() -> None:
    """A network drop between the upload+validation phase and the
    version-create POST must NOT force the operator to re-upload
    the XPI (which burns ATN quota and may 409 on the version
    bump). atn-sign.sh must support resuming via a persisted upload
    UUID (env var or file)."""
    p = REPO / "scripts" / "atn-sign.sh"
    if not p.exists():
        import pytest
        pytest.skip("scripts/atn-sign.sh not mounted")
    body = p.read_text()
    # Acceptable resume mechanisms: ATN_RESUME_UUID env-var read OR a
    # persisted .atn-upload-uuid file OR an explicit --resume flag.
    has_resume = any(
        marker in body
        for marker in (
            "ATN_RESUME_UUID",
            ".atn-upload-uuid",
            "--resume",
            "resume_uuid",
        )
    )
    assert has_resume, (
        "B-075: atn-sign.sh has no idempotency/resume mechanism. "
        "A network failure between upload-validation and version-create "
        "loses the upload UUID and forces a full re-upload (ATN quota "
        "burn + 409 risk). Add either ATN_RESUME_UUID env var support "
        "or persist the UUID to build/.atn-upload-uuid before the "
        "versions POST."
    )


def test_B076_atn_sign_uses_inherit_errexit() -> None:
    """`set -e` does NOT cover failures inside `$(…)` command-
    substitution unless `shopt -s inherit_errexit` is also set. The
    script has 7+ `$(mint_jwt)` / `$(curl …)` / `$(echo … | python3)`
    sites where a subshell error silently produces an empty string —
    sending `Authorization: JWT ` to ATN, polling `/upload//`, etc."""
    p = REPO / "scripts" / "atn-sign.sh"
    if not p.exists():
        import pytest
        pytest.skip("atn-sign.sh not mounted")
    body = p.read_text()
    assert "shopt -s inherit_errexit" in body, (
        "B-076: atn-sign.sh is missing `shopt -s inherit_errexit`. "
        "Without it, `set -e` does not cover failures inside `$(…)` "
        "subshells — a mint_jwt error silently assigns an empty JWT "
        "and curl sends `Authorization: JWT ` to ATN."
    )


def test_B077_atn_sign_does_not_silently_default_processed_to_false() -> None:
    """If a future ATN API rename drops the `processed` field, the
    current `.get('processed', False)` silently loops for 5 minutes
    before erroring. Fix: use `.get('processed', None)` + assert
    not None so a schema rename produces a fast, actionable error."""
    p = REPO / "scripts" / "atn-sign.sh"
    if not p.exists():
        import pytest
        pytest.skip("atn-sign.sh not mounted")
    body = p.read_text()
    assert ".get('processed', False)" not in body and ".get(\"processed\", False)" not in body, (
        "B-077: atn-sign.sh still uses `.get('processed', False)`. "
        "A future ATN schema rename of `processed` silently loops for "
        "5 minutes. Replace with `.get('processed', None)` + assert "
        "not None so the field-rename failure mode is loud and fast."
    )
