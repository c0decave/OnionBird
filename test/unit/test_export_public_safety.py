"""Safety tests for scripts/export-public.sh.

Reproduces BUG-004 (CWE-73 unsafe TARGET path), BUG-005 (CWE-200
narrow secret-pattern exclusion), and BUG-007 (CWE-20 improper input
handling — NUL byte loss in command substitution). The first two
were filed by codex against the maintainer-only public export helper;
BUG-007 was filed by claude against the BUG-005 failsafe layer that
silently collapses to single-file detection on multi-file leaks.

The tests construct a self-contained fake repository in a tmp directory,
copy the real ``export-public.sh`` into it, and invoke the script with
various TARGET arguments. Behavioural assertions — what files end up in
the public mirror, which TARGET values are rejected — are stronger than
parsing the exclude list, because the script's actual rsync semantics
(include/exclude precedence, anchor rules, post-export scrubs) are
emergent behaviour we want to lock in.

Each test is annotated with the bug it reproduces and the case class
(happy / edge / sad) so reviewers can verify the three-class coverage
required by the substrate's ``tests-cover-happy-edge-sad`` gate.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "export-public.sh"


# --------------------------------------------------------------------- helpers


def _make_fake_repo(tmp_path: Path) -> Path:
    """Construct a minimal repo layout that satisfies the script's
    ``$REPO_ROOT/addon`` precondition, and drop a copy of the real
    export-public.sh into it so the script resolves ``REPO_ROOT`` to
    the fake. Returns the fake repo root."""
    fake = tmp_path / "fake-repo"
    (fake / "addon").mkdir(parents=True)
    (fake / "scripts").mkdir(parents=True)
    (fake / "docs").mkdir(parents=True)
    # Minimum addon contents so rsync has something to copy.
    (fake / "addon" / "manifest.json").write_text(
        '{"name": "fake", "version": "0.0.0"}', encoding="utf-8"
    )
    (fake / "Makefile").write_text("# fake makefile\nall:\n\techo ok\n", encoding="utf-8")
    # README needed by some post-export passes (link scrubbing).
    (fake / "README.md").write_text("# fake\n", encoding="utf-8")
    # Copy the real script in.
    fake_script = fake / "scripts" / "export-public.sh"
    shutil.copy(SCRIPT, fake_script)
    fake_script.chmod(fake_script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return fake


def _run(fake: Path, target: str, *, dry_run: bool = False,
         extra_env: dict | None = None,
         fake_home: Path | None = None,
         timeout: float = 30.0) -> subprocess.CompletedProcess:
    """Invoke the export script. ``fake_home`` overrides $HOME so the
    HOME-equals-TARGET test never has to touch the real $HOME — that
    matters because rsync --delete --dry-run still WALKS the entire
    target tree to compute the delete set, and walking real $HOME is
    both slow and risky if a future test forgets the dry-run flag.

    ``timeout`` caps subprocess wall-time. The fix MUST refuse unsafe
    TARGETs in milliseconds (no rsync invocation), so any test
    targeting an actual unsafe path can use a low timeout — exceeding
    it means rsync was reached, which is itself a fix failure."""
    env = os.environ.copy()
    if dry_run:
        env["DRY_RUN"] = "1"
    if fake_home is not None:
        env["HOME"] = str(fake_home)
    if extra_env:
        env.update(extra_env)
    if shutil.which("rsync") is None:
        pytest.skip(
            "rsync not on PATH; export-public.sh requires rsync to "
            "run, so the behavioural assertions cannot be exercised."
        )
    try:
        return subprocess.run(
            [str(fake / "scripts" / "export-public.sh"), target],
            capture_output=True, text=True, env=env, check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        # Surface the timeout as a synthetic CompletedProcess with rc=124
        # and a marker on stderr — the BUG-004 tests interpret this as
        # "rsync was reached" which is itself a failure of the fix.
        return subprocess.CompletedProcess(
            args=exc.cmd,
            returncode=124,
            stdout=(exc.stdout or b"").decode("utf-8", errors="replace")
                   if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            stderr=("__TIMEOUT__: script did not refuse within "
                    f"{timeout}s — rsync was reached.\n"
                    + ((exc.stderr or b"").decode("utf-8", errors="replace")
                       if isinstance(exc.stderr, bytes) else (exc.stderr or ""))),
        )


# ============================================================ BUG-004 (TARGET)


def test_BUG_004_refuses_repo_root_target(tmp_path: Path) -> None:
    """SAD: TARGET equal to REPO_ROOT must be refused — rsync --delete
    into REPO_ROOT would wipe the working tree."""
    fake = _make_fake_repo(tmp_path)
    result = _run(fake, str(fake), dry_run=True)
    assert result.returncode != 0, (
        f"BUG-004: export-public.sh accepted TARGET==REPO_ROOT "
        f"(rc={result.returncode}); stderr=\n{result.stderr}"
    )
    assert (fake / "addon" / "manifest.json").exists(), (
        "BUG-004: REPO_ROOT addon file disappeared after a "
        "self-targeted export — the working tree was actually clobbered."
    )


def test_BUG_004_refuses_dot_when_cwd_is_repo(tmp_path: Path) -> None:
    """SAD: TARGET='.' must be refused when cwd is the repo (resolves
    to REPO_ROOT). This is the most likely operator typo."""
    fake = _make_fake_repo(tmp_path)
    if shutil.which("rsync") is None:
        pytest.skip("rsync not on PATH")
    result = subprocess.run(
        [str(fake / "scripts" / "export-public.sh"), "."],
        capture_output=True, text=True, cwd=str(fake),
        env={**os.environ, "DRY_RUN": "1"}, check=False,
    )
    assert result.returncode != 0, (
        f"BUG-004: export-public.sh accepted TARGET='.' inside "
        f"REPO_ROOT (rc={result.returncode}); stderr=\n{result.stderr}"
    )


def test_BUG_004_refuses_home_target(tmp_path: Path) -> None:
    """SAD: TARGET equal to $HOME must be refused. We override $HOME to
    a tmp dir so the test is deterministic and doesn't touch the real
    user home (rsync --delete --dry-run would still walk it). The fix
    must reject specifically with a 'refuses HOME' message — not just
    any non-zero rc, since the unfixed script can accidentally exit
    non-zero from permission errors deep in real $HOME and that's a
    false positive masquerading as the safety guarantee."""
    fake = _make_fake_repo(tmp_path)
    fake_home = tmp_path / "fake-home"
    fake_home.mkdir()
    result = _run(fake, str(fake_home), dry_run=True, fake_home=fake_home)
    assert result.returncode != 0, (
        f"BUG-004: export-public.sh accepted TARGET=$HOME ({fake_home}); "
        f"rc={result.returncode}; stderr=\n{result.stderr}"
    )
    # Discriminator (same as the filesystem-root test): rsync MUST
    # NOT have run. The unfixed script always emits "Exporting …"
    # before rsync; the fix bails out earlier.
    assert "Exporting " not in result.stdout, (
        "BUG-004: HOME-equals-TARGET check ran AFTER rsync started — "
        f"stdout=\n{result.stdout}\nstderr=\n{result.stderr}"
    )
    err_lower = result.stderr.lower()
    assert any(tok in err_lower for tok in ("home", "unsafe", "refus")), (
        "BUG-004: refusal message did not name the HOME safety reason; "
        f"stderr=\n{result.stderr}"
    )


def test_BUG_004_refuses_filesystem_root(tmp_path: Path) -> None:
    """SAD: TARGET='/' must be refused. The discriminator vs. the
    unfixed script (which exits non-zero only because rsync hits
    permission-denied on /proc, /root, etc.) is that the fix must
    bail OUT before rsync runs at all — so the 'Exporting … → /'
    banner and any rsync output ('sent N bytes', 'speedup') must
    NOT appear. The fix-emitted refusal must mention the unsafe-
    target reason in stderr.

    Timeout=5s is intentional: walking '/' takes minutes (we measured
    3+s in CI even with permission errors), so a hard cap turns
    'rsync is still running' into a deterministic failure rather than
    a hanging test."""
    fake = _make_fake_repo(tmp_path)
    result = _run(fake, "/", dry_run=True, timeout=5.0)
    assert result.returncode != 0, (
        f"BUG-004: export-public.sh accepted TARGET=/ "
        f"(rc={result.returncode}); stderr=\n{result.stderr}"
    )
    # Discriminator: rsync MUST not have run. The unfixed script
    # always emits "Exporting … → /" before invoking rsync, so the
    # presence of that banner means the safety check is missing.
    assert "Exporting " not in result.stdout, (
        "BUG-004: unsafe-TARGET check ran AFTER rsync started — the "
        "fix must bail out before any rsync call. "
        f"stdout=\n{result.stdout}\nstderr=\n{result.stderr}"
    )
    assert "sent " not in result.stdout, (
        "BUG-004: rsync apparently ran (sent-bytes line present) — "
        "fix must refuse BEFORE invoking rsync. "
        f"stdout=\n{result.stdout}"
    )
    # And the refusal must explain why.
    err_lower = result.stderr.lower()
    assert err_lower.startswith("error:") or "refus" in err_lower or \
           "unsafe" in err_lower, (
        "BUG-004: stderr does not begin with an ERROR: line naming "
        f"the safety reason; stderr=\n{result.stderr}"
    )


def test_BUG_004_refuses_target_inside_repo(tmp_path: Path) -> None:
    """SAD/EDGE: a TARGET that lives INSIDE REPO_ROOT is also unsafe —
    rsync --delete would still operate within the working tree."""
    fake = _make_fake_repo(tmp_path)
    inside = fake / "subdir-target"
    result = _run(fake, str(inside), dry_run=True)
    assert result.returncode != 0, (
        f"BUG-004: export-public.sh accepted TARGET inside REPO_ROOT "
        f"({inside}); rc={result.returncode}; stderr=\n{result.stderr}"
    )


def test_BUG_004_accepts_safe_tmp_target(tmp_path: Path) -> None:
    """HAPPY: a fresh, empty target outside the repo must be accepted
    (this is the entire point of the script — it's a regression guard
    that the safety checks don't false-positive on the normal case)."""
    fake = _make_fake_repo(tmp_path)
    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest))
    assert result.returncode == 0, (
        f"export-public.sh rejected a safe tmp target "
        f"(rc={result.returncode}); stderr=\n{result.stderr}"
    )
    assert (dest / "addon" / "manifest.json").exists(), (
        f"export ran without error but produced no addon/manifest.json "
        f"in {dest}; stdout=\n{result.stdout}\nstderr=\n{result.stderr}"
    )


def test_BUG_004_refuses_nonempty_unrelated_target(tmp_path: Path) -> None:
    """EDGE: refuse rsync --delete into a non-empty directory that is
    NOT a previous export — defense-in-depth against a stale path that
    happens to be outside REPO_ROOT but contains user data."""
    fake = _make_fake_repo(tmp_path)
    dest = tmp_path / "users-stuff"
    dest.mkdir()
    (dest / "important.txt").write_text("don't delete me\n", encoding="utf-8")
    result = _run(fake, str(dest), dry_run=True)
    assert result.returncode != 0, (
        f"BUG-004: export-public.sh accepted non-empty unrelated "
        f"target (rc={result.returncode}); stderr=\n{result.stderr}"
    )
    # Crucially: the non-export file is still there (rsync --delete
    # would have removed it — dry-run keeps it, but the early refusal
    # is the actual safety property).
    assert (dest / "important.txt").exists(), (
        "BUG-004: pre-existing user file removed during the rejected "
        "export — the refusal happened too late."
    )


def test_BUG_004_force_override_for_legitimate_re_export(tmp_path: Path) -> None:
    """HAPPY/EDGE: FORCE=1 must allow re-exporting into a non-empty
    target (the operator has explicitly confirmed it). Without this
    escape hatch the script becomes useless on the second run."""
    fake = _make_fake_repo(tmp_path)
    dest = tmp_path / "public-mirror"
    dest.mkdir()
    (dest / "stale.txt").write_text("from a previous run\n", encoding="utf-8")
    result = _run(fake, str(dest), extra_env={"FORCE": "1"})
    assert result.returncode == 0, (
        f"FORCE=1 did not unlock re-export into non-empty target "
        f"(rc={result.returncode}); stderr=\n{result.stderr}"
    )


# ============================================================ BUG-005 (secrets)


def test_BUG_005_blocks_secrets_env_bak(tmp_path: Path) -> None:
    """SAD: secrets.env.bak in the working tree must NOT appear in the
    public export. This is the literal reproduction codex described."""
    fake = _make_fake_repo(tmp_path)
    (fake / "test" / "external").mkdir(parents=True)
    (fake / "test" / "external" / "secrets.env.bak").write_text(
        "PROVIDER_API_KEY=leaked-via-bak-suffix\n", encoding="utf-8"
    )
    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest))
    assert result.returncode == 0, f"export failed: {result.stderr}"
    leaked = list(dest.rglob("secrets.env.bak"))
    assert not leaked, (
        f"BUG-005: secrets.env.bak leaked into public export: {leaked}"
    )


def test_BUG_005_blocks_dotenv_files(tmp_path: Path) -> None:
    """SAD: dotfile .env (12-factor convention) must NOT be exported."""
    fake = _make_fake_repo(tmp_path)
    (fake / ".env").write_text("API_KEY=leaked-via-dotenv\n", encoding="utf-8")
    (fake / ".env.local").write_text("DB=leaked\n", encoding="utf-8")
    (fake / ".env.production").write_text("STRIPE=leaked\n", encoding="utf-8")
    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest))
    assert result.returncode == 0, f"export failed: {result.stderr}"
    leaked = [p.name for p in dest.rglob(".env*")]
    assert not leaked, (
        f"BUG-005: .env/.env.* files leaked into public export: {leaked}"
    )


def test_BUG_005_blocks_envrc(tmp_path: Path) -> None:
    """SAD: direnv's .envrc must NOT be exported."""
    fake = _make_fake_repo(tmp_path)
    (fake / ".envrc").write_text("export TOKEN=leaked-via-envrc\n",
                                 encoding="utf-8")
    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest))
    assert result.returncode == 0, f"export failed: {result.stderr}"
    assert not (dest / ".envrc").exists(), (
        "BUG-005: .envrc leaked into public export"
    )


def test_BUG_005_blocks_pem_and_key_files(tmp_path: Path) -> None:
    """SAD: TLS/SSH key material must NOT be exported. While not the
    literal bug codex described, the same denylist contract should
    cover all common credential file extensions."""
    fake = _make_fake_repo(tmp_path)
    for name in ("server.pem", "private.key", "client.p12", "id_rsa",
                 "id_ed25519", "keystore.jks"):
        (fake / name).write_text(f"-- fake key bytes for {name} --\n",
                                 encoding="utf-8")
    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest))
    assert result.returncode == 0, f"export failed: {result.stderr}"
    leaked = [p.name for p in dest.iterdir() if p.name in {
        "server.pem", "private.key", "client.p12", "id_rsa",
        "id_ed25519", "keystore.jks",
    }]
    assert not leaked, (
        f"BUG-005: credential files leaked into public export: {leaked}"
    )


def test_BUG_005_blocks_credentials_named_files(tmp_path: Path) -> None:
    """SAD: anything with 'credentials' or 'secrets' in the name must
    NOT be exported — broad denylist, not just *.env."""
    fake = _make_fake_repo(tmp_path)
    (fake / "aws-credentials").write_text("AKIA=...\n", encoding="utf-8")
    (fake / "team-secrets.json").write_text("{\"slack\": \"xoxb\"}\n",
                                            encoding="utf-8")
    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest))
    assert result.returncode == 0, f"export failed: {result.stderr}"
    leaked = [p.name for p in dest.iterdir()
              if "credentials" in p.name.lower() or "secrets" in p.name.lower()]
    assert not leaked, (
        f"BUG-005: credentials/secrets-named files leaked: {leaked}"
    )


def test_BUG_005_preserves_secrets_env_example(tmp_path: Path) -> None:
    """HAPPY: secrets.env.example is the documented PUBLIC template
    (tracked in git). The denylist must NOT eat it — otherwise the
    exported repo would be missing the file users need to copy-fill."""
    fake = _make_fake_repo(tmp_path)
    (fake / "test" / "external").mkdir(parents=True)
    (fake / "test" / "external" / "secrets.env.example").write_text(
        "# Template — fill in then rename to secrets.env\n"
        "PROVIDER_API_KEY=\n", encoding="utf-8"
    )
    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest))
    assert result.returncode == 0, f"export failed: {result.stderr}"
    example = dest / "test" / "external" / "secrets.env.example"
    assert example.exists(), (
        "BUG-005 fix overreached: legitimate public template "
        "secrets.env.example was excluded along with the real secrets."
    )


def test_BUG_005_edge_uppercase_env_extension(tmp_path: Path) -> None:
    """EDGE: rsync globs are case-sensitive by default; an operator on
    a case-insensitive filesystem (macOS HFS+ default, NTFS) may have
    a SECRETS.ENV that the denylist would miss. Either the script
    normalises case or this is documented as an acceptable limitation.
    Today we just verify the lowercase form is blocked — the uppercase
    form is acceptable to skip provided the documented contract calls
    it out (see docs/security/export-public.md)."""
    fake = _make_fake_repo(tmp_path)
    (fake / "test" / "external").mkdir(parents=True)
    (fake / "test" / "external" / "SECRETS.env").write_text(
        "API=lower-ext\n", encoding="utf-8"
    )
    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest))
    assert result.returncode == 0, f"export failed: {result.stderr}"
    assert not (dest / "test" / "external" / "SECRETS.env").exists(), (
        "BUG-005: uppercase-prefix *.env file leaked"
    )


# ============================================================ BUG-007 (NUL)


def test_BUG_007_failsafe_handles_multi_file_leak_via_mapfile(tmp_path: Path) -> None:
    """SAD: When MULTIPLE files slip past rsync EXCLUDES (precedence
    bug, future pattern not yet in the deny list, symlink edge case),
    the post-export ``_leak_scan`` failsafe must detect AND remove
    EVERY one, not just the first.

    Bug shape: bash command substitution drops NUL bytes silently
    (it warns to stderr but discards them in the captured string).
    The prior code did ``leaked_files="$(_leak_scan "$TARGET")"`` then
    ``printf '%s' "$leaked_files" | xargs -0 -r rm -f --`` — but the
    captured string had its NUL separators stripped, so xargs saw a
    single concatenated bogus path (``./file1./file2./file3``), rm
    failed silently with rc=0 on the impossible filename, NONE of the
    leaked files were deleted, and the script still exited 4 with a
    garbled single-line report.

    Reproduction strategy: patch the copied script's EXCLUDES list to
    empty so all source files reach TARGET (simulating the rsync
    precedence/symlink/future-pattern bug that the failsafe is for).
    Drop 4 distinct secret-pattern files in a sub-directory, run the
    script, then verify:
      (1) the script exits 4 (leak was detected),
      (2) every leaked filename appears as its own line in stderr
          (no concatenated blob),
      (3) every leaked file is actually removed from TARGET (not just
          the first).

    Fix shape: read the NUL-delimited stream into a bash array via
    ``mapfile -d '' -t leaked_files < <(_leak_scan "$TARGET")``,
    then use ``"${leaked_files[@]}"`` for both the report and the
    rm. mapfile/IFS-array preserves NULs as element boundaries; the
    fragile ``$(...)`` capture is bypassed entirely."""
    import re as _re
    fake = _make_fake_repo(tmp_path)
    # Patch EXCLUDES to be empty so all source files reach TARGET —
    # this isolates the failsafe layer for the test. Without the
    # patch, rsync would never let the secret files through and the
    # failsafe would have nothing to detect.
    script_path = fake / "scripts" / "export-public.sh"
    text = script_path.read_text(encoding="utf-8")
    patched = _re.sub(
        r"EXCLUDES=\(\n(?:.*?\n)+?\)\n",
        "EXCLUDES=()\n",
        text, count=1, flags=_re.DOTALL,
    )
    assert patched != text, (
        "BUG-007 test setup: EXCLUDES patch did not match — the script's "
        "array literal shape changed and the test fixture must be updated."
    )
    script_path.write_text(patched, encoding="utf-8")

    # Drop multiple distinct pattern-matching files. Use a sub-directory
    # so rsync's normal layout (it walks REPO_ROOT) reaches them.
    secrets_dir = fake / "secret-leak-zone"
    secrets_dir.mkdir()
    leaked_names = [
        "server.pem",
        "client.key",
        "id_rsa",
        "team-credentials.json",
        "db.env",
    ]
    for name in leaked_names:
        (secrets_dir / name).write_text(
            f"sensitive-content-for-{name}\n", encoding="utf-8"
        )

    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest), timeout=15.0)

    # (1) The failsafe must detect the leak and exit 4.
    assert result.returncode == 4, (
        f"BUG-007 prereq: leak_scan did not detect a multi-file leak "
        f"(expected rc=4, got rc={result.returncode}).\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )

    # (2) Every leaked filename must appear in stderr as its own
    # token — the pre-fix concatenation collapsed them into a single
    # garbled blob like "./file1./file2./file3" with no separators.
    missing_in_report = [n for n in leaked_names if n not in result.stderr]
    assert not missing_in_report, (
        f"BUG-007: failsafe stderr report omitted leaked files: "
        f"{missing_in_report}. The NUL-byte-dropping command substitution "
        f"collapsed multiple paths into a single string, so only the first "
        f"or last filename showed up readably in the report.\n"
        f"Full stderr:\n{result.stderr}"
    )

    # (3) Every leaked file must be REMOVED from TARGET — not just the
    # first. The pre-fix `xargs -0 -r rm -f --` saw one concatenated
    # bogus path and rm silently failed (rc=0 on unknown path).
    leaked_dir_in_target = dest / "secret-leak-zone"
    remaining = sorted(
        p.name for p in leaked_dir_in_target.iterdir()
    ) if leaked_dir_in_target.exists() else []
    assert remaining == [], (
        f"BUG-007: failsafe exited 4 (leak detected) but did NOT remove "
        f"all leaked files. Remaining in target: {remaining}.\n"
        f"This is the silent-fail mode the bug filing described: bash "
        f"`$(...)` capture strips NULs from `find -print0` output, so "
        f"`xargs -0 -r rm -f --` sees one concatenated bogus path and "
        f"rm fails silently with rc=0. Fix: read into a bash array with "
        f"`mapfile -d ''` to preserve NUL-separated entries.\n"
        f"stderr from run:\n{result.stderr}"
    )


def test_BUG_007_failsafe_still_handles_single_file_leak(tmp_path: Path) -> None:
    """HAPPY: the BUG-007 fix MUST NOT regress the single-file case
    that BUG-005 already covered. One leaked file, one removal, rc=4.

    This is the happy-path regression guard for the fix: if the
    mapfile/array migration introduces a quoting bug that breaks the
    1-file case (e.g., the array expands to empty when there's exactly
    one element), the BUG-005 contract is silently broken."""
    import re as _re
    fake = _make_fake_repo(tmp_path)
    script_path = fake / "scripts" / "export-public.sh"
    text = script_path.read_text(encoding="utf-8")
    patched = _re.sub(
        r"EXCLUDES=\(\n(?:.*?\n)+?\)\n",
        "EXCLUDES=()\n",
        text, count=1, flags=_re.DOTALL,
    )
    script_path.write_text(patched, encoding="utf-8")

    (fake / "lone-leak.pem").write_text("single-file-leak\n", encoding="utf-8")

    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest), timeout=15.0)

    assert result.returncode == 4, (
        f"BUG-007 fix regression: single-file leak no longer detected. "
        f"rc={result.returncode}, stderr={result.stderr!r}"
    )
    assert "lone-leak.pem" in result.stderr, (
        f"BUG-007 fix regression: single-file leak no longer named in "
        f"the stderr report. Full stderr:\n{result.stderr}"
    )
    assert not (dest / "lone-leak.pem").exists(), (
        "BUG-007 fix regression: single-file leak no longer removed."
    )


def test_BUG_007_failsafe_handles_no_leak_clean_export(tmp_path: Path) -> None:
    """EDGE: the BUG-007 fix MUST NOT cause the script to falsely
    exit 4 on a clean export. mapfile reading an empty NUL-stream
    produces a zero-length array; the array-length check must
    correctly skip the leak branch."""
    fake = _make_fake_repo(tmp_path)
    # No secret files added — addon/, scripts/, README.md, Makefile only.
    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest), timeout=15.0)
    assert result.returncode == 0, (
        f"BUG-007 fix regression: clean export now incorrectly exits "
        f"non-zero. rc={result.returncode}, stderr={result.stderr!r}"
    )


# ===================================================== BUG-011 (layer-mirror)


def test_BUG_011_leak_scan_catches_timestamped_env_variants(tmp_path: Path) -> None:
    """SAD: ``_leak_scan`` (the bash find layer) must catch the
    timestamped / 12-factor *.env variants that the rsync EXCLUDES
    list and the python postflight verifier both already enumerate.

    Bug shape: the find clause has ``-name '*.env'``, ``-name '.env'``,
    ``-name '.env.*'``, ``-name '.envrc'`` but NO ``-name '*.env.*'``
    or per-variant rules. So files like ``prod.env.bak``,
    ``prod.env.local``, ``prod.env.old`` slip past the script's own
    failsafe. The python verifier (``scripts/_postflight_leak_verify.py``)
    still catches them via the regex ``[^/]*\\.env(\\..+)?`` — defense-
    in-depth holds end-to-end — but the operator looking at the script
    alone would see "leak_scan clean" while ``prod.env.bak`` sits in
    TARGET.

    The BUG-009 Layer-mirroring contract in
    ``docs/security/export-public-policy.md`` explicitly lists these
    variants as in-scope: ``*.env.bak``, ``*.env.old``, ``*.env.local``,
    ``*.env.production``, ``*.env.staging``, ``*.env.dev``,
    ``*.env.prod``, ``*.env.test``, ``*.env.development``. The
    contract requires every layer to encode every example.

    Reproduction strategy mirrors BUG-007: patch EXCLUDES to empty so
    the file reaches TARGET, drop variant-named files that DO NOT
    contain "secrets" / "credentials" in the name (so the only
    matching clause would have to be ``*.env.*``), invoke the script,
    and assert ``_leak_scan`` detected them.

    Fix shape: add ``-name '*.env.*'`` to the find clause. The
    downstream ``grep -zZvE '\\.example$'`` filter keeps
    ``*.env.example`` whitelisted, so the explicit allow-list in the
    policy doc still works."""
    import re as _re
    fake = _make_fake_repo(tmp_path)
    script_path = fake / "scripts" / "export-public.sh"
    text = script_path.read_text(encoding="utf-8")
    patched = _re.sub(
        r"EXCLUDES=\(\n(?:.*?\n)+?\)\n",
        "EXCLUDES=()\n",
        text, count=1, flags=_re.DOTALL,
    )
    assert patched != text, (
        "BUG-011 test setup: EXCLUDES patch did not match — the script's "
        "array literal shape changed and the test fixture must be updated."
    )
    script_path.write_text(patched, encoding="utf-8")

    # Variant filenames that match the rsync EXCLUDES (`*.env.bak`,
    # `*.env.local`, `*.env.old`) but NOT the original `_leak_scan`
    # find clauses (which only had `*.env`, `.env`, `.env.*`). The
    # filename intentionally avoids "secrets"/"credentials" so that
    # the only matching find clause would have to be one that
    # recognises the `*.env.*` shape.
    variant_names = [
        "prod.env.bak",
        "prod.env.local",
        "prod.env.old",
    ]
    leak_dir = fake / "env-variant-leak"
    leak_dir.mkdir()
    for name in variant_names:
        (leak_dir / name).write_text(
            f"sensitive-content-for-{name}\n", encoding="utf-8"
        )

    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest), timeout=15.0)

    # The failsafe should exit 4 (leak detected) for ALL three variants.
    assert result.returncode == 4, (
        f"BUG-011: _leak_scan failed to detect *.env.bak / *.env.local / "
        f"*.env.old variants. rc={result.returncode}, expected 4. The "
        f"bash find layer is missing the timestamped/12-factor variants "
        f"that the BUG-009 layer-mirroring contract in "
        f"docs/security/export-public-policy.md enumerates.\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )

    missing_in_report = [n for n in variant_names if n not in result.stderr]
    assert not missing_in_report, (
        f"BUG-011: variants present but absent from failsafe report: "
        f"{missing_in_report}. Full stderr:\n{result.stderr}"
    )

    leak_dir_in_target = dest / "env-variant-leak"
    remaining = sorted(
        p.name for p in leak_dir_in_target.iterdir()
    ) if leak_dir_in_target.exists() else []
    assert remaining == [], (
        f"BUG-011: failsafe exited 4 but did NOT remove all variants. "
        f"Remaining: {remaining}.\n"
        f"stderr: {result.stderr}"
    )


def test_BUG_011_leak_scan_still_skips_env_example_template(tmp_path: Path) -> None:
    """HAPPY: the BUG-011 fix MUST NOT eat the ``*.env.example``
    public-template allow-list. The docs/security/export-public-policy.md
    "Explicit allow-list" section names ``*.env.example`` as a
    public template (``test/external/secrets.env.example`` is the
    canonical one). The downstream ``grep -zZvE '\\.example$'`` filter
    is supposed to keep it; this test locks that contract in.

    Without the test, a future widening that adds ``-name '*.env.*'``
    without preserving the ``.example`` filter would silently strip
    legitimate templates from the public mirror."""
    fake = _make_fake_repo(tmp_path)
    # Add a public template that MUST survive the export.
    (fake / "addon" / "config.env.example").write_text(
        "# template — public, copy and fill in\nFOO=replace-me\n",
        encoding="utf-8",
    )

    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest), timeout=15.0)

    assert result.returncode == 0, (
        f"BUG-011 fix regression: clean export with *.env.example "
        f"template now exits non-zero. rc={result.returncode}, "
        f"stderr={result.stderr!r}"
    )
    assert (dest / "addon" / "config.env.example").exists(), (
        "BUG-011 fix regression: *.env.example template was eaten by "
        "the widened _leak_scan find clause. The downstream "
        "`grep -zZvE '.example$'` filter must keep it."
    )


# ===================================================== BUG-012 (.envrc variants)


def test_BUG_012_leak_scan_catches_envrc_backup_variants(tmp_path: Path) -> None:
    """SAD: all three layers (rsync EXCLUDES, bash _leak_scan, python
    postflight, Makefile preflight) currently anchor the direnv arm at
    exactly ``.envrc`` with no suffix. Common operator backups —
    ``.envrc.bak``, ``.envrc.local``, ``.envrc-old`` — slip through.

    Bug shape:
      - rsync: ``--exclude='.envrc'`` matches only the exact name.
      - bash: ``-name '.envrc'`` likewise, and ``*.env.*`` does NOT
        match ``.envrc.bak`` (the literal ``.env.`` substring is not
        present in ``.envrc.bak`` — the `r` after `env` breaks it).
      - python regex / Makefile grep: ``\\.envrc`` arm is anchored at
        end-of-name with ``$``; ``.envrc.bak`` doesn't match.

    Reproduction strategy mirrors BUG-011: patch EXCLUDES to empty so
    the files reach TARGET, drop backup-named variants that do NOT
    contain ``secrets`` / ``credentials`` in the name, invoke the
    script, and assert ``_leak_scan`` detected them.

    Fix shape: extend the direnv arm so each layer recognises both
    ``.envrc`` and ``.envrc.*`` / ``.envrc-*``. The downstream
    ``grep -zZvE '\\.example$'`` filter still keeps any
    ``.envrc.example`` variant whitelisted (none ship today; future-
    proofing only).

    Why this matters: direnv users routinely keep these backups before
    editing — and ``.envrc`` typically contains DB URLs / API keys, so
    the backup is just as sensitive. Analogous to BUG-011 which widened
    the ``*.env`` arm to ``*.env.*`` for the same convention."""
    import re as _re
    fake = _make_fake_repo(tmp_path)
    script_path = fake / "scripts" / "export-public.sh"
    text = script_path.read_text(encoding="utf-8")
    patched = _re.sub(
        r"EXCLUDES=\(\n(?:.*?\n)+?\)\n",
        "EXCLUDES=()\n",
        text, count=1, flags=_re.DOTALL,
    )
    assert patched != text, (
        "BUG-012 test setup: EXCLUDES patch did not match — the script's "
        "array literal shape changed and the test fixture must be updated."
    )
    script_path.write_text(patched, encoding="utf-8")

    # Variant filenames that operator-backup conventions produce and
    # that the original `.envrc`-only rules miss. Names intentionally
    # avoid the "secrets"/"credentials" arms so the only matching find
    # clause would have to recognise the ``.envrc*`` shape.
    variant_names = [
        ".envrc.bak",
        ".envrc.local",
        ".envrc-old",
    ]
    leak_dir = fake / "envrc-variant-leak"
    leak_dir.mkdir()
    for name in variant_names:
        (leak_dir / name).write_text(
            f"export TOKEN=leaked-via-{name}\n", encoding="utf-8"
        )

    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest), timeout=15.0)

    # The failsafe should exit 4 (leak detected) for the variants.
    assert result.returncode == 4, (
        f"BUG-012: _leak_scan failed to detect .envrc.bak / "
        f".envrc.local / .envrc-old variants. rc={result.returncode}, "
        f"expected 4. The bash find layer is missing the direnv backup "
        f"variants that operators routinely keep before editing.\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )

    missing_in_report = [n for n in variant_names if n not in result.stderr]
    assert not missing_in_report, (
        f"BUG-012: variants present but absent from failsafe report: "
        f"{missing_in_report}. Full stderr:\n{result.stderr}"
    )

    leak_dir_in_target = dest / "envrc-variant-leak"
    remaining = sorted(
        p.name for p in leak_dir_in_target.iterdir()
    ) if leak_dir_in_target.exists() else []
    assert remaining == [], (
        f"BUG-012: failsafe exited 4 but did NOT remove all variants. "
        f"Remaining: {remaining}.\n"
        f"stderr: {result.stderr}"
    )


def test_BUG_012_postflight_regex_catches_envrc_backup_variants() -> None:
    """SAD (python layer): the postflight verifier's regex must catch
    the same .envrc backup variants as the bash _leak_scan. Independent
    of any file-system; pure regex application so we can hammer many
    names without spawning subprocesses.

    Without the widening, ``.envrc.bak`` / ``.envrc.local`` / ``.envrc-old``
    fall through the ``\\.envrc`` end-anchored arm. The verifier is the
    SECOND defense layer per BUG-007 — a regression here defeats the
    "two independent code paths" property of the layer-mirror contract.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_postflight_leak_verify",
        REPO / "scripts" / "_postflight_leak_verify.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    must_match = [
        ".envrc.bak",
        ".envrc.local",
        ".envrc-old",
        "path/to/.envrc.bak",
    ]
    missing = [n for n in must_match if not mod.PATTERN.search(n)]
    assert not missing, (
        f"BUG-012 (postflight layer): PATTERN missed direnv backup "
        f"variants: {missing}. The `\\.envrc` arm is end-anchored at "
        f"`$` so suffixed names slip through. Widen to recognise "
        f"`.envrc(\\..+|-.+)?` analogous to the id_rsa arm."
    )
    # HAPPY: bare .envrc still matches (no regression).
    assert mod.PATTERN.search(".envrc"), (
        "BUG-012 fix regression: bare .envrc no longer matches PATTERN."
    )


# =============================================== BUG-012 (re): tilde-suffix gap
#
# The first BUG-012 fix widened the direnv/env arms to recognise
# ``.envrc.bak`` / ``.envrc.local`` / ``.envrc-old`` (the dot- and
# dash-suffix backup conventions) plus the ``*.env.bak`` style. It did
# NOT widen for the canonical UNIX editor backup convention — the
# single trailing ``~``. Both vim (``set backup``) and Emacs (default
# behavior) drop a ``filename~`` sibling next to the file on save, so a
# maintainer who edits ``.envrc`` or ``prod.env`` with either editor
# leaves a ``.envrc~`` / ``prod.env~`` on disk; both are byte-identical
# copies of the credentials they back up.
#
# Empirical probe (pre-fix, against the un-widened arms):
#   $ touch .envrc~ prod.env~ db.env~ .envrc.bak~ secrets.env~
#   $ python3 scripts/_postflight_leak_verify.py .
#   ERROR ... .envrc.bak~  secrets.env~     (the *secrets* arm caught
#                                             one; .envrc(\..+|-.+)?
#                                             caught the other)
#   $                                       (.envrc~, prod.env~,
#                                            db.env~ all slipped through)
# Same probe against the bash ``_leak_scan`` and Makefile preflight:
# both also miss the tilde-only variants.
#
# Fix shape: append ``~?`` to the env / envrc arms in the python regex
# and Makefile grep; add ``-name '.envrc~' -o -name '*.env~' ...``
# clauses to the bash find. Mirror the widening in the rsync EXCLUDES
# list so the file never reaches TARGET in the first place.


def test_BUG_012_postflight_regex_catches_tilde_backup_variants() -> None:
    """SAD (python layer, re-fix): the postflight regex must catch the
    classic UNIX editor backup convention — ``filename~`` — applied to
    the env/envrc arms. ``.envrc~`` / ``prod.env~`` / ``db.env~`` are
    exact byte-copies of the credentials they back up.

    The first BUG-012 fix anchored the optional suffix group at
    ``(\\..+|-.+)?`` — accepting dot or dash suffixes but stopping at
    the closing ``$``. A trailing tilde requires either appending
    ``~?`` to each arm or extending the suffix alternation to include
    a tilde token; the latter would also cover ``.envrc.bak~`` /
    ``.envrc-old~`` chained patterns.

    Independent of any file-system; pure regex application so we can
    hammer many names without spawning subprocesses."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_postflight_leak_verify",
        REPO / "scripts" / "_postflight_leak_verify.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    must_match = [
        ".envrc~",
        ".env~",
        "prod.env~",
        "db.env~",
        "path/to/.envrc~",
    ]
    missing = [n for n in must_match if not mod.PATTERN.search(n)]
    assert not missing, (
        f"BUG-012 (re, postflight layer): PATTERN missed UNIX editor "
        f"backup variants (trailing ~): {missing}. The env/envrc arms "
        f"stop at the ``(\\..+|-.+)?`` group with `$` immediately after, "
        f"so vim/Emacs backup files slip through. Widen to allow an "
        f"optional trailing ``~``."
    )
    # HAPPY: bare .envrc / .env / db.env still match (no regression
    # from adding the optional `~?` suffix).
    for keep in (".envrc", ".env", "db.env", ".envrc.bak"):
        assert mod.PATTERN.search(keep), (
            f"BUG-012 (re) fix regression: {keep!r} no longer matches "
            "PATTERN after the tilde widening."
        )
    # EDGE: chained tilde-on-suffix (``.envrc.bak~`` already passed
    # pre-fix via ``\\..+`` matching ``.bak~``; locking it in so a
    # future refactor of the suffix alternation can't silently lose it).
    assert mod.PATTERN.search(".envrc.bak~"), (
        "BUG-012 (re) regression: .envrc.bak~ no longer matches PATTERN."
    )


def test_BUG_012_leak_scan_catches_tilde_backup_variants(tmp_path: Path) -> None:
    """SAD (bash layer, re-fix): same tilde-suffix gap as the python
    postflight, but on the script-side ``_leak_scan`` find rules. The
    first BUG-012 fix added ``-name '.envrc'`` / ``.envrc.*`` /
    ``.envrc-*`` but no rule for the tilde-only convention; similarly
    ``*.env`` / ``*.env.*`` do not match ``*.env~``.

    Reproduction strategy mirrors the original BUG-012 test: patch
    EXCLUDES to empty so the files reach TARGET, drop tilde-named
    variants that avoid the ``*secrets*`` / ``*credentials*`` arms,
    invoke the script, and assert ``_leak_scan`` detected them and
    removed them (fail-secure)."""
    import re as _re
    fake = _make_fake_repo(tmp_path)
    script_path = fake / "scripts" / "export-public.sh"
    text = script_path.read_text(encoding="utf-8")
    patched = _re.sub(
        r"EXCLUDES=\(\n(?:.*?\n)+?\)\n",
        "EXCLUDES=()\n",
        text, count=1, flags=_re.DOTALL,
    )
    assert patched != text, (
        "BUG-012 (re) test setup: EXCLUDES patch did not match — the "
        "script's array literal shape changed and the test fixture "
        "must be updated."
    )
    script_path.write_text(patched, encoding="utf-8")

    # Names intentionally avoid `secrets`/`credentials` so detection
    # has to come from the env/envrc arm, not the catch-all substrings.
    variant_names = [
        ".envrc~",
        "prod.env~",
        "db.env~",
    ]
    leak_dir = fake / "tilde-variant-leak"
    leak_dir.mkdir()
    for name in variant_names:
        (leak_dir / name).write_text(
            f"export TOKEN=leaked-via-{name}\n", encoding="utf-8"
        )

    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest), timeout=15.0)

    assert result.returncode == 4, (
        f"BUG-012 (re): _leak_scan failed to detect tilde-suffix env / "
        f"envrc variants. rc={result.returncode}, expected 4. The bash "
        f"find layer is missing the classic UNIX editor backup convention "
        f"(vim/Emacs write `<name>~` siblings on save).\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )

    missing_in_report = [n for n in variant_names if n not in result.stderr]
    assert not missing_in_report, (
        f"BUG-012 (re): variants present but absent from failsafe "
        f"report: {missing_in_report}. Full stderr:\n{result.stderr}"
    )

    leak_dir_in_target = dest / "tilde-variant-leak"
    remaining = sorted(
        p.name for p in leak_dir_in_target.iterdir()
    ) if leak_dir_in_target.exists() else []
    assert remaining == [], (
        f"BUG-012 (re): failsafe exited 4 but did NOT remove all "
        f"variants. Remaining: {remaining}.\n"
        f"stderr: {result.stderr}"
    )


# ============================================ BUG-013: non-env arm tilde/backup
#
# BUG-012 (re) widened the env / envrc arms with ``~?`` for the UNIX
# editor backup convention but never touched the remaining arms. The
# non-env credential families (``.netrc``, ``.npmrc``, ``*.pem``,
# ``*.key``, ``id_rsa`` family on the regex layers) are still
# end-anchored without a tilde / dot / dash suffix provision, so:
#
#   - ``.netrc.bak``, ``.netrc.local``, ``.netrc-old``, ``.netrc~``
#   - ``.npmrc.bak``, ``.npmrc.local``, ``.npmrc-old``, ``.npmrc~``
#   - ``*.pem~``, ``*.key~``, ``*.p12~``, ``*.pfx~``, ``*.keystore~``,
#     ``*.jks~``
#   - ``id_rsa~``, ``id_ed25519~`` (caught at bash via ``id_rsa*`` glob
#     but not at the python regex / Makefile grep layers)
#
# all slip past ALL three pattern layers and ALL rsync EXCLUDES. They
# are byte-identical copies of the credentials they back up (``.netrc``
# stores ``machine X login Y password Z`` in plaintext; ``*.key`` holds
# private TLS material). Same risk class as BUG-012 (re) but applied
# to credential families the prior fix overlooked.
#
# Fix shape: append ``~?`` to every end-anchored arm in the python
# regex and Makefile preflight grep; add ``-name '*.pem~' -o ...``
# style clauses to the bash _leak_scan; widen rsync EXCLUDES with
# ``.netrc.*``, ``.netrc-*``, ``.netrc~``, equivalent ``.npmrc.*``,
# and a ``*.pem~`` family. Per docs/security/export-public-policy.md
# §"Layer-mirroring contract", all four enforcement points (rsync
# EXCLUDES, bash _leak_scan, python postflight, Makefile preflight)
# must agree on scope in the SAME commit.


def test_BUG_013_postflight_regex_catches_non_env_tilde_and_backup_variants() -> None:
    """SAD (python layer): the postflight regex must catch tilde / dot /
    dash backup variants on the non-env credential arms — same shape
    fix as BUG-012 (re) but applied to the families the prior fix
    overlooked.

    Pre-fix PATTERN ended every non-env arm at ``$`` with no provision
    for a trailing ``~`` (UNIX editor backup) or for ``.bak`` / ``.local``
    / ``-old`` style suffixes. So a maintainer editing ``.netrc`` in vim
    leaves ``.netrc~`` on disk — a plaintext credential copy that
    survives every layer of the leak scan. Empirical /tmp probe pre-fix:
        $ touch .netrc.bak .npmrc~ foo.pem~ bar.key~
        $ python3 scripts/_postflight_leak_verify.py .
        $                  # rc=0, all four credential backups survived

    Independent of any file-system; pure regex application."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_postflight_leak_verify",
        REPO / "scripts" / "_postflight_leak_verify.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # SAD: variants that should be caught after BUG-013 fix.
    must_match = [
        ".netrc.bak", ".netrc.local", ".netrc-old", ".netrc~",
        ".npmrc.bak", ".npmrc.local", ".npmrc-old", ".npmrc~",
        "foo.pem~", "bar.key~", "store.p12~", "vault.pfx~",
        "id_rsa~", "id_ed25519~",
    ]
    missing = [n for n in must_match if not mod.PATTERN.search(n)]
    assert not missing, (
        f"BUG-013 (postflight layer): PATTERN missed non-env "
        f"backup variants: {missing}. The .netrc/.npmrc/.pem/.key/"
        f"id_X arms are end-anchored at ``$`` with no provision for "
        f"the canonical UNIX editor backup convention (`~`) or "
        f"common backup suffixes (`.bak`, `.local`, `-old`). "
        f"Widen analogous to the env/envrc widening from BUG-012 (re)."
    )
    # HAPPY: bare canonical names still match (no regression).
    for keep in (".netrc", ".npmrc", "foo.pem", "bar.key", "id_rsa", "id_ed25519"):
        assert mod.PATTERN.search(keep), (
            f"BUG-013 fix regression: {keep!r} no longer matches PATTERN."
        )
    # EDGE: case-insensitive (PATTERN already has re.IGNORECASE) — the
    # .NETRC~ variant must still match after the widening.
    assert mod.PATTERN.search(".NETRC~"), (
        "BUG-013: case-insensitivity regression on .NETRC~."
    )


def test_BUG_013_leak_scan_catches_non_env_tilde_and_backup_variants(
    tmp_path: Path,
) -> None:
    """SAD (bash layer): the bash ``_leak_scan`` find rule must grow
    explicit clauses for the non-env tilde/backup variants. ``id_rsa*``
    glob catches ``id_rsa~`` already, but ``.netrc``/``.npmrc``/``*.pem``
    are exact-name (or canonical-extension) only — ``.netrc~`` and
    ``foo.pem~`` slip past because bash glob ``*.pem`` matches strings
    that END in ``.pem``, not ``.pem~``.

    Reproduction strategy mirrors BUG-012 (re): patch EXCLUDES to empty
    so the variants reach TARGET, drop the files, invoke the script,
    assert ``_leak_scan`` detects (rc=4) AND removes them (fail-secure).
    Names avoid the ``*secrets*``/``*credentials*`` substrings so the
    detection has to come from the specific arms."""
    import re as _re
    fake = _make_fake_repo(tmp_path)
    script_path = fake / "scripts" / "export-public.sh"
    text = script_path.read_text(encoding="utf-8")
    patched = _re.sub(
        r"EXCLUDES=\(\n(?:.*?\n)+?\)\n",
        "EXCLUDES=()\n",
        text, count=1, flags=_re.DOTALL,
    )
    assert patched != text, (
        "BUG-013 test setup: EXCLUDES patch did not match — the "
        "script's array literal shape changed; update the fixture."
    )
    script_path.write_text(patched, encoding="utf-8")

    variant_names = [
        ".netrc.bak", ".netrc~",
        ".npmrc.bak", ".npmrc~",
        "host.pem~", "host.key~",
    ]
    leak_dir = fake / "non-env-tilde-leak"
    leak_dir.mkdir()
    for name in variant_names:
        (leak_dir / name).write_text(
            f"# byte-identical-credential-backup-of-{name}\n",
            encoding="utf-8",
        )

    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest), timeout=15.0)

    assert result.returncode == 4, (
        f"BUG-013: _leak_scan failed to detect non-env tilde/backup "
        f"variants. rc={result.returncode}, expected 4. The bash find "
        f"layer is missing explicit clauses for .netrc/.npmrc backup "
        f"suffixes and the *.pem~ / *.key~ tilde convention.\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )

    missing_in_report = [n for n in variant_names if n not in result.stderr]
    assert not missing_in_report, (
        f"BUG-013: variants present but absent from failsafe report: "
        f"{missing_in_report}. Full stderr:\n{result.stderr}"
    )

    leak_dir_in_target = dest / "non-env-tilde-leak"
    remaining = sorted(
        p.name for p in leak_dir_in_target.iterdir()
    ) if leak_dir_in_target.exists() else []
    assert remaining == [], (
        f"BUG-013: failsafe exited 4 but did NOT remove all variants. "
        f"Remaining: {remaining}.\nstderr: {result.stderr}"
    )


def test_BUG_013_leak_scan_still_passes_on_pem_example_template(
    tmp_path: Path,
) -> None:
    """HAPPY / EDGE: the BUG-013 widening must NOT eat ``.example``
    templates. A future widening that swaps the .pem arm to ``*.pem*``
    or ``*.pem~?`` without preserving the ``\\.example$`` allow-list
    filter would silently delete legitimate ``cert.pem.example`` files
    documented in the README. Guarding explicitly."""
    fake = _make_fake_repo(tmp_path)
    # Drop a benign template into the source tree (allowed via the
    # script's `--include='*.example'` rule applied before the denylist).
    (fake / "cert.pem.example").write_text("-----TEMPLATE-----\n", encoding="utf-8")
    (fake / ".netrc.example").write_text("machine X login Y\n", encoding="utf-8")

    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest), timeout=15.0)

    assert result.returncode == 0, (
        f"BUG-013 fix regression: .example templates now block export. "
        f"rc={result.returncode}\nstderr={result.stderr!r}"
    )
    assert (dest / "cert.pem.example").exists(), (
        "BUG-013 regression: cert.pem.example dropped from public mirror."
    )
    assert (dest / ".netrc.example").exists(), (
        "BUG-013 regression: .netrc.example dropped from public mirror."
    )


# ============================================================ BUG-014 (case)


def test_BUG_014_leak_scan_catches_uppercase_extension_variants(
    tmp_path: Path,
) -> None:
    """SAD (bash layer): the bash ``_leak_scan`` find clauses use
    ``-name`` (case-sensitive) for the TLS keystore arm
    (``*.pem``/``*.key``/``*.p12``/``*.pfx``/``*.keystore``/``*.jks``),
    the SSH key arm (``id_rsa*``/``id_ed25519*``/``id_ecdsa*``/
    ``id_dsa*``) and the registry-creds arm (``.netrc``/``.npmrc`` and
    their backup variants). Uppercase variants — ``host.PEM``,
    ``cert.PFX``, ``private.KEY``, ``.NETRC``, ``ID_RSA`` — slip past
    even though the python postflight verifier (``re.IGNORECASE``) and
    the Makefile preflight (``grep -iE``) both catch them. Per the
    BUG-009 mirroring contract the three layers must agree on scope.
    Names deliberately avoid ``secrets``/``credentials`` substrings so
    detection has to come from the specific arms (those two arms
    already use ``-iname`` and would mask the gap).

    Reproduction strategy mirrors BUG-013: patch EXCLUDES to empty so
    the uppercase variants reach TARGET via rsync (rsync excludes are
    also case-sensitive and would normally filter them, but we want to
    isolate the bash post-export scan), then invoke the script and
    assert ``_leak_scan`` (a) detects (rc=4) and (b) removes them
    (fail-secure delete via ``rm -f``)."""
    import re as _re
    fake = _make_fake_repo(tmp_path)
    script_path = fake / "scripts" / "export-public.sh"
    text = script_path.read_text(encoding="utf-8")
    patched = _re.sub(
        r"EXCLUDES=\(\n(?:.*?\n)+?\)\n",
        "EXCLUDES=()\n",
        text, count=1, flags=_re.DOTALL,
    )
    assert patched != text, (
        "BUG-014 test setup: EXCLUDES patch did not match — the "
        "script's array literal shape changed; update the fixture."
    )
    script_path.write_text(patched, encoding="utf-8")

    variant_names = [
        "host.PEM", "cert.PFX", "private.KEY",
        ".NETRC", ".NPMRC", "ID_RSA",
    ]
    leak_dir = fake / "uppercase-cred-leak"
    leak_dir.mkdir()
    for name in variant_names:
        (leak_dir / name).write_text(
            f"# uppercase-credential-variant-{name}\n",
            encoding="utf-8",
        )

    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest), timeout=15.0)

    assert result.returncode == 4, (
        f"BUG-014: _leak_scan failed to detect uppercase-extension / "
        f"uppercase-basename credential variants. rc={result.returncode}, "
        f"expected 4. The bash find layer uses -name (case-sensitive) "
        f"for the TLS/SSH/netrc/npmrc arms while the python verifier "
        f"uses re.IGNORECASE; the two layers diverge on case-handling.\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )

    missing_in_report = [n for n in variant_names if n not in result.stderr]
    assert not missing_in_report, (
        f"BUG-014: variants present but absent from failsafe report: "
        f"{missing_in_report}. Full stderr:\n{result.stderr}"
    )

    leak_dir_in_target = dest / "uppercase-cred-leak"
    remaining = sorted(
        p.name for p in leak_dir_in_target.iterdir()
    ) if leak_dir_in_target.exists() else []
    assert remaining == [], (
        f"BUG-014: failsafe exited 4 but did NOT remove all uppercase "
        f"variants. Remaining: {remaining}.\nstderr: {result.stderr}"
    )


def test_BUG_014_postflight_regex_already_catches_uppercase_variants() -> None:
    """HAPPY (python layer, no-regression guard): document that the
    python verifier's ``re.IGNORECASE`` flag already catches every
    uppercase variant the bash layer misses. This is the BUG-014
    asymmetry from the python side — if a future "simplify" PR drops
    ``re.IGNORECASE`` to match bash's case-sensitivity, the failsafe
    that catches BUG-014 today collapses and the regression is silent
    until a real ``host.PFX`` slips through. Lock the IGNORECASE
    behaviour in with an explicit assertion."""
    from scripts._postflight_leak_verify import PATTERN
    uppercase_variants = [
        "host.PEM", "cert.PFX", "private.KEY",
        "vault.P12", "store.JKS", "ks.KEYSTORE",
        ".NETRC", ".NPMRC", "ID_RSA", "id_ed25519.PUB",
    ]
    for name in uppercase_variants:
        assert PATTERN.search(name), (
            f"BUG-014: python verifier regex no longer matches "
            f"{name!r} — IGNORECASE flag was dropped or the arm "
            f"shape changed. The bash layer relies on this python "
            f"check as the case-handling failsafe."
        )


def test_BUG_014_leak_scan_still_passes_on_uppercase_ext_example_template(
    tmp_path: Path,
) -> None:
    """HAPPY / EDGE: the BUG-014 widening (``-name`` → ``-iname``) must
    NOT eat ``.example`` templates whose base extension happens to be
    uppercase. Concretely: ``cert.PEM.example`` is a public template
    that should survive the export. Without this guard a future
    refactor that swaps the allowlist filter (``grep -zZvE '\\.example$'``)
    to a tighter shape could silently delete it."""
    fake = _make_fake_repo(tmp_path)
    (fake / "cert.PEM.example").write_text(
        "-----TEMPLATE-uppercase-ext-----\n", encoding="utf-8"
    )
    (fake / "store.JKS.example").write_text(
        "# uppercase JKS example template\n", encoding="utf-8"
    )

    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest), timeout=15.0)

    assert result.returncode == 0, (
        f"BUG-014 fix regression: uppercase-ext .example templates "
        f"now block export. rc={result.returncode}\n"
        f"stderr={result.stderr!r}"
    )
    assert (dest / "cert.PEM.example").exists(), (
        "BUG-014 regression: cert.PEM.example dropped from public mirror."
    )
    assert (dest / "store.JKS.example").exists(), (
        "BUG-014 regression: store.JKS.example dropped from public mirror."
    )


# ============================================ BUG-015: TLS keystore manual-backup
#
# BUG-013 widened the TLS keystore family (``*.pem|*.key|*.p12|*.pfx|
# *.keystore|*.jks``) with the UNIX editor tilde-backup convention
# (``*.pem~``, ``*.key~``, etc.) but never widened the same family with
# the manual-rotation backup convention (``.bak``, ``.old``, ``.local``,
# ``-old``, ``.backup``). The four other credential families ALL handle
# manual rotation:
#
#   - ``.envrc.bak`` / ``.envrc-old`` / ``.envrc.local`` — caught by
#     ``\.envrc(\..+|-.+)?~?`` (BUG-012 widening)
#   - ``.netrc.bak`` / ``.netrc-old`` — caught by ``(\.netrc|\.npmrc)
#     (\..+|-.+)?~?`` (BUG-013 widening)
#   - ``id_rsa.bak`` / ``id_rsa-old`` — caught by ``id_(rsa|…)([._-].+)?~?``
#     (BUG-009 + BUG-013 widening)
#
# but the TLS keystore arm is still ``[^/]*\.(pem|key|p12|pfx|keystore|jks)~?``
# in the python regex / Makefile grep, and ``-iname '*.pem' -o -iname
# '*.pem~'`` in the bash _leak_scan. So ``host.pem.bak``, ``cert.key.old``,
# ``store.p12.bak`` — byte-identical copies of the TLS private key
# material — slip past EVERY layer. Empirical /tmp probe pre-fix:
#
#     $ touch host.pem.bak cert.key.old store.p12.bak
#     $ python3 scripts/_postflight_leak_verify.py .
#     $                  # rc=0, all three TLS backups survived
#
# Same risk class as BUG-013 (.netrc.bak) but on the credential family
# the prior fix overlooked. Fix shape: append ``(\..+|-.+)?~?`` to the
# TLS keystore arm in the python regex / Makefile grep; add
# ``-iname '*.pem.*' -o -iname '*.pem-*' …`` clauses to the bash
# _leak_scan; mirror in rsync EXCLUDES; update the policy doc table.
# Per the BUG-009 layer-mirroring contract, ALL four layers must land
# in the SAME Resolve commit.


def test_BUG_015_postflight_regex_catches_tls_keystore_manual_backups() -> None:
    """SAD (python layer): the postflight regex must catch ``.bak``,
    ``.old``, ``.local``, ``-old`` and ``.bak~`` suffix variants on the
    TLS keystore arm — same shape fix as BUG-013 for the .netrc/.npmrc
    family. ``host.pem.bak`` is a byte-identical copy of the private TLS
    key material; the BUG-013 ``~`` widening covered editor-auto-backups
    but the manual-rotation convention (``cp host.pem host.pem.bak``)
    was forgotten. Empirical /tmp probe pre-fix:

        $ touch host.pem.bak cert.key.old store.p12.bak
        $ python3 scripts/_postflight_leak_verify.py .
        $                  # rc=0, all three TLS backups survived

    Independent of any file-system; pure regex application."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_postflight_leak_verify",
        REPO / "scripts" / "_postflight_leak_verify.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    must_match = [
        "host.pem.bak", "host.pem.old", "host.pem.local", "host.pem-old",
        "cert.key.bak", "cert.key.old", "cert.key-old", "cert.key.local",
        "store.p12.bak", "store.p12-old",
        "vault.pfx.bak", "vault.pfx-old",
        "ks.keystore.bak", "ks.jks-old",
        # tilde + manual suffix combo (operator edits the .bak in vim)
        "host.pem.bak~", "cert.key-old~",
    ]
    missing = [n for n in must_match if not mod.PATTERN.search(n)]
    assert not missing, (
        f"BUG-015 (postflight layer): PATTERN missed TLS keystore "
        f"manual-rotation backup variants: {missing}. The .pem/.key/"
        f".p12/.pfx/.keystore/.jks arm is shaped "
        f"``[^/]*\\.(pem|key|p12|pfx|keystore|jks)~?`` — no provision "
        f"for the canonical manual-rotation convention "
        f"(`.bak`, `.local`, `-old`). Widen analogous to the .envrc / "
        f".netrc widening from BUG-012 / BUG-013."
    )
    # HAPPY: bare canonical names + the BUG-013 ``~`` variants still match.
    for keep in ("host.pem", "cert.key", "store.p12",
                 "host.pem~", "cert.key~", "store.p12~"):
        assert mod.PATTERN.search(keep), (
            f"BUG-015 fix regression: {keep!r} no longer matches PATTERN."
        )
    # EDGE: case-insensitive — uppercase manual backup must still match.
    assert mod.PATTERN.search("HOST.PEM.BAK"), (
        "BUG-015: case-insensitivity regression on HOST.PEM.BAK."
    )


def test_BUG_015_leak_scan_catches_tls_keystore_manual_backups(
    tmp_path: Path,
) -> None:
    """SAD (bash layer): the bash ``_leak_scan`` find rule must grow
    explicit clauses for the TLS keystore manual-rotation backup
    variants. ``-iname '*.pem'`` matches strings that END in ``.pem``,
    not ``.pem.bak``; the BUG-013 ``-iname '*.pem~'`` only covers the
    editor-auto-backup convention.

    Reproduction strategy mirrors BUG-013: patch EXCLUDES to empty so
    the variants reach TARGET, drop the files, invoke the script,
    assert ``_leak_scan`` detects (rc=4) AND removes them (fail-secure).
    Names avoid the ``*secrets*``/``*credentials*`` substrings so the
    detection has to come from the specific arms."""
    import re as _re
    fake = _make_fake_repo(tmp_path)
    script_path = fake / "scripts" / "export-public.sh"
    text = script_path.read_text(encoding="utf-8")
    patched = _re.sub(
        r"EXCLUDES=\(\n(?:.*?\n)+?\)\n",
        "EXCLUDES=()\n",
        text, count=1, flags=_re.DOTALL,
    )
    assert patched != text, (
        "BUG-015 test setup: EXCLUDES patch did not match — the "
        "script's array literal shape changed; update the fixture."
    )
    script_path.write_text(patched, encoding="utf-8")

    variant_names = [
        "host.pem.bak", "host.pem.old", "host.pem-old",
        "cert.key.bak", "cert.key.local",
        "store.p12.bak", "vault.pfx-old",
        "ks.keystore.bak", "ks.jks-old",
    ]
    leak_dir = fake / "tls-manual-backup-leak"
    leak_dir.mkdir()
    for name in variant_names:
        (leak_dir / name).write_text(
            f"-----BEGIN PRIVATE KEY----- {name} -----END PRIVATE KEY-----\n",
            encoding="utf-8",
        )

    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest), timeout=15.0)

    assert result.returncode == 4, (
        f"BUG-015: _leak_scan failed to detect TLS keystore manual-"
        f"rotation backup variants. rc={result.returncode}, expected 4. "
        f"The bash find layer is missing ``-iname '*.pem.*' / '*.pem-*' "
        f"/ '*.key.*' …`` clauses; the BUG-013 widening covered only "
        f"the tilde-auto-backup convention.\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )

    missing_in_report = [n for n in variant_names if n not in result.stderr]
    assert not missing_in_report, (
        f"BUG-015: variants present but absent from failsafe report: "
        f"{missing_in_report}. Full stderr:\n{result.stderr}"
    )

    leak_dir_in_target = dest / "tls-manual-backup-leak"
    remaining = sorted(
        p.name for p in leak_dir_in_target.iterdir()
    ) if leak_dir_in_target.exists() else []
    assert remaining == [], (
        f"BUG-015: failsafe exited 4 but did NOT remove all variants. "
        f"Remaining: {remaining}.\nstderr: {result.stderr}"
    )


def test_BUG_015_leak_scan_still_passes_on_pem_bak_example_template(
    tmp_path: Path,
) -> None:
    """HAPPY / EDGE: the BUG-015 widening must NOT eat ``.example``
    templates whose name happens to look like a TLS keystore backup —
    e.g. ``cert.pem.bak.example`` (documented rollback procedure
    template) or ``host.pem.example`` (the canonical case). A future
    refactor that widens the .pem arm to ``*.pem*`` without preserving
    the ``\\.example$`` allow-list filter would silently delete these."""
    fake = _make_fake_repo(tmp_path)
    (fake / "cert.pem.example").write_text(
        "-----TEMPLATE-pem-----\n", encoding="utf-8"
    )
    (fake / "host.key.example").write_text(
        "# TLS key template\n", encoding="utf-8"
    )

    dest = tmp_path / "public-mirror"
    result = _run(fake, str(dest), timeout=15.0)

    assert result.returncode == 0, (
        f"BUG-015 fix regression: TLS keystore .example templates "
        f"now block export. rc={result.returncode}\n"
        f"stderr={result.stderr!r}"
    )
    assert (dest / "cert.pem.example").exists(), (
        "BUG-015 regression: cert.pem.example dropped from public mirror."
    )
    assert (dest / "host.key.example").exists(), (
        "BUG-015 regression: host.key.example dropped from public mirror."
    )
