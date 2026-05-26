"""Unit tests for scripts/_postflight_leak_verify.py.

The post-flight verifier is the BUG-007 build-system second layer:
after scripts/export-public.sh's own _leak_scan claims success, this
script re-walks TARGET in an independent process and exits 6 if any
secret-pattern file is still present. These tests lock in its
happy / edge / sad contract so a future change to the pattern list,
the .example allowlist, or the missing-TARGET fail-secure stays
honest.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VERIFIER = REPO / "scripts" / "_postflight_leak_verify.py"


def _run(target: Path | str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(target)],
        capture_output=True, text=True, check=False,
    )


def test_verifier_passes_clean_target(tmp_path: Path) -> None:
    """HAPPY: a clean directory with only innocuous files returns rc=0."""
    (tmp_path / "README.md").write_text("# clean", encoding="utf-8")
    (tmp_path / "addon").mkdir()
    (tmp_path / "addon" / "manifest.json").write_text("{}", encoding="utf-8")
    result = _run(tmp_path)
    assert result.returncode == 0, (
        f"clean target should pass; got rc={result.returncode}, "
        f"stderr={result.stderr!r}"
    )


def test_verifier_fails_on_missing_target(tmp_path: Path) -> None:
    """EDGE: a TARGET that does not exist returns rc=6 (fail-secure).

    Rationale: if the script claimed success but the directory is
    missing, something is badly wrong; the verifier must NOT silently
    pass on a non-existent dir (rc=0 on missing-dir would defeat the
    point of an independent verification)."""
    missing = tmp_path / "no-such-dir"
    result = _run(missing)
    assert result.returncode == 6, (
        f"missing target should fail-secure with rc=6; got "
        f"rc={result.returncode}, stderr={result.stderr!r}"
    )
    assert "does not exist" in result.stderr.lower(), (
        f"missing-target error should name the cause; stderr={result.stderr!r}"
    )


def test_verifier_detects_leaked_secrets_env(tmp_path: Path) -> None:
    """SAD: a *.env file under TARGET trips the verifier (rc=6)."""
    (tmp_path / "addon").mkdir()
    (tmp_path / "addon" / "secrets.env").write_text(
        "API_KEY=leaked\n", encoding="utf-8"
    )
    result = _run(tmp_path)
    assert result.returncode == 6, (
        f"leaked *.env file should fail rc=6; got rc={result.returncode}, "
        f"stderr={result.stderr!r}"
    )
    assert "secrets.env" in result.stderr, (
        f"verifier should name the leaked file; stderr={result.stderr!r}"
    )


def test_verifier_detects_leaked_pem_and_id_rsa(tmp_path: Path) -> None:
    """SAD: multiple distinct credential-pattern leaks must all be reported.

    Mirrors the BUG-007 multi-file repro shape (5+ files in one walk)
    so a future regression that drops all-but-one entry from the
    report is caught here too."""
    for name in ("server.pem", "id_rsa", "id_ed25519",
                 "aws-credentials", "client.key"):
        (tmp_path / name).write_text(
            f"-- fake bytes for {name} --\n", encoding="utf-8"
        )
    result = _run(tmp_path)
    assert result.returncode == 6
    for name in ("server.pem", "id_rsa", "id_ed25519",
                 "aws-credentials", "client.key"):
        assert name in result.stderr, (
            f"verifier omitted {name!r} from stderr report; "
            f"got stderr={result.stderr!r}"
        )


def test_verifier_allows_dot_example_template(tmp_path: Path) -> None:
    """EDGE: *.example files are public templates and must NOT trip the scan.

    Otherwise the legitimate secrets.env.example shipped to the
    public mirror (documented in README) would be flagged on every
    export, making the verifier useless in practice."""
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "secrets.env.example").write_text(
        "# template\n", encoding="utf-8"
    )
    (tmp_path / "config.example").write_text(
        "# template\n", encoding="utf-8"
    )
    result = _run(tmp_path)
    assert result.returncode == 0, (
        f"*.example templates should be allowed; got rc={result.returncode}, "
        f"stderr={result.stderr!r}"
    )


def test_verifier_detects_case_insensitive_secrets(tmp_path: Path) -> None:
    """SAD: pattern matching is case-insensitive (re.IGNORECASE) so
    `Secrets.txt`, `CREDENTIALS.json`, `My-Credentials` etc. are all
    caught. Operators on case-insensitive filesystems (macOS HFS+,
    NTFS) might use mixed-case names; the verifier must not have a
    case-sensitivity gap that the script's `-iname` find covers."""
    (tmp_path / "Secrets.txt").write_text("x", encoding="utf-8")
    (tmp_path / "CREDENTIALS.json").write_text("{}", encoding="utf-8")
    result = _run(tmp_path)
    assert result.returncode == 6
    assert "Secrets.txt" in result.stderr
    assert "CREDENTIALS.json" in result.stderr


def test_verifier_usage_message_on_missing_arg(tmp_path: Path) -> None:
    """SAD: invoked without the TARGET arg, the verifier prints a
    usage line and exits non-zero. Defensive against an operator
    typo in the Makefile (the wrapper passes "$(EXPORT_PUBLIC_TARGET)"
    which could be empty if the var is unset; an empty positional
    arg would still satisfy argc, but a MISSING one shouldn't crash
    with a Python traceback)."""
    result = subprocess.run(
        [sys.executable, str(VERIFIER)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode != 0
    assert "usage" in result.stderr.lower(), (
        f"missing-arg should print usage; stderr={result.stderr!r}"
    )


def test_verifier_recurses_into_subdirectories(tmp_path: Path) -> None:
    """EDGE: leaks nested several directories deep are still caught
    (verifier uses os.walk, not a single-dir glob)."""
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    (nested / "deep.pem").write_text("-- key --", encoding="utf-8")
    result = _run(tmp_path)
    assert result.returncode == 6
    assert "deep.pem" in result.stderr


def test_BUG_009_verifier_detects_plain_dotenv_filenames(tmp_path: Path) -> None:
    """SAD / defense-in-depth: filenames ending in `.env` without a
    leading dot (`db.env`, `production.env`) are real-world secret
    files. The bash `_leak_scan` catches them via ``-name '*.env'``;
    the python verifier must do the same so the layers actually
    mirror each other. Pre-fix the regex anchored at start-of-name
    with ``\\.env`` which only matches `.env` / `.env.local`, leaving
    arbitrary-prefix `.env` files past the supposed safety net."""
    (tmp_path / "db.env").write_text("DB_PASS=leak\n", encoding="utf-8")
    (tmp_path / "production.env").write_text("X=y\n", encoding="utf-8")
    result = _run(tmp_path)
    assert result.returncode == 6, (
        f"verifier missed *.env (non-dotfile) leaks; rc={result.returncode}, "
        f"stderr={result.stderr!r}"
    )
    assert "db.env" in result.stderr
    assert "production.env" in result.stderr


def test_BUG_009_verifier_detects_id_keys_with_dash_suffix(tmp_path: Path) -> None:
    """SAD / defense-in-depth: backup-style key names like
    ``id_rsa-old`` or ``id_ed25519.bak`` are caught by the bash side
    (``-name 'id_rsa*'``) but the python regex used ``id_rsa(\\..+)?``
    which only allowed a `.X` suffix, missing the dash-separator
    convention operators routinely use."""
    (tmp_path / "id_rsa-old").write_text("-- key --", encoding="utf-8")
    (tmp_path / "id_ed25519-bak").write_text("-- key --", encoding="utf-8")
    result = _run(tmp_path)
    assert result.returncode == 6, (
        f"verifier missed id_X-* suffix leaks; rc={result.returncode}, "
        f"stderr={result.stderr!r}"
    )
    assert "id_rsa-old" in result.stderr
    assert "id_ed25519-bak" in result.stderr


def test_BUG_015_verifier_detects_tls_keystore_manual_backups(tmp_path: Path) -> None:
    """SAD / BUG-015 (postflight layer): TLS keystore manual-rotation
    backups (``host.pem.bak``, ``cert.key.old``, ``store.p12.bak``,
    ``vault.pfx-old``, ``ks.jks-old``) are byte-identical copies of the
    private TLS key material they back up. The BUG-013 widening added
    only the ``~`` editor-auto-backup convention; the manual ``cp X X.bak``
    rotation pattern was forgotten.

    Pre-fix regex shape was ``[^/]*\\.(pem|key|p12|pfx|keystore|jks)~?$`` —
    matches names ending in the canonical extension (optionally followed
    by ``~``) but no provision for ``.bak`` / ``.old`` / ``.local`` /
    ``-old``. The companion .envrc / .netrc / .npmrc / id_rsa families
    ALL handle manual rotation; the TLS keystore arm is the outlier.
    Fix: widen with ``(\\..+|-.+)?~?`` (same shape as ``.envrc``)."""
    for name in ("host.pem.bak", "cert.key.old", "store.p12.bak",
                 "vault.pfx-old", "ks.jks-old"):
        (tmp_path / name).write_text(
            f"-----BEGIN PRIVATE KEY----- {name} -----\n", encoding="utf-8"
        )
    result = _run(tmp_path)
    assert result.returncode == 6, (
        f"verifier missed TLS keystore manual-rotation backups; "
        f"rc={result.returncode}, stderr={result.stderr!r}"
    )
    for name in ("host.pem.bak", "cert.key.old", "store.p12.bak",
                 "vault.pfx-old", "ks.jks-old"):
        assert name in result.stderr, (
            f"verifier omitted {name!r} from stderr report; "
            f"got stderr={result.stderr!r}"
        )


def test_BUG_015_verifier_still_allows_pem_dot_example_template(
    tmp_path: Path,
) -> None:
    """HAPPY / EDGE: the BUG-015 widening must NOT regress the
    ``.example`` allowlist. A canonical ``host.pem.example`` (TLS key
    template) and ``cert.key.example`` must survive after the
    ``(\\..+|-.+)?~?`` widening on the TLS keystore arm — the
    ``f.endswith('.example')`` guard in main() is the documented
    allow-list anchor and must remain authoritative."""
    (tmp_path / "host.pem.example").write_text("# template\n", encoding="utf-8")
    (tmp_path / "cert.key.example").write_text("# template\n", encoding="utf-8")
    result = _run(tmp_path)
    assert result.returncode == 0, (
        f"BUG-015 fix regression: .example templates now trip the "
        f"verifier. rc={result.returncode}, stderr={result.stderr!r}"
    )
