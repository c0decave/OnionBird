"""B-011: install-user-js.sh emits per-server hardening from prefs.js.

Without this, a user who runs the companion user.js but starts TB without
the addon leaks the real hostname via HELO on the first SMTP. The fix
enumerates existing mail.smtpserver.* and mail.identity.* keys recorded
in prefs.js and emits matching user.js lines.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

SCRIPT = Path("/scripts/install-user-js.sh")


SAMPLE_PREFS_JS = '''\
# Mozilla user preferences file
user_pref("mail.smtpserver.smtp1.hostname", "smtp.example.com");
user_pref("mail.smtpserver.smtp1.port", 587);
user_pref("mail.smtpserver.smtp1.username", "alice@example.com");
user_pref("mail.smtpserver.smtp2.hostname", "cl76kxdkjvyeqrug65aukstub3cvkvax6pzbdjup54qidq2uqinfnbid.onion");
user_pref("mail.smtpserver.smtp2.port", 25);
user_pref("mail.smtpserver.smtp3.hostname", "CL76KXDKJVYEQRUG65AUKSTUB3CVKVAX6PZBDJUP54QIDQ2UQINFNBID.ONION:587.");
user_pref("mail.smtpserver.smtp4.hostname", "attacker.onion[glob]");
user_pref("mail.smtpserver.smtp5.hostname", "abc123def456.onion");
user_pref("mail.identity.id1.useremail", "alice@example.com");
user_pref("mail.identity.id1.fullName", "Alice");
user_pref("mail.identity.id2.useremail", "bob@example.com");
'''


def _build_synthetic_profile(tmpdir: Path) -> Path:
    """Create a fake TB profile dir with the required files for the script."""
    profile = tmpdir / "test-profile.default"
    profile.mkdir(parents=True)
    (profile / "prefs.js").write_text(SAMPLE_PREFS_JS)
    return profile


def _run_install(profile: Path, extra: list[str] | None = None) -> subprocess.CompletedProcess:
    cmd = ["bash", str(SCRIPT), str(profile)] + (extra or [])
    return subprocess.run(cmd, capture_output=True, text=True, check=True)


def test_install_emits_per_server_hello_argument(tmp_path: Path) -> None:
    profile = _build_synthetic_profile(tmp_path)
    _run_install(profile)
    out = (profile / "user.js").read_text()
    for key in ("smtp1", "smtp2"):
        needle = f'user_pref("mail.smtpserver.{key}.hello_argument", "[127.0.0.1]");'
        assert needle in out, f"missing per-server HELO for {key}: {out}"


def test_install_picks_try_ssl_per_server_type(tmp_path: Path) -> None:
    """Clearnet servers must require STARTTLS (try_ssl=3). Onion servers
    must NOT (try_ssl=0) — the onion already provides authentication +
    confidentiality at the rendezvous layer and TB's TLS verification
    would never pass on a .onion certificate."""
    profile = _build_synthetic_profile(tmp_path)
    _run_install(profile)
    out = (profile / "user.js").read_text()
    assert 'user_pref("mail.smtpserver.smtp1.try_ssl", 3);' in out, (
        "clearnet smtp1 must require STARTTLS"
    )
    assert 'user_pref("mail.smtpserver.smtp2.try_ssl", 0);' in out, (
        "onion smtp2 must NOT require STARTTLS"
    )
    assert 'user_pref("mail.smtpserver.smtp3.try_ssl", 0);' in out, (
        "onion smtp3 with uppercase/port/trailing-dot must NOT require STARTTLS"
    )
    assert 'user_pref("mail.smtpserver.smtp4.try_ssl", 3);' in out, (
        "hostname containing glob chars must not be classified by Bash pattern matching"
    )
    assert 'user_pref("mail.smtpserver.smtp5.try_ssl", 3);' in out, (
        "obsolete/short onion-looking hostnames must not disable STARTTLS"
    )


def test_install_emits_per_identity_hardening(tmp_path: Path) -> None:
    """F-074: install-user-js.sh no longer hard-codes
    `mail.identity.<key>.FQDN = "localhost.localdomain"` per
    identity — that put users on the script-only path into the
    TorBirdy supercluster fingerprint. The addon owns the
    Message-ID FQDN strategy once installed (default mode:
    `from_domain` = blend with the provider's regular users).
    The script still emits `compose_html = false` per identity
    because that's a privacy-relevant default the addon does
    not currently re-assert globally."""
    profile = _build_synthetic_profile(tmp_path)
    _run_install(profile)
    out = (profile / "user.js").read_text()
    for key in ("id1", "id2"):
        # F-074: the FQDN line MUST be absent now.
        assert f'user_pref("mail.identity.{key}.FQDN"' not in out, (
            f"F-074: install-user-js.sh wrote mail.identity.{key}.FQDN "
            f"per identity. That puts script-only users into the legacy "
            f"TorBirdy supercluster fingerprint. Removed in F-074; the "
            f"addon owns this pref via applyHardeningToAllIdentities."
        )
        assert f'user_pref("mail.identity.{key}.compose_html", false);' in out


def test_install_no_per_server_flag_suppresses(tmp_path: Path) -> None:
    profile = _build_synthetic_profile(tmp_path)
    _run_install(profile, ["--no-per-server"])
    out = (profile / "user.js").read_text()
    assert "mail.smtpserver.smtp1" not in out, (
        "--no-per-server must skip enumerated lines"
    )


def test_install_with_no_prefs_js_succeeds(tmp_path: Path) -> None:
    """First-run install before TB has written prefs.js should still work."""
    profile = tmp_path / "fresh"
    profile.mkdir()
    _run_install(profile)
    out = (profile / "user.js").read_text()
    assert 'user_pref("network.trr.mode", 5);' in out  # static prefs present
    assert "mail.smtpserver." not in out                # no per-server lines


def test_uninstall_removes_per_server_block(tmp_path: Path) -> None:
    profile = _build_synthetic_profile(tmp_path)
    _run_install(profile)
    subprocess.run(
        ["bash", str(SCRIPT), str(profile), "--uninstall"],
        capture_output=True, text=True, check=True,
    )
    out = (profile / "user.js").read_text()
    assert "mail.smtpserver." not in out
    assert "network.trr.mode" not in out


def test_reinstall_does_not_duplicate(tmp_path: Path) -> None:
    profile = _build_synthetic_profile(tmp_path)
    _run_install(profile)
    _run_install(profile)
    out = (profile / "user.js").read_text()
    assert out.count('user_pref("mail.smtpserver.smtp1.hello_argument"') == 1, (
        "double install should not duplicate the per-server block"
    )


def test_install_backs_up_existing_user_js_once(tmp_path: Path) -> None:
    profile = _build_synthetic_profile(tmp_path)
    existing = profile / "user.js"
    existing.write_text('// user custom pref\nuser_pref("example.keep", true);\n')
    _run_install(profile)
    backup = profile / "user.js.bak-pre-onionbird"
    assert backup.read_text() == '// user custom pref\nuser_pref("example.keep", true);\n'
    _run_install(profile)
    assert backup.read_text() == '// user custom pref\nuser_pref("example.keep", true);\n'
