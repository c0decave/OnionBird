"""B-095 + F-088: tests for atn-sign.sh helper functions.

The atn-sign.sh script previously had zero automated test coverage —
the only signal it worked was a green ATN upload. F-088 added a
`redact_secrets` shell function for log hygiene; B-095 generally
flagged the no-test situation. This file covers the testable
fragments of the script:

  - redact_secrets actually redacts JWT-shaped strings and the
    literal $JWT / $ATN_API_SECRET values
  - script has `set +x` early so a bash -x wrapper can't leak
  - mint_jwt produces a three-segment base64url JWT shape

These are sub-script unit tests that don't require an ATN endpoint.
The real "does the full upload work" test stays a manual gesture
gated on real ATN credentials.
"""
from __future__ import annotations

import re
import subprocess
import textwrap


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_atn_sign_redact_secrets_replaces_jwt_value() -> None:
    """The redact_secrets bash function (F-088) must replace the
    runtime $JWT value with a placeholder. Source the script's
    function and pipe a payload containing the JWT through it."""
    script = _read("/scripts/atn-sign.sh")
    # Extract the redact_secrets function definition. We source-equivalent
    # it into a small bash harness so we don't have to run the full script
    # (which would hit ATN).
    m = re.search(
        r"^redact_secrets\(\)\s*\{[\s\S]+?\n\}",
        script,
        re.MULTILINE,
    )
    assert m, "F-088: redact_secrets function not found in atn-sign.sh"
    fn = m.group(0)
    harness = textwrap.dedent(f"""
        set -euo pipefail
        export JWT="abc123secret-jwt-value"
        export ATN_API_SECRET="theverysecretvalue"
        {fn}
        printf '%s\\n' "Authorization: JWT $JWT and secret was $ATN_API_SECRET" \\
          | redact_secrets
    """)
    out = subprocess.check_output(["bash", "-c", harness], text=True, timeout=10)
    assert "abc123secret-jwt-value" not in out, (
        f"F-088: redact_secrets did not redact the literal $JWT value. "
        f"Output: {out!r}"
    )
    assert "theverysecretvalue" not in out, (
        f"F-088: redact_secrets did not redact $ATN_API_SECRET. "
        f"Output: {out!r}"
    )
    assert "<REDACTED-JWT>" in out, (
        f"F-088: expected <REDACTED-JWT> placeholder. Output: {out!r}"
    )


def test_atn_sign_redact_secrets_replaces_shape_match() -> None:
    """redact_secrets must also redact strings matching the JWT shape
    (header.payload.signature, all base64url) even when $JWT itself
    isn't set in the environment (e.g. a JWT was minted and discarded
    without being captured into the variable)."""
    script = _read("/scripts/atn-sign.sh")
    m = re.search(
        r"^redact_secrets\(\)\s*\{[\s\S]+?\n\}",
        script,
        re.MULTILINE,
    )
    assert m
    fn = m.group(0)
    # A realistic-shaped JWT (base64url segments)
    fake_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJpc3MiOiJ0ZXN0Iiwic3ViIjoidGVzdCIsImlhdCI6MTcwMDAwMDAwMH0"
        ".aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-_aBcDeF"
    )
    harness = textwrap.dedent(f"""
        set -euo pipefail
        unset JWT || true
        unset ATN_API_SECRET || true
        {fn}
        printf '%s\\n' "Authorization: JWT {fake_jwt}" | redact_secrets
    """)
    out = subprocess.check_output(["bash", "-c", harness], text=True, timeout=10)
    assert fake_jwt not in out, (
        f"F-088: shape-based JWT detection missed the bearer. "
        f"Output: {out!r}"
    )
    assert "<REDACTED-JWT-SHAPE>" in out, (
        f"F-088: expected <REDACTED-JWT-SHAPE> placeholder. "
        f"Output: {out!r}"
    )


def test_atn_sign_disables_xtrace_explicitly() -> None:
    """F-088: `set +x` must appear in the script so a wrapper
    invoking the script with `bash -x` cannot expand $JWT to stderr.

    We also require it to appear in the script's top preamble (first
    50 lines) rather than buried somewhere — defense-in-depth lives
    at the top where reviewers look."""
    script = _read("/scripts/atn-sign.sh")
    lines = script.splitlines()
    preamble = "\n".join(lines[:50])
    assert re.search(r"^set\s+\+x\b", preamble, re.MULTILINE), (
        "F-088: no `set +x` in the first 50 lines of atn-sign.sh. "
        "A wrapper invoking the script with `bash -x` or "
        "SHELLOPTS=xtrace would expand $JWT to stderr on every "
        "command — short-lived JWTs are still valid bearer "
        "credentials and should not land in CI logs."
    )


def test_atn_sign_mint_jwt_definition_present() -> None:
    """B-095: structural assertion that mint_jwt is defined and has
    the load-bearing properties. We do NOT execute mint_jwt in
    isolation because the body uses a python heredoc (PYEOF) that's
    awkward to re-source without re-implementing the heredoc-aware
    bash parser. The redact_secrets tests above cover the security-
    relevant log-hygiene path; this one covers shape regression of
    mint_jwt's own envelope (function exists, mints HS256 JWT,
    consults ATN_API_KEY / ATN_API_SECRET)."""
    script = _read("/scripts/atn-sign.sh")
    assert re.search(r"^mint_jwt\s*\(\)\s*\{", script, re.MULTILINE), (
        "B-095: mint_jwt function definition missing from atn-sign.sh"
    )
    # The relevant python block must use HS256 (Mozilla ATN's spec).
    assert '"alg": "HS256"' in script or "'alg': 'HS256'" in script, (
        "B-095: mint_jwt does not declare HS256 — ATN requires it."
    )
    # Must read the secret from env (not hardcoded).
    assert 'os.environ["ATN_API_SECRET"]' in script or \
           "os.environ['ATN_API_SECRET']" in script, (
        "B-095: mint_jwt does not read ATN_API_SECRET from env — "
        "hardcoded secret regression."
    )
