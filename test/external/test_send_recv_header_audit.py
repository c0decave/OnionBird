"""S1: send-to-self via Tor, fetch back via IMAP-over-Tor, audit headers.

Run with:
    set -a; source test/external/secrets.env; set +a
    pytest test/external/test_send_recv_header_audit.py -v -s
"""

from __future__ import annotations

import uuid

import pytest

from external.header_audit import format_report, run_all
from external.imap_fetch import IMAPOverTor
from external.providers import ProviderConfig
from external.tb_real_send import send_via

# Mark all tests in this module as external
pytestmark = pytest.mark.external


def _unique_subject(scenario: str) -> str:
    return f"onionbird-{scenario}-{uuid.uuid4().hex[:12]}"


def test_S1_send_and_audit_headers(
    tb, provider: ProviderConfig, imap: IMAPOverTor,
    recv_email: str, delivery_timeout: int,
    socks_host: str, socks_port: int,
) -> None:
    """Send one mail through Tor, fetch via IMAP, audit every header."""
    subject = _unique_subject("S1")
    print(f"\n[S1] sending {subject!r} via {provider.code} ({provider.smtp_host})")
    send_via(
        tb, provider,
        to=recv_email,
        subject=subject,
        body="Plain body for S1 header audit.\n",
        socks_host=socks_host, socks_port=socks_port,
    )
    print(f"[S1] sent. polling {provider.imap_host} for arrival...")
    msg = imap.wait_for_subject(subject, timeout=delivery_timeout)
    assert msg is not None, (
        f"mail with subject {subject!r} did not arrive within {delivery_timeout}s"
    )

    print("[S1] retrieved. running header audit:")
    results = run_all(msg)
    print(format_report(results))
    failed = [r for r in results if not r.ok]
    p0_failed = [r for r in failed if r.severity == "P0"]
    assert not p0_failed, f"P0 header leaks: {[r.code for r in p0_failed]}"
    # Allow P1/P2 to be reported but not fail the test, so we see provider quirks
    if failed:
        print(f"[S1] non-blocking issues: {[r.code for r in failed]}")


def test_S4_utf8_subject_roundtrip(
    tb, provider: ProviderConfig, imap: IMAPOverTor,
    recv_email: str, delivery_timeout: int,
    socks_host: str, socks_port: int,
) -> None:
    """UTF-8 subject + body must survive Tor relay + provider + IMAP."""
    nonce = uuid.uuid4().hex[:8]
    subject = f"Geheim-{nonce} — Treffen 🌚"
    body = "ÜBerwacht? ja. Auch heute.\n"
    print(f"\n[S4] sending {subject!r} via {provider.code}")
    send_via(
        tb, provider,
        to=recv_email, subject=subject, body=body,
        socks_host=socks_host, socks_port=socks_port,
    )
    msg = imap.wait_for_subject(f"Geheim-{nonce}", timeout=delivery_timeout)
    assert msg is not None, "UTF-8 mail did not arrive"

    # Subject was RFC 2047 encoded on the wire; imap-tools decodes it back
    assert "Geheim-" + nonce in msg.subject, (
        f"subject not preserved: {msg.subject!r}"
    )
    assert "🌚" in msg.subject or "&#127770;" in msg.subject, (
        "emoji lost in subject"
    )
    assert "ÜBerwacht" in msg.body_text, "ÜBerwacht lost in body"

    results = run_all(msg)
    print(format_report(results))
    p0 = [r for r in results if not r.ok and r.severity == "P0"]
    assert not p0, f"P0 leaks: {p0}"


def test_S6_burst_five_mails(
    tb, provider: ProviderConfig, imap: IMAPOverTor,
    recv_email: str, delivery_timeout: int,
    socks_host: str, socks_port: int,
) -> None:
    """5 sequential sends; every one must arrive AND pass the audit."""
    batch = uuid.uuid4().hex[:8]
    subjects = [f"burst-{batch}-{i}" for i in range(5)]
    print(f"\n[S6] sending 5 mails in batch {batch}")
    for s in subjects:
        send_via(
            tb, provider,
            to=recv_email, subject=s, body=f"body {s}\n",
            socks_host=socks_host, socks_port=socks_port,
        )
    # Poll for the LAST one as a barrier (assume in-order delivery; if not,
    # extend the loop)
    print(f"[S6] sent. waiting for arrival of {subjects[-1]!r}")
    last = imap.wait_for_subject(subjects[-1], timeout=delivery_timeout * 2)
    assert last is not None, "5th burst mail did not arrive"

    # Now collect all 5
    arrived = []
    for s in subjects:
        m = imap.wait_for_subject(s, timeout=5)
        if m:
            arrived.append((s, m))
    print(f"[S6] {len(arrived)}/5 retrieved.")
    assert len(arrived) == 5, (
        f"missing burst mails: {[s for s in subjects if not any(s == k for k, _ in arrived)]}"
    )

    # Audit each
    for s, m in arrived:
        results = run_all(m)
        p0 = [r for r in results if not r.ok and r.severity == "P0"]
        assert not p0, f"P0 leak in {s}: {p0}"


def test_S8_fail_closed_with_bad_socks(
    tb, provider: ProviderConfig, socks_host: str,
) -> None:
    """SOCKS port 19999 (nothing listening) + failover_direct=false:
    the send must fail and the mail must never leave TB."""
    print("\n[S8] sending with bad SOCKS port")
    raised = False
    try:
        send_via(
            tb, provider,
            to=provider.email,
            subject=_unique_subject("S8-FAIL"),
            body="should not leave\n",
            socks_host=socks_host, socks_port=19999,
        )
    except Exception as e:
        raised = True
        print(f"[S8] send raised as expected: {e}")
    assert raised, "send did NOT fail with bad SOCKS — possible bypass"
