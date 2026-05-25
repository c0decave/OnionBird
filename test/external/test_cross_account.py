"""SX1: cross-account send + recipient-mailbox audit.

Sends from the configured provider's identity TO a distinct recipient
mailbox (T0R_RECV_USER) and verifies the mail arrives in the recipient's
INBOX. Both mailboxes are accessed IMAP-over-Tor. Headers are audited
on the message as the RECIPIENT sees it (different verdict surface than
the send-to-self audit — receiving-side rewrites by the provider's
inbound MTA are visible here).
"""

from __future__ import annotations

import uuid

import pytest

from external.header_audit import format_report, run_all
from external.imap_fetch import IMAPOverTor
from external.providers import ProviderConfig
from external.tb_real_send import send_via

pytestmark = pytest.mark.external


def _subject(scenario: str) -> str:
    return f"onionbird-{scenario}-{uuid.uuid4().hex[:12]}"


def test_SX1_cross_account_send_and_audit(
    tb, provider: ProviderConfig,
    recv_provider: ProviderConfig, imap_recv: IMAPOverTor,
    delivery_timeout: int,
    socks_host: str, socks_port: int,
) -> None:
    if recv_provider.user == provider.user:
        pytest.skip(
            "no distinct T0R_RECV_USER configured — set in secrets.env "
            "to exercise cross-account delivery"
        )
    subject = _subject("SX1")
    print(
        f"\n[SX1] send from {provider.email!r} -> {recv_provider.email!r}"
        f" via {provider.smtp_host}"
    )
    send_via(
        tb, provider,
        to=recv_provider.email,
        subject=subject,
        body="SX1 cross-account body.\n",
        socks_host=socks_host, socks_port=socks_port,
    )
    print(f"[SX1] sent. polling recipient {recv_provider.imap_host}...")
    msg = imap_recv.wait_for_subject(subject, timeout=delivery_timeout)
    assert msg is not None, (
        f"SX1: mail {subject!r} did not arrive in {recv_provider.user!r} "
        f"within {delivery_timeout}s"
    )

    # Provider-internal Received hops show up here (sender->provider MTA->
    # recipient inbox) — the audit covers all of them.
    results = run_all(msg)
    print(format_report(results))
    p0 = [r for r in results if not r.ok and r.severity == "P0"]
    assert not p0, f"P0 leaks in recipient-view: {[r.code for r in p0]}"


def test_SX2_recv_mailbox_does_not_leak_dns(
    tb, provider: ProviderConfig,
    recv_provider: ProviderConfig, imap_recv: IMAPOverTor,
    delivery_timeout: int,
    socks_host: str, socks_port: int,
) -> None:
    """Cross-account IMAP fetch must itself go through SOCKS+rdns — no DNS
    queries for recv_provider.imap_host may hit dns-trap."""
    if recv_provider.user == provider.user:
        pytest.skip("no distinct T0R_RECV_USER configured")
    import json
    import time
    import urllib.request

    DNS_TRAP = "http://dns-trap:8053/queries"
    urllib.request.urlopen(
        urllib.request.Request(DNS_TRAP, method="DELETE"), timeout=5
    ).read()

    subject = _subject("SX2")
    send_via(
        tb, provider,
        to=recv_provider.email,
        subject=subject,
        body="SX2 no-leak audit.\n",
        socks_host=socks_host, socks_port=socks_port,
    )
    msg = imap_recv.wait_for_subject(subject, timeout=delivery_timeout)
    assert msg is not None, "SX2 mail did not arrive"

    time.sleep(0.5)
    queries = json.loads(urllib.request.urlopen(DNS_TRAP, timeout=5).read())
    bad = [
        q for q in queries
        if recv_provider.imap_host in q.get("qname", "")
        and q.get("disposition") != "forwarded"
    ]
    assert not bad, f"cross-account IMAP DNS leak: {bad}"
