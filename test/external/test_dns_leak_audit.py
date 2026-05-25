"""S9: end-to-end DNS-leak audit during real Tor-routed send.

Premise revisited: the handoff (2026-05-21) claimed TB 140's SmtpClient uses
TCPSocket and pre-resolves the SMTP host locally, bypassing socks_remote_dns.
This audit verifies the *actual* behaviour against undisclose.de (or any
provider): no DNS query for the SMTP/IMAP host hits the local resolver
(dns-trap) during a real send. If TB ever regresses and does pre-resolve,
dns-trap is now a Tor-DNS forwarder (no clearnet leak), and we still see
the query logged with disposition='forwarded' — so a future leak is loud,
not silent.
"""

from __future__ import annotations

import json
import time
import urllib.request
import uuid

import pytest

from external.imap_fetch import IMAPOverTor
from external.providers import ProviderConfig
from external.tb_real_send import send_via

pytestmark = pytest.mark.external

DNS_TRAP_URL = "http://dns-trap:8053/queries"
SMTP_TRAP_WAIT_URL = "http://smtp-trap:8025/messages/wait?n=1&timeout=30"
SMTP_TRAP_MESSAGES_URL = "http://smtp-trap:8025/messages"


def _dns_queries() -> list[dict]:
    with urllib.request.urlopen(DNS_TRAP_URL, timeout=5) as r:
        return json.loads(r.read())


def _dns_clear() -> None:
    req = urllib.request.Request(DNS_TRAP_URL, method="DELETE")
    urllib.request.urlopen(req, timeout=5).read()


def _smtp_clear() -> None:
    req = urllib.request.Request(SMTP_TRAP_MESSAGES_URL, method="DELETE")
    urllib.request.urlopen(req, timeout=5).read()


def _smtp_wait_for_one() -> list[dict]:
    with urllib.request.urlopen(SMTP_TRAP_WAIT_URL, timeout=35) as r:
        return json.loads(r.read())


def _queries_for(qname_substr: str) -> list[dict]:
    return [q for q in _dns_queries() if qname_substr in q.get("qname", "")]


def test_S9_no_dns_leak_for_smtp_host_during_send(
    tb, provider: ProviderConfig, imap: IMAPOverTor,
    recv_email: str, delivery_timeout: int,
    socks_host: str, socks_port: int,
) -> None:
    """During a real send, the SMTP host must not be resolved by the local
    resolver. If it IS (TCPSocket pre-resolve regression), the disposition
    must be 'forwarded' (i.e. via Tor) — never anything else.

    'forwarded' is the only acceptable disposition for any clearnet query
    that did happen to escape SOCKS5 remote-DNS — because dns-trap forwards
    to tor:5353, not to ISP/system DNS.
    """
    _dns_clear()
    subject = f"onionbird-S9-{uuid.uuid4().hex[:12]}"
    send_via(
        tb, provider,
        to=recv_email, subject=subject,
        body="S9 dns-leak audit\n",
        socks_host=socks_host, socks_port=socks_port,
    )
    # Allow a brief settle so any async DNS still in-flight gets logged
    time.sleep(0.5)

    smtp_q = _queries_for(provider.smtp_host)
    imap_q = _queries_for(provider.imap_host)
    all_clearnet_qs = smtp_q + imap_q

    # Acceptable outcomes:
    #   A. Zero queries — TB used SOCKS5 remote-DNS for everything (best).
    #   B. >=1 query — TB pre-resolved, BUT every disposition must be
    #      'forwarded' (i.e. went via Tor, not system DNS).
    bad = [q for q in all_clearnet_qs if q["disposition"] != "forwarded"]
    assert not bad, (
        f"DNS LEAK detected: queries for SMTP/IMAP host had non-Tor "
        f"disposition: {bad}"
    )

    # Belt-and-braces: also assert no .onion ever appears (would mean
    # something tried to resolve an onion via DNS — always a leak).
    onion_q = [q for q in _dns_queries() if ".onion" in q.get("qname", "")]
    assert not onion_q, f".onion in DNS log = leak: {onion_q}"

    # Now make sure the send actually completed (mail arrived). Without this
    # the test could pass on a no-op send.
    msg = imap.wait_for_subject(subject, timeout=delivery_timeout)
    assert msg is not None, f"S9 mail did not arrive within {delivery_timeout}s"


def test_S9b_onion_smtp_send_leaks_no_dns(
    tb,
    socks_host: str, socks_port: int,
) -> None:
    """Sanity sibling of S9 for onion: when the test infra's onion SMTP is
    targeted, NO DNS query for the .onion may appear (it must be resolved
    by Tor via SOCKS5 RESOLVE, not via the local resolver).

    Skipped when not running against the internal onion fixture.
    """
    import os
    onion_path = "/tests/fixtures/onion-hostname.txt"
    if not os.path.exists(onion_path):
        pytest.skip("internal onion fixture missing")
    onion = open(onion_path).read().strip()

    _dns_clear()
    _smtp_clear()
    # Compose a faux provider pointing at the onion smtp-trap. We don't auth.
    from external.providers import ProviderConfig as PC
    fake = PC(
        code="ONION",
        email="anon@local.invalid",
        user="",
        password="",
        smtp_host=onion,
        smtp_port=25,
        imap_host="",
        imap_port=0,
        smtp_use_ssl=False,
        smtp_socket_type=1,  # plain
        imap_use_ssl=False,
    )
    result = send_via(
        tb, fake,
        to="dropbox@local.invalid",
        subject="S9b onion dns-leak audit",
        body="x\n",
        socks_host=socks_host, socks_port=socks_port,
    )
    assert result == "ok"
    captured = _smtp_wait_for_one()
    assert captured and captured[0]["rcpt_tos"] == ["dropbox@local.invalid"]
    time.sleep(0.3)
    onion_q = [q for q in _dns_queries() if ".onion" in q.get("qname", "")]
    assert not onion_q, (
        f"LEAK: onion {onion} appeared in DNS log: {onion_q}"
    )
