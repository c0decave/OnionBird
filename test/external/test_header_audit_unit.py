"""Unit tests for the header-audit checks (H1..H15).

These do NOT require a real provider — they exercise each check against
synthetic FetchedMessage objects to verify the check logic is correct.
Run as part of the regular `make test-integration` (mounted in runner).
"""

from __future__ import annotations

from email.message import Message

from external.header_audit import (
    H1_received_chain_no_real_ip,
    H2_message_id_fqdn,
    H3_date_utc,
    H4_no_user_agent,
    H5_no_content_language,
    H6_mime_version,
    H7_from_matches,
    H8_no_x_originating_ip,
    H9_authentication_results,
    H10_dkim_signature,
    H11_return_path_clean,
    H12_mime_boundary_random,
    H13_subject_roundtrip,
    H14_reply_refs,
    H15_list_headers,
    run_all,
    summarize,
)
from external.imap_fetch import FetchedMessage


def make_msg(headers: dict[str, str], body: str = "body\n") -> FetchedMessage:
    m = Message()
    for k, v in headers.items():
        m[k] = v
    if body:
        m.set_payload(body)
    raw = m.as_bytes()
    multi: dict[str, list[str]] = {}
    for k, v in headers.items():
        multi.setdefault(k, []).append(v)
    return FetchedMessage(
        raw=raw,
        headers=dict(headers),
        headers_multi=multi,
        subject=headers.get("Subject", ""),
        message_id=headers.get("Message-ID", ""),
        body_text=body,
    )


def make_msg_multi_received(received_hops: list[str], **extra_headers) -> FetchedMessage:
    """Build a FetchedMessage with multiple Received headers preserved.
    First entry in received_hops is the latest (closest to destination)."""
    m = make_msg(extra_headers, body="x")
    m.headers_multi["Received"] = list(received_hops)
    m.headers["Received"] = received_hops[0] if received_hops else ""
    return m


# ---------- H1 ----------

def test_H1_no_received_passes() -> None:
    r = H1_received_chain_no_real_ip(make_msg({}))
    assert r.ok


def test_H1_clean_received_passes() -> None:
    r = H1_received_chain_no_real_ip(make_msg({
        "Received": "from [127.0.0.1] (helo=[127.0.0.1]) by smtp.disroot.org with ESMTPSA"
    }))
    assert r.ok, r.evidence


def test_H1_rfc1918_in_received_fails_p0() -> None:
    r = H1_received_chain_no_real_ip(make_msg({
        "Received": "from laptop ([192.168.178.42]) by smtp.example.com with ESMTPSA"
    }))
    assert not r.ok
    assert r.severity == "P0"
    assert "192.168.178.42" in r.evidence


def test_H1_lan_hostname_fails_p0() -> None:
    r = H1_received_chain_no_real_ip(make_msg({
        "Received": "from marco.fritz.box ([1.2.3.4]) by smtp.example.com"
    }))
    assert not r.ok
    assert r.severity == "P0"


def test_H1_rfc1918_only_blocks_in_earliest_hop() -> None:
    """H1 catches RFC1918 in the sender-side (earliest) hop only.
    Provider-internal RFC1918 is normal MTA routing and not a leak."""
    # RFC1918 in earliest = real leak
    r = H1_received_chain_no_real_ip(make_msg_multi_received([
        "from provider-mx.example.com by destination",
        "from relay.example.com ([1.2.3.4]) by provider",
        "from laptop ([192.168.178.5]) by relay",  # earliest = sender hop
    ]))
    assert not r.ok, "H1 must catch RFC1918 in earliest (sender) hop"
    assert "192.168.178.5" in r.evidence
    assert r.severity == "P0"


def test_H1_rfc1918_in_intermediate_hop_is_ok() -> None:
    """Provider-internal RFC1918 (e.g. internal mail relay) is not a leak."""
    r = H1_received_chain_no_real_ip(make_msg_multi_received([
        "from mx-out.example.com ([172.20.0.7]) by destination.example.com",  # provider-internal
        "from public-mx.example.com ([198.51.100.5]) by mx-out",              # public Tor exit
    ]))
    assert r.ok, f"provider-internal RFC1918 must not fail H1; got: {r.evidence}"
    assert "provider-internal" in r.evidence


def test_H1_clean_multi_hop_passes() -> None:
    r = H1_received_chain_no_real_ip(make_msg_multi_received([
        "from provider-mx.example.com by destination",
        "from relay.example.com by provider",
        "from [127.0.0.1] by relay",
    ]))
    assert r.ok, r.evidence
    assert "3 hops" in r.evidence


# ---------- H2 ----------

def test_H2_localhost_localdomain_passes() -> None:
    r = H2_message_id_fqdn(make_msg({"Message-ID": "<abc@localhost.localdomain>"}))
    assert r.ok


def test_H2_provider_rewrite_passes() -> None:
    r = H2_message_id_fqdn(make_msg({"Message-ID": "<x@disroot.org>"}))
    assert r.ok


def test_H2_lan_hostname_fails_p0() -> None:
    r = H2_message_id_fqdn(make_msg({"Message-ID": "<abc@laptop.lan>"}))
    assert not r.ok
    assert r.severity == "P0"


def test_H2_missing_fails_p0() -> None:
    r = H2_message_id_fqdn(make_msg({}))
    assert not r.ok
    assert r.severity == "P0"


# ---------- H3 ----------

def test_H3_utc_offset_passes() -> None:
    r = H3_date_utc(make_msg({"Date": "Thu, 21 May 2026 14:00:00 +0000"}))
    assert r.ok


def test_H3_gmt_passes() -> None:
    r = H3_date_utc(make_msg({"Date": "Thu, 21 May 2026 14:00:00 GMT"}))
    assert r.ok


def test_H3_non_utc_fails() -> None:
    r = H3_date_utc(make_msg({"Date": "Thu, 21 May 2026 16:00:00 +0200"}))
    assert not r.ok


def test_H3_missing_fails() -> None:
    r = H3_date_utc(make_msg({}))
    assert not r.ok


# ---------- H4 ----------

def test_H4_no_ua_passes() -> None:
    r = H4_no_user_agent(make_msg({}))
    assert r.ok


def test_H4_user_agent_fails_p0() -> None:
    r = H4_no_user_agent(make_msg({"User-Agent": "Thunderbird/140.11.0esr"}))
    assert not r.ok
    assert r.severity == "P0"


def test_H4_x_mailer_fails_p0() -> None:
    r = H4_no_user_agent(make_msg({"X-Mailer": "Thunderbird/140.11.0esr"}))
    assert not r.ok
    assert r.severity == "P0"


def test_H4_lowercase_user_agent_fails_p0() -> None:
    msg = make_msg({})
    msg.headers["user-agent"] = "Thunderbird/140.11.0esr"
    msg.headers_multi["user-agent"] = ["Thunderbird/140.11.0esr"]
    r = H4_no_user_agent(msg)
    assert not r.ok
    assert r.severity == "P0"


# ---------- H5 ----------

def test_H5_no_content_language_passes() -> None:
    r = H5_no_content_language(make_msg({}))
    assert r.ok


def test_H5_de_de_fails() -> None:
    r = H5_no_content_language(make_msg({"Content-Language": "de-DE"}))
    assert not r.ok


# ---------- H6 ----------

def test_H6_mime_version_10_passes() -> None:
    r = H6_mime_version(make_msg({"MIME-Version": "1.0"}))
    assert r.ok


def test_H6_missing_fails() -> None:
    r = H6_mime_version(make_msg({}))
    assert not r.ok


def test_H6_unexpected_version_fails() -> None:
    r = H6_mime_version(make_msg({"MIME-Version": "2.0"}))
    assert not r.ok


# ---------- H7 ----------

def test_H7_no_expectation_passes_on_present() -> None:
    r = H7_from_matches(make_msg({"From": "alice@disroot.org"}))
    assert r.ok


def test_H7_match_passes() -> None:
    r = H7_from_matches(
        make_msg({"From": "Alice <alice@disroot.org>"}),
        expected_email="alice@disroot.org",
    )
    assert r.ok


def test_H7_mismatch_fails() -> None:
    r = H7_from_matches(
        make_msg({"From": "evil@bad.example"}),
        expected_email="alice@disroot.org",
    )
    assert not r.ok


# ---------- H8 ----------

def test_H8_no_leak_headers_passes() -> None:
    r = H8_no_x_originating_ip(make_msg({}))
    assert r.ok


def test_H8_x_originating_ip_fails_p0() -> None:
    r = H8_no_x_originating_ip(make_msg({"X-Originating-IP": "[1.2.3.4]"}))
    assert not r.ok
    assert r.severity == "P0"


def test_H8_x_forwarded_for_fails_p0() -> None:
    r = H8_no_x_originating_ip(make_msg({"X-Forwarded-For": "10.0.0.5"}))
    assert not r.ok
    assert r.severity == "P0"


def test_H8_duplicate_lowercase_leak_header_fails_p0() -> None:
    msg = make_msg({"Subject": "x"})
    msg.headers_multi["x-originating-ip"] = ["[1.2.3.4]"]
    r = H8_no_x_originating_ip(msg)
    assert not r.ok
    assert r.severity == "P0"
    assert "1.2.3.4" in r.evidence


# ---------- H9, H10, H15 (informational) ----------

def test_H9_always_passes() -> None:
    assert H9_authentication_results(make_msg({})).ok
    r = H9_authentication_results(make_msg({"Authentication-Results": "dkim=pass"}))
    assert r.ok and r.severity == "info"


def test_H10_always_passes() -> None:
    assert H10_dkim_signature(make_msg({})).ok
    r = H10_dkim_signature(make_msg({"DKIM-Signature": "v=1; a=rsa-sha256; ..."}))
    assert r.ok and r.severity == "info"


def test_H15_always_passes() -> None:
    assert H15_list_headers(make_msg({})).ok
    r = H15_list_headers(make_msg({"List-Unsubscribe": "<mailto:u@example>"}))
    assert r.ok and r.severity == "info" and "List-Unsubscribe" in r.evidence


# ---------- H11 ----------

def test_H11_return_path_matches_from_passes() -> None:
    r = H11_return_path_clean(
        make_msg({"Return-Path": "<alice@disroot.org>"}),
        expected_email="alice@disroot.org",
    )
    assert r.ok


def test_H11_return_path_mismatch_fails() -> None:
    r = H11_return_path_clean(
        make_msg({"Return-Path": "<bounce@spammer.tld>"}),
        expected_email="alice@disroot.org",
    )
    assert not r.ok


def test_H11_lan_hint_fails_p0() -> None:
    r = H11_return_path_clean(
        make_msg({"Return-Path": "<alice@host.lan>"}),
        expected_email="alice@host.lan",
    )
    assert not r.ok
    assert r.severity == "P0"


# ---------- H12 ----------

def test_H12_non_multipart_passes() -> None:
    r = H12_mime_boundary_random(make_msg({"Content-Type": "text/plain"}))
    assert r.ok


def test_H12_uuid_boundary_passes() -> None:
    r = H12_mime_boundary_random(make_msg({
        "Content-Type": 'multipart/alternative; boundary="------------a1b2c3d4e5f60718"'
    }))
    assert r.ok


def test_H12_timestamp_boundary_fails() -> None:
    r = H12_mime_boundary_random(make_msg({
        "Content-Type": 'multipart/alternative; boundary="------------1234567890123456"'
    }))
    assert not r.ok


def test_H12_short_boundary_fails() -> None:
    r = H12_mime_boundary_random(make_msg({
        "Content-Type": 'multipart/alternative; boundary="------------abc"'
    }))
    assert not r.ok


# ---------- H13 ----------

def test_H13_subject_present_passes() -> None:
    r = H13_subject_roundtrip(make_msg({"Subject": "hello"}))
    assert r.ok


def test_H13_expected_substring_passes() -> None:
    r = H13_subject_roundtrip(
        make_msg({"Subject": "burst-abc123-0"}),
        expected_substring="burst-abc123",
    )
    assert r.ok


def test_H13_expected_substring_missing_fails() -> None:
    r = H13_subject_roundtrip(
        make_msg({"Subject": "wrong"}),
        expected_substring="needle",
    )
    assert not r.ok


def test_H13_missing_subject_fails() -> None:
    r = H13_subject_roundtrip(make_msg({}))
    assert not r.ok


# ---------- H14 ----------

def test_H14_no_reply_no_thread_headers_passes() -> None:
    r = H14_reply_refs(make_msg({}))
    assert r.ok


def test_H14_unexpected_in_reply_to_fails() -> None:
    r = H14_reply_refs(make_msg({"In-Reply-To": "<unrelated@x>"}))
    assert not r.ok


def test_H14_reply_correct_refs_pass() -> None:
    parent = "<parent-abc@localhost.localdomain>"
    r = H14_reply_refs(
        make_msg({"In-Reply-To": parent, "References": parent}),
        expected_in_reply_to=parent,
    )
    assert r.ok


def test_H14_reply_missing_in_reply_to_fails() -> None:
    parent = "<parent@x>"
    r = H14_reply_refs(
        make_msg({"References": parent}),
        expected_in_reply_to=parent,
    )
    assert not r.ok


def test_H14_reply_missing_references_fails() -> None:
    parent = "<parent@x>"
    r = H14_reply_refs(
        make_msg({"In-Reply-To": parent}),
        expected_in_reply_to=parent,
    )
    assert not r.ok


# ---------- run_all + summarize ----------

def test_run_all_returns_15_results() -> None:
    msg = make_msg({
        "Date": "Thu, 21 May 2026 14:00:00 +0000",
        "From": "alice@disroot.org",
        "Message-ID": "<a@localhost.localdomain>",
        "MIME-Version": "1.0",
        "Return-Path": "<alice@disroot.org>",
        "Subject": "test",
    })
    results = run_all(msg, expected_from="alice@disroot.org", expected_subject="test")
    assert len(results) == 15
    codes = {r.code for r in results}
    assert codes == {f"H{i}" for i in range(1, 16)}


def test_summarize_counts_correctly() -> None:
    # Clean message — all P0/P1/P2 pass; info-tier are counted separately.
    msg = make_msg({
        "Date": "Thu, 21 May 2026 14:00:00 +0000",
        "From": "alice@disroot.org",
        "Message-ID": "<a@localhost.localdomain>",
        "MIME-Version": "1.0",
        "Return-Path": "<alice@disroot.org>",
        "Subject": "test",
    })
    results = run_all(msg, expected_from="alice@disroot.org")
    s = summarize(results)
    assert s["fail_p0"] == 0
    assert s["pass"] >= 10  # all 11 non-info checks pass
    # info-tier: H9 (Auth-Results), H10 (DKIM), H12 (non-multipart n/a), H15 (list)
    assert s["info"] == 4


def test_summarize_p0_leak_counted() -> None:
    msg = make_msg({
        "User-Agent": "Thunderbird/140.11.0esr",
        "Message-ID": "<a@laptop.lan>",
        "Date": "Thu, 21 May 2026 14:00:00 +0000",
    })
    results = run_all(msg)
    s = summarize(results)
    assert s["fail_p0"] >= 2  # H2 + H4
