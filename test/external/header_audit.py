"""Header audit checks against a received RFC 5322 message.

One check per row of header_matrix.md (H1..H15). Numbering matches the
matrix exactly. Each check returns a CheckResult with (ok, evidence, severity).

Severity levels:
  P0   exploitable identity leak — blocks the test
  P1   soft fingerprint — reported, does not block
  P2   sanity check — reported, does not block
  info informational provider behaviour — never blocks
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from external.imap_fetch import FetchedMessage


@dataclass
class CheckResult:
    code: str
    name: str
    ok: bool
    evidence: str
    severity: str = "P1"
    blocking: bool = field(init=False)

    def __post_init__(self) -> None:
        self.blocking = self.severity == "P0"


Check = Callable[[FetchedMessage], CheckResult]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RFC1918 = re.compile(
    r"\b(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b"
)
_HOSTNAME_FLAGS = (
    ".local",       # mDNS / Bonjour
    ".lan",         # generic LAN
    ".home",        # generic home network
    ".home.arpa",   # RFC 8375 home networks
    ".internal",    # generic internal
    ".fritz.box",   # AVM FritzBox default
    "fritz.box",    # AVM without leading dot
    ".speedport",   # Telekom Speedport
    ".gateway",     # generic
    ".intra",       # generic
    ".workgroup",   # SMB default
    ".corp",        # generic corp
    ".lan.",        # appearing as a subdomain
)
_LEAK_HEADERS = (
    "X-Originating-IP",
    "X-Source-IP",
    "X-Real-IP",
    "X-Forwarded-For",
    "X-Sender-IP",
    "X-Originating-Client",
    "X-Mozilla-Status",
    "X-Mozilla-Status2",
)


def _all_received(msg: FetchedMessage) -> list[str]:
    """Return all Received: header values (RFC 5322 allows duplicates).
    Uses headers_multi to preserve every hop, ordered as they appear in
    the message (top = closest-to-destination, bottom = closest-to-sender)."""
    multi = _header_values(msg, "Received")
    if multi:
        return list(multi)
    return []


def _header_values(msg: FetchedMessage, name: str) -> list[str]:
    """Case-insensitive multi-value header lookup.

    Leak headers are attacker/provider-controlled surface. Auditing only the
    last dict value or exact title-case spelling can hide duplicate/lowercase
    leak headers.
    """
    values: list[str] = []
    wanted = name.lower()
    for key, vals in msg.headers_multi.items():
        if key.lower() == wanted:
            values.extend(str(v) for v in vals if v is not None)
    if values:
        return values
    for key, value in msg.headers.items():
        if key.lower() == wanted and value is not None:
            values.append(str(value))
    return values


# ---------------------------------------------------------------------------
# H1: Received chain has no real IP / no LAN hostname leak
# ---------------------------------------------------------------------------

def H1_received_chain_no_real_ip(msg: FetchedMessage) -> CheckResult:
    """Sender-side leak check on the Received chain.

    Threat model: a recipient reading the message headers should NOT be able
    to deduce the sender's real IP / LAN hostname from the earliest Received
    hop (the one immediately after the sender's MTA-submission).

    - **RFC1918 IPs**: only flagged in the EARLIEST hop (provider-internal
      relays often use private routing, which is normal and not a leak).
    - **LAN-hostname patterns** (`.fritz.box`, `.local`, etc.): flagged in
      ANY hop — they cannot legitimately appear in provider infrastructure
      and indicate a sender-side identity hint.
    """
    received = _all_received(msg)
    if not received:
        return CheckResult(
            "H1", "received-chain-no-leak", True, "no Received header (direct)"
        )

    # LAN hostname patterns in any hop are always suspicious
    for idx, hop in enumerate(received):
        lower = hop.lower()
        for hint in _HOSTNAME_FLAGS:
            if hint in lower:
                return CheckResult(
                    "H1", "received-chain-no-leak", False,
                    f"LAN hostname pattern {hint!r} in hop {idx}: {hop[:200]}",
                    "P0",
                )

    # RFC1918 is leak-relevant ONLY in the earliest hop (closest to sender,
    # = last entry in the file because each MTA prepends).
    earliest = received[-1]
    rfc1918 = _RFC1918.findall(earliest)
    if rfc1918:
        return CheckResult(
            "H1", "received-chain-no-leak", False,
            f"RFC1918 IP in sender-side hop: {rfc1918}", "P0",
        )

    # Count provider-internal RFC1918 hops as info-level
    internal_count = sum(
        1 for hop in received[:-1] if _RFC1918.search(hop)
    )
    note = f"{len(received)} hops"
    if internal_count:
        note += f"; {internal_count} provider-internal RFC1918 (OK)"
    return CheckResult(
        "H1", "received-chain-no-leak", True,
        f"{note}; earliest: {earliest[:140]}",
    )


# ---------------------------------------------------------------------------
# H2: Message-ID FQDN normalised
# ---------------------------------------------------------------------------

def H2_message_id_fqdn(msg: FetchedMessage) -> CheckResult:
    mid = msg.message_id
    m = re.match(r"<[^@]+@([^>]+)>", mid)
    if not m:
        return CheckResult("H2", "message-id-fqdn", False, f"no Message-ID: {mid!r}", "P0")
    fqdn = m.group(1)
    # Reallife-audit (2026-05-22): `localhost.localdomain` is a STRONG
    # cross-provider supercluster fingerprint for onionbird/TorBirdy users.
    # Per-install random `.invalid` FQDN breaks that supercluster.
    # Accept either: legacy hardcoded value (for back-compat) OR any
    # `.invalid` TLD per RFC 6761 (the new randomized form).
    if fqdn in ("localhost.localdomain", "localhost"):
        return CheckResult("H2", "message-id-fqdn", True, fqdn)
    if fqdn.endswith(".invalid"):
        return CheckResult("H2", "message-id-fqdn", True, fqdn)
    lower = fqdn.lower()
    for hint in _HOSTNAME_FLAGS:
        if hint in lower:
            return CheckResult(
                "H2", "message-id-fqdn", False,
                f"suspicious FQDN: {fqdn}", "P0",
            )
    # Heuristic: provider rewrite — public-looking domain, accept.
    if "." in fqdn:
        return CheckResult(
            "H2", "message-id-fqdn", True,
            f"provider-rewritten: {fqdn}",
        )
    return CheckResult("H2", "message-id-fqdn", False, f"bare hostname: {fqdn}", "P0")


# ---------------------------------------------------------------------------
# H3: Date UTC
# ---------------------------------------------------------------------------

def H3_date_utc(msg: FetchedMessage) -> CheckResult:
    date = str(msg.headers.get("Date", ""))
    if not date:
        return CheckResult("H3", "date-utc", False, "no Date header", "P1")
    # RFC 2822: "+0000" preferred, "GMT" and "UT" also UTC-zero
    if (date.endswith("+0000")
            or date.endswith(" -0000")
            or date.endswith(" GMT")
            or date.endswith(" UT")):
        return CheckResult("H3", "date-utc", True, date)
    return CheckResult("H3", "date-utc", False, f"non-UTC offset: {date}", "P1")


# ---------------------------------------------------------------------------
# H4: No User-Agent / X-Mailer
# ---------------------------------------------------------------------------

def H4_no_user_agent(msg: FetchedMessage) -> CheckResult:
    for header in ("User-Agent", "X-Mailer"):
        values = _header_values(msg, header)
        if values:
            return CheckResult(
                "H4", "no-user-agent", False,
                f"{header} leak: {values[0]}", "P0",
            )
    return CheckResult("H4", "no-user-agent", True, "absent")


# ---------------------------------------------------------------------------
# H5: No Content-Language
# ---------------------------------------------------------------------------

def H5_no_content_language(msg: FetchedMessage) -> CheckResult:
    cl = msg.headers.get("Content-Language")
    if cl:
        return CheckResult(
            "H5", "no-content-language", False,
            f"Content-Language leak: {cl}", "P1",
        )
    return CheckResult("H5", "no-content-language", True, "absent")


# ---------------------------------------------------------------------------
# H6: MIME-Version present and 1.0
# ---------------------------------------------------------------------------

def H6_mime_version(msg: FetchedMessage) -> CheckResult:
    v = str(msg.headers.get("MIME-Version", "")).strip()
    if v == "1.0":
        return CheckResult("H6", "mime-version", True, v, "P2")
    if not v:
        return CheckResult(
            "H6", "mime-version", False, "MIME-Version header missing", "P2",
        )
    return CheckResult(
        "H6", "mime-version", False, f"unexpected: {v}", "P2",
    )


# ---------------------------------------------------------------------------
# H7: From matches expected identity
# ---------------------------------------------------------------------------

def H7_from_matches(msg: FetchedMessage, expected_email: str = "") -> CheckResult:
    sender = str(msg.headers.get("From", ""))
    if not sender:
        return CheckResult("H7", "from-matches", False, "no From header", "P2")
    if expected_email and expected_email not in sender:
        return CheckResult(
            "H7", "from-matches", False,
            f"From {sender!r} does not contain {expected_email!r}", "P2",
        )
    return CheckResult("H7", "from-matches", True, sender)


# ---------------------------------------------------------------------------
# H8: No X-Originating-IP / similar leak headers
# ---------------------------------------------------------------------------

def H8_no_x_originating_ip(msg: FetchedMessage) -> CheckResult:
    for h in _LEAK_HEADERS:
        values = _header_values(msg, h)
        if values:
            return CheckResult(
                "H8", "no-leak-headers", False,
                f"{h}: {values[0]}", "P0",
            )
    return CheckResult("H8", "no-leak-headers", True, "absent")


# ---------------------------------------------------------------------------
# H9: Authentication-Results (informational)
# ---------------------------------------------------------------------------

def H9_authentication_results(msg: FetchedMessage) -> CheckResult:
    ar = msg.headers.get("Authentication-Results")
    return CheckResult(
        "H9", "authentication-results", True,
        str(ar)[:200] if ar else "absent",
        "info",
    )


# ---------------------------------------------------------------------------
# H10: DKIM-Signature (informational)
# ---------------------------------------------------------------------------

def H10_dkim_signature(msg: FetchedMessage) -> CheckResult:
    dkim = msg.headers.get("DKIM-Signature")
    return CheckResult(
        "H10", "dkim-signature", True,
        str(dkim)[:200] if dkim else "absent",
        "info",
    )


# ---------------------------------------------------------------------------
# H11: Return-Path matches From (no hostname suffix leak)
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"<?([^\s<>]+@[^\s<>]+)>?")


def _extract_email(value: str) -> str:
    m = _EMAIL_RE.search(value or "")
    return m.group(1).lower() if m else ""


def H11_return_path_clean(msg: FetchedMessage, expected_email: str = "") -> CheckResult:
    rp = str(msg.headers.get("Return-Path", ""))
    if not rp:
        return CheckResult("H11", "return-path-clean", True, "absent (acceptable)", "P1")
    rp_addr = _extract_email(rp)
    if expected_email:
        if rp_addr != expected_email.lower():
            return CheckResult(
                "H11", "return-path-clean", False,
                f"Return-Path {rp_addr!r} != From {expected_email!r}", "P1",
            )
    # Check for hostname-suffix leak in the local part (e.g. someone@host.lan)
    for hint in _HOSTNAME_FLAGS:
        if hint in rp_addr:
            return CheckResult(
                "H11", "return-path-clean", False,
                f"Return-Path has LAN hint {hint!r}: {rp}", "P0",
            )
    return CheckResult("H11", "return-path-clean", True, rp)


# ---------------------------------------------------------------------------
# H12: MIME boundary randomised
# ---------------------------------------------------------------------------

# Predictable TB pre-MV3 boundary pattern (timestamp-based)
_TB_TIMESTAMP_BOUNDARY = re.compile(r"------------\d{16,}")


def H12_mime_boundary_random(msg: FetchedMessage) -> CheckResult:
    """If multipart, the boundary string must look randomised (not a predictable
    TB version-stamp). Single-part messages pass this trivially."""
    ct = str(msg.headers.get("Content-Type", ""))
    boundary_m = re.search(r'boundary="?([^";\s]+)"?', ct)
    if not boundary_m:
        return CheckResult(
            "H12", "mime-boundary-random", True, "non-multipart, n/a", "info"
        )
    boundary = boundary_m.group(1)
    # Heuristic: a boundary should have at least 16 chars of entropy beyond
    # the leading dashes. TB classically used "------------" + timestamp;
    # newer versions use UUID-style. UUID-style is fine.
    if _TB_TIMESTAMP_BOUNDARY.match(boundary):
        return CheckResult(
            "H12", "mime-boundary-random", False,
            f"predictable timestamp boundary: {boundary}", "P1",
        )
    # Reasonable entropy: at least 16 alnum chars
    body = boundary.lstrip("-")
    if len(body) < 16:
        return CheckResult(
            "H12", "mime-boundary-random", False,
            f"short boundary: {boundary}", "P1",
        )
    return CheckResult("H12", "mime-boundary-random", True, boundary)


# ---------------------------------------------------------------------------
# H13: Subject roundtrip (UTF-8 / RFC 2047)
# ---------------------------------------------------------------------------

def H13_subject_roundtrip(msg: FetchedMessage, expected_substring: str = "") -> CheckResult:
    s = msg.subject
    if not s:
        return CheckResult("H13", "subject-roundtrip", False, "no Subject", "P2")
    if expected_substring and expected_substring not in s:
        return CheckResult(
            "H13", "subject-roundtrip", False,
            f"expected {expected_substring!r} not in {s!r}", "P2",
        )
    return CheckResult("H13", "subject-roundtrip", True, s)


# ---------------------------------------------------------------------------
# H14: In-Reply-To / References (for replies)
# ---------------------------------------------------------------------------

def H14_reply_refs(
    msg: FetchedMessage, expected_in_reply_to: str = ""
) -> CheckResult:
    """For a reply: In-Reply-To and References must contain the parent's
    Message-ID. For non-reply mails, just verify these headers are absent
    or empty (avoid accidental thread-correlation via stale state)."""
    irt = str(msg.headers.get("In-Reply-To", "")).strip()
    refs = str(msg.headers.get("References", "")).strip()

    if not expected_in_reply_to:
        # Not a reply scenario — both headers should be absent / empty
        if irt or refs:
            return CheckResult(
                "H14", "reply-refs", False,
                f"unexpected thread headers: In-Reply-To={irt!r} References={refs!r}",
                "P1",
            )
        return CheckResult("H14", "reply-refs", True, "absent")

    # Reply scenario — both must include expected Message-ID
    if expected_in_reply_to not in irt:
        return CheckResult(
            "H14", "reply-refs", False,
            f"In-Reply-To {irt!r} missing {expected_in_reply_to!r}", "P1",
        )
    if expected_in_reply_to not in refs:
        return CheckResult(
            "H14", "reply-refs", False,
            f"References {refs!r} missing {expected_in_reply_to!r}", "P1",
        )
    return CheckResult("H14", "reply-refs", True, f"In-Reply-To={irt}")


# ---------------------------------------------------------------------------
# H15: List-Unsubscribe etc. (informational)
# ---------------------------------------------------------------------------

def H15_list_headers(msg: FetchedMessage) -> CheckResult:
    """Provider may inject List-Unsubscribe / List-Id / List-Post for mailing
    lists. Informational only — not a leak vector for our threat model."""
    list_hdrs = [
        h for h in ("List-Unsubscribe", "List-Id", "List-Post",
                    "List-Help", "List-Subscribe", "Precedence")
        if msg.headers.get(h)
    ]
    if list_hdrs:
        return CheckResult(
            "H15", "list-headers", True,
            f"present: {','.join(list_hdrs)}", "info",
        )
    return CheckResult("H15", "list-headers", True, "absent", "info")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all(
    msg: FetchedMessage,
    *,
    expected_from: str = "",
    expected_subject: str = "",
    expected_in_reply_to: str = "",
) -> list[CheckResult]:
    return [
        H1_received_chain_no_real_ip(msg),
        H2_message_id_fqdn(msg),
        H3_date_utc(msg),
        H4_no_user_agent(msg),
        H5_no_content_language(msg),
        H6_mime_version(msg),
        H7_from_matches(msg, expected_from),
        H8_no_x_originating_ip(msg),
        H9_authentication_results(msg),
        H10_dkim_signature(msg),
        H11_return_path_clean(msg, expected_from),
        H12_mime_boundary_random(msg),
        H13_subject_roundtrip(msg, expected_subject),
        H14_reply_refs(msg, expected_in_reply_to),
        H15_list_headers(msg),
    ]


def format_report(results: list[CheckResult]) -> str:
    lines = []
    for r in results:
        mark = "✓" if r.ok else "✗"
        ev = r.evidence[:100].replace("\n", " ")
        lines.append(f"  {mark} {r.code:<4} {r.name:<28} [{r.severity:<4}] {ev}")
    return "\n".join(lines)


def summarize(results: list[CheckResult]) -> dict[str, int]:
    out = {"pass": 0, "fail_p0": 0, "fail_p1": 0, "fail_p2": 0, "info": 0}
    for r in results:
        if r.ok:
            if r.severity == "info":
                out["info"] += 1
            else:
                out["pass"] += 1
        else:
            key = {"P0": "fail_p0", "P1": "fail_p1", "P2": "fail_p2"}.get(
                r.severity, "fail_p1"
            )
            out[key] += 1
    return out
