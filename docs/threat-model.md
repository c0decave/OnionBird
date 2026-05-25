# OnionBird Threat Model

## In scope

OnionBird defends against **header-level deanonymisation** of a Thunderbird user
by an observer that has access to:

- The SMTP server log (typical mail-server-side observer)
- The full RFC 5322 message as received by the recipient
- Both of the above for multiple messages over time, for correlation

Concretely, OnionBird prevents the following leaks in outgoing mail:

| Leak | Mitigation |
|---|---|
| Real IP address visible to SMTP server | SOCKS5 routing through Tor for IMAP/SMTP/POP3 |
| DNS lookup of mail-server hostname | `network.proxy.socks_remote_dns = true` |
| `User-Agent` / `X-Mailer` header containing TB version + OS | `mailnews.headers.sendUserAgent = false` |
| `Message-ID` FQDN containing real hostname or local domain | Per-identity `mail.identity.idN.FQDN`; default strategy uses the From-address domain, with `localhost` / `localhost.localdomain` / custom modes available |
| `Date` header containing local timezone offset | UTC mode (Process-wide `privacy.resistFingerprinting` or per-compose rewrite) |
| HELO/EHLO containing local hostname or LAN IP | Per-SMTP `hello_argument = "[127.0.0.1]"` |
| Auto-config DNS probes (`autoconfig.<domain>`) | `mailnews.auto_config.fetchFromISP.v2 = false` |
| Reply-header localization (e.g. `Am %s schrieb %s:`) | `mailnews.reply_header_authorwrote = "%s"` |
| IPv6 leaks via dual-stack lookups | `network.dns.disableIPv6 = true` |
| Remote-content tracking pixels in HTML mail | Plaintext default + remote-image block |
| ECH (Encrypted Client Hello) / DNS HTTPS-RR side-channel | `network.dns.echconfig.enabled = false` + `use_https_rr_as_altsvc = false` (closes the out-of-band DNS path that SOCKS-remote-DNS doesn't cover) |
| DoH (DNS-over-HTTPS) parallel resolver leak | `network.trr.mode = 5` plus `trr.uri / custom_uri / bootstrapAddress / confirmationNS` cleared |

## Out of scope

OnionBird **does not** protect against:

1. **OS-level leaks outside the Thunderbird process.** Other applications
   (system spell-check daemons, indexing services, MAPI bridges) may read
   message content. NTP daemons reveal clock skew. Swap/hibernate files may
   contain plaintext. **Use Tails or Whonix for this assurance level.**

2. **Network-correlation attacks.** If an observer can see when you use Tor
   (e.g. from a WLAN access log) and when a message arrives at a destination,
   timing correlation can deanonymise you regardless of header hygiene. The
   Harvard bomb-hoax case (2013, Eldo Kim) is the canonical example — the
   suspect was caught by access-point logs, not by mail headers.

3. **Tor-relay-level attacks.** Compromised guard or exit nodes, traffic
   confirmation attacks, and similar adversaries with capabilities against
   the Tor network itself are not in OnionBird's threat model.

4. **OpenPGP cryptographic metadata.** Key creation timestamps,
   signature-creation timestamps (RFC 9580 mandatory subpackets), and
   recipient identifiers in encrypted messages can leak identity.
   OnionBird does NOT currently rewrite OpenPGP metadata; users must
   handle OpenPGP anonymity settings outside the addon.

5. **Pre-startup leaks.** DNS probes that fire between TB launch and addon
   load are not blocked by the addon. The **companion `user.js`** mitigates
   this for known leak vectors but is best-effort. For deterministic
   pre-startup protection, run TB inside a Tor-isolated network namespace
   (Tails, Whonix).

6. **Recipient-side leaks.** What the recipient does with your message
   (forwarding, archiving, web-mail rendering) is outside OnionBird's
   control.

7. **Server-added `Authentication-Results: ... smtp.auth=<your-mailbox>@<provider>`
   header.** This is added by the provider's MTA on outbound mail; it
   discloses the authenticated mailbox to every recipient. It cannot
   be stripped client-side because the addon never sees the bytes
   the recipient eventually receives — the provider rewrites them
   downstream of the SMTP session. **Use a pseudonymous / throwaway
   mailbox for anonymity-critical correspondence.** (Inherent
   property of authenticated SMTP; see README "Inherent limits"
   bullet 1.)

8. **Calendar (iTIP / iMIP) invitations.** The addon does NOT
   intercept TB's compose path to sanitise outbound calendar
   attachments. `PRODID:` (TB version + locale), `DTSTAMP:` (real
   wall-clock at compose time), and `UID@hostname` (real machine
   hostname) all leak in the attached `.ics`. OnionBird targets the
   mail-header surface; calendar metadata is acknowledged as a
   real gap and is tracked in `docs/follow-up.md` (Roadmap).
   *Workaround for now:* don't send calendar invitations from a
   privacy-critical identity, or strip the attachment manually.

9. **`Content-Language` header.** TB emits a `Content-Language`
   header derived from the user's spell-checker locale for HTML
   messages. The addon does NOT currently strip this header — an
   earlier version of this document claimed a "compose-time strip"
   that was never implemented; the row was moved here when
   `git grep Content-Language addon/` returned zero matches.
   *Workaround:* compose in plaintext (the addon already prefers
   plaintext rendering), which avoids the `Content-Language` header.

## Honest comparison to Tails/Whonix

| Property | OnionBird | Tails | Whonix |
|---|---|---|---|
| Cross-platform desktop | ✓ | live USB only | requires VM |
| User-installable, no root | ✓ | n/a | n/a |
| Defends against SMTP-server-side leaks | ✓ | ✓ | ✓ |
| Defends against OS-level leaks | ✗ | ✓ | ✓ |
| Defends against network correlation | ✗ | partial | partial |
| Defends against pre-startup leaks | partial | ✓ | ✓ |

**If you need high-assurance anonymity, use Tails or Whonix.**

## Verification

Most claims in the "In scope" table correspond to integration tests that
assert on captured-mail headers from inside the Podman / Docker test
environment, plus the external suite against real providers (e.g.
undisclose.de). The major remaining gap is **event-driven mid-session
resolver changes** (NetworkManager / VPN flipping `/etc/resolv.conf`
after startup). The canary now re-runs periodically while hardening is
active, but it still does not subscribe to OS network-link events. See
`docs/follow-up.md` F-004.

Specifically NOT covered by current tests:
- Date header determinism under non-UTC timezones (only verified under
  `TZ=UTC` containers).
- Content-Language header absence (not asserted in H-checks).
- Auto-config probe paths beyond URL-clearing (no test exercises the
  full TB account-wizard flow under hardening).
- Reply-header localisation across non-en locales.
- MIME boundary randomness (audit checks "non-multipart, n/a" only).
- IPv6 dual-stack SMTP send (defended via `network.dns.disableIPv6`,
  not yet end-to-end tested).
See `test/integration/test_feature_*.py`.
