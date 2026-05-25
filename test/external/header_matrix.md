# External-test header audit matrix

Each external send is audited against these checks. Severity:
**P0** = exploitable identity leak. **P1** = soft fingerprint. **P2** = sanity.

| Code | Check | Pass criterion | Severity |
|------|-------|----------------|----------|
| H1 | Received chain | No RFC1918 IP in any Received hop. First hop's HELO arg is `[127.0.0.1]` or a benign value | **P0** |
| H2 | Message-ID FQDN | Domain is `localhost.localdomain` OR provider-rewritten public domain. Never matches host LAN names. | **P0** |
| H3 | Date | Ends with `+0000` or `GMT` (UTC normalised by `resistFingerprinting`) | P1 |
| H4 | User-Agent / X-Mailer | Header is absent | **P0** |
| H5 | Content-Language | Header is absent | P1 |
| H6 | MIME-Version | Header is `1.0` | P2 |
| H7 | From | Matches configured identity address | P2 |
| H8 | X-Originating-IP / X-Real-IP / X-Forwarded-For / X-Sender-IP | All ABSENT | **P0** |
| H9 | Authentication-Results | Present (provider added DKIM/SPF/DMARC verdicts — informational). **CAVEAT: this header typically discloses `smtp.auth=<user>@<provider>` to every recipient. That is an inherent property of authenticated SMTP, not removable by OnionBird. For anonymity from recipients, use a pseudonymous/throwaway mailbox.** | info |
| H10 | DKIM-Signature | Provider added (informational) | info |
| H11 | Return-Path | Matches From; contains no hostname suffix | P1 |
| H12 | MIME boundary | If multipart: boundary string randomised (not predictable) | P1 |
| H13 | Subject encoding | RFC 2047 encoded for non-ASCII; round-trips correctly | P2 |
| H14 | In-Reply-To / References | On reply: matches original Message-ID exactly | P1 |
| H15 | List-Unsubscribe etc. | Provider may add (informational) | info |

## Provider-specific quirks

Document each provider's known rewrites here as we discover them.

### Disroot

- Adds `X-Disroot-Signature` (DKIM-equivalent). Acceptable, marked H10.
- Rewrites `Message-ID` to `@disroot.org` for outgoing? Verify.
- Adds `Received-SPF` for incoming. Acceptable, H9.

### Riseup

- Stripped: most identifying headers.
- TBD on first run.

### Self-hosted (OWN)

- Full control: whatever your MTA adds.
