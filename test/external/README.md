# External tests — real accounts, real Tor

These tests drive a real Thunderbird instance against real mail providers
through real Tor. They are **NOT** part of the default `make test` run.

## Threat / risk

External tests reveal information to:
- Provider operators (you're sending mail from a TB-with-OnionBird profile)
- Tor exit operators (for non-onion providers)
- Anyone who can read the Internet-side traffic

Use **dedicated throwaway accounts** for every external test session.
Do NOT reuse personal accounts. Burn them after.

## Prerequisites

1. **Real Tor on the host**, listening on `127.0.0.1:9050` (system Tor) or
   `127.0.0.1:9150` (Tor Browser).

2. **A Thunderbird binary on the host** (NOT in the test container). The
   external tests connect to a Marionette running on the host's TB:
   ```sh
   thunderbird --marionette --remote-allow-system-access --profile /tmp/onionbird-external
   ```

3. **Credentials in environment variables** — see `secrets.env.example`.

4. **A receiving mailbox you control** (IMAP-fetchable). With no
   `T0R_RECV_USER`, tests use send-to-self. If you set `T0R_RECV_USER`,
   it must describe a distinct mailbox: `T0R_RECV_EMAIL` must be a valid
   recipient address different from the sender, and `T0R_RECV_PASS` must
   be non-empty.

5. **The test pod for DNS/smtp-trap assertions.** Run `make
   COMPOSE_ENGINE=docker test-up` before the DNS-leak scenarios so
   `dns-trap`, `smtp-trap`, and the onion fixture are available.

## Provider matrix

| Code | Provider | SMTP | IMAP | Notes |
|------|----------|------|------|-------|
| `DISROOT` | Disroot.org | `disroot...onion:25` or `disroot.org:587` STARTTLS | onion or clearnet 993 SSL | Tor-friendly, free, onion endpoint |
| `RISEUP` | Riseup.net | `mail.riseup.net:587` STARTTLS | `mail.riseup.net:993` SSL | Invite-only |
| `OWN` | Self-hosted | Your config | Your config | Best capture control |
| `UNDISCLOSE` | Undisclose.de | `mail.undisclose.de:587` STARTTLS | `mail.undisclose.de:993` SSL | Used by the current external audit set |
| `POSTEO` | Posteo.de | `posteo.de:587` STARTTLS | `posteo.de:993` SSL | Paid 1€/mo, no onion |

## Run a session

```sh
# 1. Copy and fill secrets
cp test/external/secrets.env.example test/external/secrets.env
chmod 600 test/external/secrets.env
$EDITOR test/external/secrets.env

# 2. Start the test pod for dns-trap/smtp-trap based scenarios
make COMPOSE_ENGINE=docker test-up

# 3. Start Tor on host (system tor, or `tor`, or Tor Browser)
sudo systemctl start tor      # or: tor &

# 4. Start TB with marionette
/path/to/thunderbird --marionette --remote-allow-system-access \
    --profile /tmp/onionbird-external --no-remote &

# 5. Wait for TB to be up, then run external tests
set -a; source test/external/secrets.env; set +a
pytest test/external/ -v --provider=DISROOT
```

Provider selection is `T0R_TEST_PROVIDER` by default and can be
overridden with `--provider=DISROOT`, `--provider=RISEUP`,
`--provider=UNDISCLOSE`, `--provider=POSTEO`, or `--provider=OWN`.

## What gets verified

For each sent mail, the IMAP-fetched copy is audited against the
header matrix in `test/external/header_matrix.md`. Test failures
indicate either a OnionBird regression OR a provider-side rewrite
that needs documenting.

DNS-leak tests also check the local `dns-trap` log. Onion SMTP tests
must first capture a real message in `smtp-trap`; they no longer pass
just because no DNS query was observed.

## Cost / time

Each scenario sends 1–6 mails. Tor latency ~1–10s per send. Full
provider sweep is ~30–60s when nothing's wrong. Account-creation
overhead is one-time.
