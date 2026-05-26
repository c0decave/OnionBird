# OnionBird

**Languages:** **English** · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **BETA — leak-tight on Tor-DNS-aware OS in our test environment; no production user base yet. Read [the prerequisites](#before-you-install) before installing.**

> Read [the threat model](docs/threat-model.md) and [the follow-up
> list](docs/follow-up.md) before trusting it for anonymity-critical use.

OnionBird is a Thunderbird add-on that routes IMAP/SMTP through a local
Tor proxy and strips or normalises message headers historically used to
deanonymise senders. Supports Thunderbird **128+** (manifest
`strict_min_version: 128.0`); primary integration target is the
**Thunderbird 140 ESR** line. Intended as the modern successor to the
unmaintained TorBirdy extension (last release v0.2.6 in 2018, killed
by the removal of Legacy XUL in TB 78).

Current add-on version: **0.1.4**.

---

## 100% Privacy & Security Policy

OnionBird's project mandate is binary: **every observable code path that
leaks user identity, real IP, hostname, locale, timezone, or the fact
that the user is hardening their mail is considered a P0 defect and
blocks release.** "Good enough", "usually works", or "almost no leak"
are not acceptable outcomes.

Concretely this means:

- **Fail closed by default.** `network.proxy.failover_direct = false`
  is forced — if the configured Tor proxy is unreachable, the send
  fails. The addon NEVER silently downgrades to clearnet.
- **DNS through Tor only.** `network.proxy.socks_remote_dns = true`,
  `network.trr.mode = 5` (no parallel DoH), `network.dns.disablePrefetch
  = true`. Verified empirically: zero DNS queries reach the local
  resolver during real Tor-routed sends.
- **OCSP off.** Revocation checks would otherwise fire a clearnet HTTP
  request to the CA on every TLS handshake.
- **No update phone-home.** App + extensions + GMP-manager URLs cleared.
- **No telemetry, no Safebrowsing, no captive-portal probes, no remote
  content rendering.**
- **No WebRTC, no geolocation, no DNS-prefetch, no predictor.**
- **Mid-session protection.** Prefs are re-asserted on every TB startup
  and periodically while hardening is active. If a third party flips a
  hardened pref, the addon repairs it without clobbering the detected
  SOCKS endpoint.
- **Hardening is reversible.** Snapshot taken before first enable,
  restorable via the Options page Disable button or `disable-hardening`
  message.
- **Self-test canary** at startup and during active hardening compares
  SOCKS5-RESOLVE (3 stream-isolated Tor circuits) against the full
  system-resolver answer set. Every public system IP must either be
  seen through Tor or PTR-confirmed over Tor as the exact canary host
  or end in `.<canary-host>`; a bare registry suffix like `co.uk`
  would never satisfy the match because the rule is exact-host-or-
  leading-dot, not Public-Suffix-List awareness (operator must
  therefore configure a full FQDN as the canary anchor, never a
  registry suffix).
- **Privacy-safe diagnostics.** Options-page command logs and
  background console messages summarize counts, masked IPs, and error
  classes instead of raw canary IPs, PTR names, account origins, SMTP
  hostnames, or Message-ID domains.
- **Pref-write allowlist** in the experiment API. The addon's parent-
  process surface cannot write arbitrary prefs (`browser.startup.*`,
  `devtools.*`, etc. are denied) — limits blast radius of any future
  message-handler regression.

**Inherent limits — OnionBird CANNOT fix these:**

1. **`Authentication-Results: ... smtp.auth=<your-mailbox>@<provider>`**
   is added by the provider's MTA on outbound mail. It discloses your
   authenticated mailbox to every recipient. This is a property of
   authenticated SMTP and is impossible to remove from the addon side.
   *Workaround:* use a throwaway / pseudonymous mailbox for sensitive
   correspondence.
2. **The Tor exit IP appears in the recipient's `Received:` chain.**
   Provider MTAs do reverse-DNS on the connecting IP and emit names like
   `tor-exit-107.digitalcourage.de`. The recipient learns "this user
   sent via Tor". Inherent to the SMTP transport.
3. **OS-level leaks** — hostname disclosure from other apps, NTP
   leaks, swap files, filesystem timestamps. Stack OnionBird with a
   Tor-hardened OS to close these — see
   [the Tails / Whonix stacking note](#stack-it-with-a-tor-hardened-os).
4. **Network-correlation** — observers of both ends of a Tor circuit.
   Not defeated by header hygiene.
5. **TB UI locale is forced to en-US when hardening is enabled.**
   `privacy.resistFingerprinting=true` is in `HARDENING_PREFS` for
   network-fingerprint reasons (it forces UTC `Date`, suppresses
   navigator-locale exposure, and pins a handful of headers).
   Mozilla unfortunately ties UI-locale spoofing to the same pref —
   so a German user's TB switches to English immediately on enable.
   This is a known cross-cutting side-effect of the global
   `resistFingerprinting` switch; the proper fix is per-feature
   replacement (UTC `Date` hook + per-compose locale-rewrite) and is
   tracked in `docs/follow-up.md` F-018. *Workaround for now:*
   accept the en-US UI, OR disable hardening when reading mail in
   the native UI locale is required (you lose the network-
   fingerprint defence in that window).

Anything not in those five buckets is **in scope** for the policy. File
a P0 bug if you find a counter-example.

---

## Tor-mail landscape — same-layer alternatives

OnionBird sits at the **mail-client layer** — it hardens Thunderbird's
own network and header behavior. Tails and Whonix operate one layer
below (the operating system); they belong in the [defense-in-depth
stack](#stack-it-with-a-tor-hardened-os) below, not in a feature
comparison with a single MUA addon.

At the mail-client layer, OnionBird's nearest neighbors are:

| Project | Layer | Tor routing | Header hygiene | Maintained? |
|---|---|---|---|---|
| **OnionBird** (this) | Thunderbird add-on | yes (SOCKS5 + remoteDNS) | yes (all known historical leak vectors closed; canary detects new ones) | yes (2026-) |
| TorBirdy | TB extension | yes | yes (historical) | **no** — last release 2018, broken since TB 78 (Legacy XUL removal) |
| Tor Mail (legacy, `.onion`) | webmail provider on .onion | n/a | n/a | shut down 2013 (Freedom Hosting bust) |
| Mailpile (Tor mode) | local mail client | optional | partial | last release 2020 (effectively abandoned) |
| ProtonMail via Tor | webmail | yes (`.onion` v3) | provider-controlled headers, no client-side hygiene | yes (browser-only) |
| Riseup / Disroot / Cock.li | mail providers w/ .onion | yes (you route via Tor) | client-dependent | yes (depends on the MUA you point at them) |

For a feature-by-feature comparison with the project OnionBird sets out
to succeed — TorBirdy — see [the next section](#onionbird-vs-torbirdy--feature-by-feature).

### Stack it with a Tor-hardened OS

OnionBird is intentionally *not* an operating system. To close
OS-level leaks (other apps' DNS, NTP timestamps, hostname disclosure
from non-mail processes, swap files, filesystem mtimes) you should run
OnionBird **inside** a Tor-hardened OS:

- **[Tails](https://tails.net/)** — Debian-based live system that
  forces *all* network traffic through Tor and runs from a USB stick
  with optional persistence. Use Thunderbird from Tails' persistent
  storage with OnionBird installed; you get mail-client hardening +
  OS-wide routing in one stack.
- **[Whonix](https://www.whonix.org/)** — two VMs (Gateway + Workstation)
  where the Gateway transparently torifies the Workstation. Install
  Thunderbird + OnionBird in the Workstation; Whonix handles OS-level
  isolation, OnionBird handles the mail-specific fingerprinting
  vectors Whonix can't see.

The two layers are complementary: an OS can't strip a `Message-ID:
<uuid@localhost.localdomain>` from a mail body, and an addon can't
prevent a system NTP daemon from leaking the host's real time. Use
both.

---

## OnionBird vs TorBirdy — feature-by-feature

TorBirdy was the gold standard from ~2012–2018 and is still cited as
the reference Tor-mail addon. It hasn't shipped since 2018 and is
**incompatible with Thunderbird 78 and later** (Mozilla removed the
Legacy XUL extension surface TorBirdy depended on). The table below is
deliberately honest about where OnionBird improves on TorBirdy, where
the two are equivalent, and where TorBirdy did things OnionBird
hasn't reimplemented (mostly because the underlying TB code has
changed and the fix is no longer needed).

### Where OnionBird is materially better

| Feature | TorBirdy | OnionBird |
|---|---|---|
| **Compatible with current Thunderbird** | broken since TB 78 (2020) — Legacy XUL gone | yes, targets TB 128+ / 140 ESR via WebExtension + Experiments API |
| **Active maintenance** | abandoned 2018 | active 2026- |
| **Continuous leak canary** | none — set prefs and pray | runs at startup and every 10 minutes, 3 stream-isolated SOCKS5-RESOLVE circuits cross-checked against system resolver + PTR-via-Tor verification |
| **PTR-via-Tor verification** | none | each divergent system IP must PTR-resolve via Tor to the exact canary host or end in `.<canary-host>`; operator must configure a full FQDN as the canary anchor (a registry suffix like `co.uk` would never produce a valid match because the rule is suffix-match-with-leading-dot, not Public-Suffix-List parsing) |
| **Message-ID FQDN strategy** | hard-coded `localhost.localdomain` — every TorBirdy user shared the same supercluster fingerprint | 4 modes: `from_domain` (default, blends with normal provider users), `localhost`, `localhost.localdomain` (TorBirdy-compatible), or `custom`. Per-install random `m<hex>.invalid` fallback when no usable domain |
| **Stream-isolation per probe** | n/a | each canary circuit uses a fresh crypto-RNG SOCKS5 isolation token; user-traffic SMTP/IMAP also routed through isolation |
| **DoH (DNS-over-HTTPS) suppression** | pre-DoH era — not addressed | `network.trr.mode=5` plus `trr.uri / custom_uri / bootstrapAddress / confirmationNS` cleared |
| **ECH (Encrypted Client Hello) suppression** | pre-ECH era — not addressed | `network.dns.echconfig.enabled=false`, `use_https_rr_as_altsvc=false` — closes the out-of-band DNS path SOCKS-remote-DNS doesn't cover |
| **WebRTC defense-in-depth** | disabled `media.peerconnection.enabled` | same + `ice.no_host`, `default_address_only`, `proxy_only_if_behind_proxy` pinned so a future re-enable can't leak host candidates |
| **Crash-reporter URL nuked** | partial (disabled the reporter) | reporter disabled + `breakpad.reportURL` + `toolkit.crashreporter.submitURL` cleared, `include_extensions=false` |
| **Pref-write allowlist** | no such concept | the addon's privileged Experiments API surface cannot write arbitrary prefs — `browser.startup.*`, `devtools.*`, `xpinstall.signatures.required` etc. denied at the gate |
| **Empirical end-to-end test suite** | manual smoke testing | container-driven integration suite (currently 177+ tests, with the exact count auto-injected by CI from `pytest --co -q`; new audit findings keep landing as `xfail(strict=True)` rather than being deleted) + 6 real-Tor scenarios against `undisclose.de` with byte-level header audit (H1–H15) on captured mail |
| **Mid-session re-assertion** | static at startup | re-applied on every account-create / account-modify event plus periodic (10 min); broken hardening pref is repaired without clobbering the detected SOCKS endpoint |
| **Per-install random fallback** | shared `localhost.localdomain` | persistent `m<10hex>.invalid` per installation — different installs have different Message-ID FQDNs |
| **Default-identity branch** | per-identity only | also writes `mail.identity.default.*` so a new identity created after enable can't inherit the host's real FQDN |
| **Application-layer send-block on leak** | none — relied entirely on `failover_direct=false` at the proxy layer | `compose.onBeforeSend` listener cancels outgoing sends with a visible compose-window notification when the canary's last verdict is anything other than `clean`; works for slow-developing DNS poisoning that doesn't trip the transport-layer safety net |
| **UI locales shipped** | EN + a handful of community translations, no recent update | 30 locale bundles for the bulk of the UI — Western Latin/Slavic/Turkic (EN, DE, FR, PT, ES, PL, UK, RU, BE, TR) · RTL Arabic-script (FA, AR, HE, KU, UR, PS, UG) · South Asian (HI, BN) · East Asian (ZH-CN, BO) · SE Asian (VI, TH, MY, ID) · African (AF, SW, AM, TI) · Caucasian (KA). PS/UG/BO/MY/BN/SW/AM/TI/KA target repression/censorship hotspots; AI-translated pending native-speaker PR review. Newly-added feature strings (e.g. F-168 SOCKS-override UI) ship hand-translated in EN + DE and English-fallback in the other 28 until the next translation pass — `browser.i18n.getMessage` returns the English text on the non-translated locales so the UI stays functional |

### Where they are equivalent

Both TorBirdy (when it worked) and OnionBird do the following the
same way, because there is only one correct answer:

- **SOCKS5 proxy** with `network.proxy.type=1`, `socks_version=5`
- **`socks_remote_dns=true`** so DNS resolution happens at the Tor
  exit, not on the user's machine
- **`failover_direct=false`** so a broken proxy fails the send
  instead of falling back to clearnet
- **HELO/EHLO override to `[127.0.0.1]`** so SMTP doesn't leak the
  real hostname
- **User-Agent / X-Mailer suppression**
  (`mailnews.headers.sendUserAgent=false`)
- **`intl.accept_languages=en-US, en`** so Accept-Language headers
  don't fingerprint the user's locale
- **Telemetry / health-report / Safebrowsing / captive-portal probes**
  disabled
- **Address-book auto-collect** off so Tor-routed recipients don't
  land in a durable local "Collected Addresses" list
- **Update-phone-home URLs cleared** (app, extensions, GMP-manager)
- **IPv6 disabled** by default (TB's SOCKS handling has had IPv6
  edge cases)

### Where TorBirdy did things OnionBird intentionally does NOT do

TorBirdy was for an older Thunderbird. Some of its prefs targeted
features that no longer exist or have been replaced:

- **Enigmail debug log scrubbing** — Enigmail has not been
  loadable since TB 78 (July 2020), which removed the legacy XUL
  addon format Enigmail was built on; its maintainer co-built the
  RNP-based native OpenPGP that ships with TB 78+ to replace it,
  and no MailExtension port exists. The Enigmail v2.x archive will
  still install on TB ≤ 68, but those releases stopped receiving
  security updates in 2020 and are not defensible in a Tor threat
  model. OnionBird targets TB 128+, so this scrubbing is moot.
- **Lightning calendar disable** — Lightning is built-in and
  always-on in modern TB; disabling it via prefs no longer works.
  OnionBird's gap on calendar leaks (iTIP/iMIP, `PRODID`,
  `DTSTAMP`, `UID@hostname`) is acknowledged and tracked in the
  Roadmap.
- **HTTPS-Everywhere-style URL rewriting** — was a TorBirdy
  sibling, never in scope for the addon itself; modern web uses
  HTTPS by default.

### Where both still fall short

Honest about open ground:

- **iTIP / iMIP calendar invitations** leak `PRODID:`,
  `DTSTAMP:`, `UID@hostname` — neither TorBirdy nor OnionBird
  intercepts the compose path to sanitise them. Tracked in
  OnionBird's roadmap.
- **OpenPGP signature creation time** (when signing) reveals the
  local clock and can correlate sends. Neither addon addresses it.
- **`Authentication-Results` from the provider's MTA** reveals
  the authenticated mailbox to every recipient. Inherent to
  authenticated SMTP, unfixable from the addon side. Workaround:
  use a throwaway / pseudonymous mailbox.
- **Tor exit IP in `Received:` chain** — the recipient learns
  "this user sent via Tor". Inherent to SMTP transport.

### TL;DR

If you trusted TorBirdy in 2018, you should consider OnionBird now:
the same threat model, the same pref-hardening philosophy, but
running on a Thunderbird that has moved through eight major
versions since TorBirdy died. Plus empirical canary verification,
modern DoH/ECH coverage, and a pref-write allowlist that bounds
the blast radius of any future regression.

If you ran TorBirdy *and* a Tor-hardened OS, keep doing that with
OnionBird — see [stacking with Tails / Whonix](#stack-it-with-a-tor-hardened-os)
above.

---

## Before you install

The addon hardens what runs **inside** Thunderbird. For 100% Tor coverage
the **OS resolver** must also route through Tor. Pick the path that
matches your environment:

- **Tails / Whonix workstation** — system DNS is already Tor. Install
  the `.xpi`, you're done.
- **Stock Linux with system Tor** — add `DNSPort 5353` to your
  `/etc/tor/torrc` and ensure `/etc/resolv.conf` reaches it (a local
  `dnsmasq`/`unbound` forwarding to `127.0.0.1:5353` is the standard
  pattern).
- **Tor Browser bundle only** — Tor listens on `9150` not `9050`; the
  add-on probes existing prefs plus both common local ports before
  writing proxy prefs, and later re-asserts preserve that endpoint.
- **Remote Tor/Whonix SOCKS** — use an IP literal such as
  `10.152.152.10:9050`, not a hostname. The add-on intentionally
  ignores hostname-valued SOCKS endpoints because resolving the proxy
  hostname itself would be a local DNS lookup before Tor is reached.
- **Stock desktop without system DNS via Tor** — install at your own
  risk. The canary will flag the configuration on the Options page and
  in the browser console.

---

## What it does today

- Routes IMAP/SMTP through a local SOCKS5 proxy (default `127.0.0.1:9050`,
  configurable) with `socks_remote_dns=true` and `failover_direct=false`.
  Enable probes an existing SOCKS pref, system Tor `9050`, and Tor
  Browser `9150`; startup/periodic re-assert preserves the current
  endpoint only when it is loopback or an IP literal.
- Normalises identifying headers on outbound mail: `User-Agent` /
  `X-Mailer` suppressed, `Message-ID` FQDN configurable (default = your
  From-domain), SMTP `HELO`/`EHLO` rewritten to `[127.0.0.1]`, `Date`
  UTC via `privacy.resistFingerprinting`, no `format=flowed`.
- Defense-in-depth pref hardening: TRR=5, OCSP off, no WebRTC, no
  DNS prefetch, no predictor, no update phone-home, no telemetry, no
  Safebrowsing, no captive-portal probes, no remote content rendering.
- **SOCKS5-RESOLVE-vs-system-DNS canary** at startup and periodically:
  compares all public system IPs against stream-isolated Tor circuits,
  then uses PTR-via-Tor only as a strict exact-host/subdomain fallback.
- Privacy-safe logging: command logs and background diagnostics redact
  raw canary IP/PTR data and account identifiers by default.
- **Tor test mode** on the Options page verifies that a local Tor SOCKS
  endpoint is reachable without sending mail, changing prefs, or using
  system DNS for the target-host probe.
- Options page supports system/light/dark theme, ships in **21 UI
  locales** (EN, DE, ES, FR, PT, PL, UK, RU, BE, TR, FA, AR, HE, KU,
  UR, HI, ZH-CN, VI, TH, ID, AF), and includes built-in Help with
  TL;DR plus Nerd mode for scope, limits, TorBirdy compatibility, and
  the required Experiments API boundary.
- Auto-enables on first install. **Disable button** in the Options page
  restores the snapshot.
- Only **onion + loopback** SMTP servers are hardened by default
  (B-003): your existing clearnet accounts keep working.
- Companion `user.js` for pre-startup hardening + a script that
  enumerates your existing accounts in `prefs.js` and emits matching
  per-server lines.

---

## Quick start

```sh
# Build the .xpi (MV2, canonical)
make build

# Optional: parallel MV3 build for forward-compat smoke
make build-mv3

# Bring up the test pod (Tor+DNSPort + aiosmtpd + DNS-forwarder +
# Xvfb+TB + runner)
make COMPOSE_ENGINE=docker test-up

# Run the integration suite (current count: see `pytest --co -q | wc -l`; zero skipped in the standard pod env)
make COMPOSE_ENGINE=docker test-integration

# Tear down
make COMPOSE_ENGINE=docker test-down
```

# Or pick a provider explicitly for a focused run
set -a; source test/external/secrets.env; set +a
PYTHONPATH=test pytest -v -s test/external/ --provider=POSTEO
```

`T0R_TEST_PROVIDER` selects the default provider for `make
test-external`. `--provider=...` overrides it for direct pytest runs.
If `T0R_RECV_USER` is set, the receiver must be a distinct mailbox:
`T0R_RECV_EMAIL` has to be a valid recipient address different from the
sender, and `T0R_RECV_PASS` must be non-empty.

### Signing for ATN

See [docs/atn-signing.md](docs/atn-signing.md) — requires Mozilla developer
credentials.

---

## Architecture

OnionBird is a hybrid: a MailExtension background script provides the
public API surface (options page, on-install auto-enable handler,
message bus for enable/disable, periodic self-test), while an
Experiments API module runs in the parent process and exposes
`Services.prefs`, `MailServices.outgoingServer`, `MailServices.accounts`,
raw SOCKS5 RESOLVE / RESOLVE_PTR, and `nsIDNSService.clearCache`
manipulation. The two halves communicate through the addon's custom
`browser.onionbird.*` namespace.

See [docs/architecture.md](docs/architecture.md) for a diagram and
[docs/audit-2026-05-21-bug-report.md](docs/audit-2026-05-21-bug-report.md)
for the audit findings that shaped the current design.

---

## Roadmap / known limitations

See [docs/follow-up.md](docs/follow-up.md) for the full ranked list.
Highlights deferred to future iterations:

- Mixed-mode UI toggle for users who explicitly want to harden every
  SMTP server, not just onion/loopback servers.
- Network-link / resolver-change event hook in addition to the periodic
  canary.
- Multi-circuit PTR retry to reduce false positives if a Tor exit
  refuses PTR.
- Saved-login tagging for add-on-created Tor accounts; disable already
  offers a scrub path for detected onion/loopback mail-server logins.
- First-run wizard around the current SOCKS auto-probe.
- Bridges / pluggable-transports for censored ISPs.
- Tor control-port integration (NEWNYM per send).
- Packaged cross-platform installer UX beyond the current script.
- Native-speaker review of the newly added repression/censorship-
  hotspot locales (`my`, `ug`, `bo`, `am`, `ti`, `ps`, `bn`, `ka`,
  `sw`) — currently AI-translated; PRs from native speakers tightening
  terminology, idiom, and any security-critical wording are
  prioritised. `prs` (Dari) was deliberately left out because `fa` is
  close enough for an MVP; a separate `prs` locale is welcome if a
  contributor wants to differentiate the Afghan Persian wording.

---

## License

MPL-2.0. See [LICENSE](LICENSE) for the full text.

This software is provided AS IS without warranty of any kind. The
authors are not liable for any deanonymisation or other harm arising
from its use. See LICENSE for the full disclaimer.
