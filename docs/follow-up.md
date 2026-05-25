# Deferred Findings — 5-Agent Review (2026-05-22)

> **Looking up an audit ID in code (B-NNN / F-NNN / P0-T3-X / Round-4
> P#-X / I-X)?** Run `git grep -nE '\b(B|F)-[0-9]{3}\b|P[0-3]-T[0-9]-[0-9]|Round-4 P[0-9]|I-[0-9]'`
> against the addon source to find the call site, then look the
> finding up in *this file* for full context. The old separate
> `docs/audit-ids.md` glossary was deleted in the U-077 fix because
> 4 of its 7 mappings disagreed with this file — having a single
> source of truth (this file) and `git grep` is strictly better than
> two parallel glossaries that can drift.

---


Five independent code-review subagents inspected commits `8f2dc51..HEAD`
(the dns-leak-fix series + canary + cross-account + MV3 + B-011). Items
that were applied in the same session are NOT listed here — see git log.
This file is the consolidated **deferred** list, ordered by severity.

Each entry: source agent, severity per agent, one-line description,
status (`open` / `partial` / `policy`), pointer.

## P0 — leak path or high-impact UX trap

| # | Source | Title | Status | Pointer |
|---|---|---|---|---|
| F-001 | agent#3 P0-1 | TCPSocket clearnet pre-resolve path closed in tests, not at runtime in addon for users without Tor-DNS-aware OS. README now gates installation on system DNS configuration, but no fail-loud runtime check. | partial | enable-hardening now runs the canary and returns `ok=false`/logs loudly on leak or inconclusive self-test; a profile-level hard block can still be added. |
| F-002 | agent#3 P0-2 | New SMTP servers added after enable-hardening are NOT auto-hardened. No `MailServices.accounts` observer registered. | fixed | account create/update/delete runtime events now trigger immediate re-assert; the 60s timer remains as fallback. |
| F-003 | agent#3 P0-3 | Login credentials stored in `Services.logins` survive `disable-hardening`. Other addons / forensic recovery can read Tor-mode creds in clearnet mode. | partial | disable now audits/removes onion/loopback mail-server saved logins without returning usernames; explicit login tagging for addon-created accounts is still future. |
| F-004 | agent#3 P0-4 | Self-test runs once at startup. NetworkManager / VPN / DHCP that flips `/etc/resolv.conf` mid-session is not detected. | partial | fixed by 10min active-mode canary timer; still could add `nsINetworkLinkService` event trigger later. |
| F-005 | agent#3 P0-5 | `install-user-js.sh` uses bash glob `*.onion` against attacker-controlled `prefs.js` value. Onion classification can be influenced by a writable-`prefs.js` attacker. Partial fix landed (case-insensitive, port-strip, trailing-dot strip), but glob is still not literal-suffix. | fixed | strict v3-onion shape check replaced Bash pattern matching; regression covers glob chars and obsolete short onion-looking hosts. |
| F-006 | agent#4 P0-2 | Auto-enable on first install always writes `network.proxy.socks_port=9050`. Tor Browser users (9150) and Whonix workstations (`10.152.152.10:9050`) get their mail broken immediately. | partial | enable-hardening probes existing prefs, `127.0.0.1:9050`, and Tor Browser `127.0.0.1:9150` before writing; startup/periodic reassert now preserves the detected/current SOCKS endpoint; first-run wizard still open. |
| F-007 | agent#4 P0-3 | `network.trr.uri` and `network.trr.custom_uri` not in `HARDENING_PREFS` → not in snapshot → not restored deterministically. | fixed | both URIs plus bootstrap/confirmation prefs are in `HARDENING_PREFS`. |
| F-008 | agent#4 P0-4 | `install-user-js.sh` stomps existing user.js (e.g. arkenfox-style) without `.bak` backup. | fixed | first install writes `.bak-pre-OnionBird`; reinstall keeps the original backup. |
| F-009 | agent#4 P0-5 | Linux Flatpak (`~/.var/app/org.mozilla.Thunderbird/.thunderbird`) + macOS `profiles.ini`-path bug + Windows entirely missing in `install-user-js.sh::detect_profile`. | fixed | Flatpak, macOS root, and `$APPDATA/Thunderbird` roots are detected via `profiles.ini`. |
| F-010 | agent#4 P0-6 | Canary "leak suspected" badge has no UI to retry with a different anchor host or open the threat-model doc. | partial | anchor-host input added; threat-model link/help expander still open. |
| F-011 | agent#4 P0-8 | `strict_max_version: 140.*`. When TB 141 ships, addon is auto-disabled by compat check. User.js prefs remain → user thinks they're protected, runtime SOCKS+rdns is gone. | fixed | `strict_max_version` removed from MV2/MV3 manifests. |
| F-012 | agent#2 P0-2 | `test_defense_prefs_apply_via_experiment_runtime` writes prefs via `Services.prefs.setXxxPref` directly. Proves Mozilla works, not addon. | fixed | runtime test now installs the addon and waits for the real auto-enable/background/experiment path to apply the defense prefs. |
| F-013 | agent#2 P0-3 | `test_SX2_recv_mailbox_does_not_leak_dns` audits the Python IMAP client (`IMAPOverTor`, `rdns=True`), not TB's `nsImapService`. Pass-by-construction. | open | needs: drive TB to fetch the recipient inbox via Marionette + audit dns-trap. |
| F-014 | agent#2 P0-4 | `test_S9b_onion_smtp_send_leaks_no_dns` swallows all exceptions and only checks "no .onion in DNS" — passes if `send_via` throws before any socket open. | fixed | S9b now requires `send_via == "ok"` and a captured smtp-trap message before asserting no onion DNS query. |
| F-015 | agent#2 P0-5 | `recv_provider.user` (not `.email`) is used as the cross-account skip-guard. A misconfigured `T0R_RECV_*` can silently degrade to send-to-self. | fixed | `recv_provider` now fails fixture setup unless `T0R_RECV_EMAIL` is RFC-shaped, distinct from sender, and has a password. |

## P1 — should fix in next iteration

| # | Source | Title | Status |
|---|---|---|---|
| F-016 | agent#1 P1-5 | `SELF_TEST_JS` inline test JS drifts from real `socks5Resolve` (atyp=1 only vs full atyp handling). | fixed |
| F-017 | agent#3 P1-3 | `applyHardeningToAllSmtpServers(true)` (now-default after fix) does NOT auto-detect new mixed-mode setups. Add a UI toggle. | open |
| F-018 | agent#3 P1-4 | `privacy.resistFingerprinting` has cross-cutting side effects (locale spoof breaks DE/FR users). Replace with targeted prefs + compose-time Date rewrite. | open |
| F-019 | agent#3 P1-6 | MV3 fallback: if a future TB rejects `experiment_apis`, addon loses primitives silently. No user-visible warning. | partial — `test_feature_mv3_functional.py::test_mv3_addon_actually_hardens_when_installed` now fails (rather than silently passing) when the MV3 XPI install succeeds but enableHardening does not run, catching the regression in CI. User-visible runtime warning still open. |
| F-020 | agent#3 P2-1 | Compromised exit can refuse PTR → forces leak verdict → cried-wolf → user disables addon. Mitigate with multi-circuit PTR. | open |
| F-021 | agent#3 P2-2 | 2-label PTR confirmation is wrong for public suffixes (`co.uk`, `ac.jp`). | fixed — PTR must match the target host or a subdomain; default canary anchor is `torproject.org`. |
| F-022 | agent#3 P2-3 | OCSP + speculative-connect prefs not silenced. | fixed |
| F-023 | agent#3 P2-4 | `applyPrefs` reports partial failure but does NOT roll back. Comment claims "atomic" — false. | fixed |
| F-024 | agent#3 P2-5 | Canary guidance string says "inspect /etc/resolv.conf" — Linux-centric, unhelpful on Win/macOS. | fixed |
| F-025 | agent#4 P1-1 | English-only UI (no `_locales/` for de/fr/es). ATN reviewers historically nudge on this. | partial — options/help + manifest now use WebExtension i18n with EN/DE/ES; FR remains future content work. |
| F-026 | agent#4 P1-2 | `make sign` pre-flight doesn't validate ATN JWT vs AMO, doesn't diff manifest version vs live listing. | open |
| F-027 | agent#4 P1-3 | Canary auto-runs on options-page-open even before `enable-hardening`. Confuses Persona F (fresh install). | fixed |
| F-028 | agent#4 P1-5 | `permissions.default.image=2` in HARDENING_PREFS contradicts user.js (which explicitly removed it). | fixed |
| F-029 | agent#4 P1-6 | Snapshot/restore semantics: when original pref was unset, restoring as `""` creates a `user_pref` shadow that doesn't fully revert. | fixed |
| F-030 | agent#4 P1-7 | README's "Before you install" section exists but is text-only; should be a checklist UI / install-time check. | partial |
| F-031 | agent#5 P1-3..P1-7 | Test totals divergent across README/handoff/architecture diagram. README now updated; handoff still has 45/68/126 across sections. | partial |
| F-032 | agent#5 P1-6 | `docs/threat-model.md` still references `--throw-keyids` option that doesn't exist anywhere in source. | fixed |
| F-033 | agent#5 P1-7 | `docs/audit-2026-05-21-bug-report.md` has no `Status` column. Open vs Fixed B-XXX items ambiguous. | open |
| F-034 | agent#5 P1-8 | `docs/plans/2026-05-21-onionbird-implementation.md` `strict_min_version: 140.0` contradicts the shipped manifest `128.0`. | fixed — plan moved to `docs/plans/archive/` (was historical, misleading). README updated to clarify TB 128+ supported / TB 140 ESR primary target. |
| F-035 | agent#2 P1-1..P1-6 | Test quality: S9 pass-by-absence acceptance, B-011 single-line prefs.js assumption, MV3 install-smoke is pass-or-skip, CLASSIFY_JS inline duplication. | partial — `test_feature_user_agent.py`, `test_feature_message_id.py`, and `test_feature_helo.py` rewritten to drive the addon's real enableHardening chain instead of bypassing it via `Services.prefs.set*Pref`. `test_audit_fixes.py::test_pref_allowlist_is_exact_and_suffix_limited` refactored from substring-match to structural parse. MV3 covered by `test_feature_mv3_functional.py`. CLASSIFY_JS inline duplication remains. |

## P2 — polish

| # | Source | Title |
|---|---|---|
| F-036 | agent#1 P3-1 | `waitForBytes` busy-polls main thread. Use `nsIInputStreamCallback.asyncWait`. |
| F-037 | agent#1 P3-3 | `var { Ci } = globalThis.Components` at file-bottom (hoisted but fragile). [fixed — replaced with explicit `typeof Components`-guarded initialisation at `implementation.js:10`.] |
| F-038 | agent#4 P2-2 | fixed — Canary table displays masked IPs by default, with an explicit reveal toggle. |
| F-039 | agent#4 P2-3 | fixed — `install-user-js.sh` refuses install while TB is running unless `--force-running` is supplied. |
| F-040 | agent#5 P2-10 | `test_feature_dns_leak.py` file-level docstring describes pre-forwarder behavior. |
| F-041 | agent#5 P2-11 | fixed — `_leak_detected` Python mirror now cross-references `runSelfTest`; `SELF_TEST_JS` mirrors IPv4/IPv6/domain SOCKS responses. |

## Items applied in this session

For provenance (not deferred):

- Agent #1 P0-1: `announceSelfTest` race vs `onInstalled` — sequenced + gated.
- Agent #1 P1-1: IPv6 string canonicalization — added `canonicalizeIp`.
- Agent #1 P1-2: sentinel/CG-NAT/link-local — `isInconclusiveIp`.
- Agent #1 P1-3: skip self-test when hardening inactive.
- Agent #1 P1-4: install-user-js.sh `.onion:port` + case-insensitive.
- Agent #1 P1-6: dns-trap task strong refs (no silent GC).
- Agent #1 P1-7: DNSPolicy WONTFIX (Tor 0.4.9 has no such directive; network isolation suffices).
- Agent #1 P2-1: F1/F2 disposition filter (forwarded ≠ leak).
- Agent #1 P2-8: walk all system A records in `systemResolve`.
- Agent #3 P1-1: `clearDnsCache` on enable/disable.
- Agent #3 P1-2: re-assert HARDENING_PREFS on startup when active.
- Agent #3 P1-5: silence app + extensions update phone-home.
- Agent #4 P0-1: Disable button in options.html.
- Agent #4 P0-7: canary error → actionable guidance mapper.
- Agent #5 P0-1: `applyHardeningToAllSmtpServers(true)` — onion-only default.
- Agent #5 P0-2: `git rm --cached test/fixtures/onion-hostname.txt`.
- Agent #2 P0-1: renamed mislabeled `test_failed_forward_falls_back_to_nxdomain` + skip-placeholder for the real fail-closed path.
- PTR-via-Tor false-positive fix (caught empirically before the agents, applied in commit `<see git log>`).
- Full-suite isolation: `TBClient` now uninstalls add-ons it installed before closing the Marionette session, so auto-enabled hardening cannot reassert into later baseline tests.
- Deep-dive follow-up: `snapshotPrefs` now records `null` for absent user prefs instead of default values, SMTP disable cleanup skips clearnet servers, and Message-ID custom FQDN validation enforces the 63-character DNS-label limit.
- Deep-dive follow-up: PTR-via-Tor canary fallback no longer accepts shared 2-label suffixes such as `co.uk`; PTR must confirm the exact target host or a subdomain, and the default canary anchor moved to `torproject.org`.
- Deep-dive follow-up: the canary now requires every public system-resolver IP to be Tor-seen or PTR-confirmed, so a poisoned resolver cannot hide an injected IP beside one legitimate A record.
- Deep-dive follow-up: SOCKS endpoints with hostnames are ignored/rejected for Tor mode; non-loopback endpoints must be IP literals to avoid resolving the proxy hostname locally before Tor.
- Deep-dive follow-up: Options status now uses the durable hardening snapshot instead of spoofable live-pref heuristics.

## What changed in the 2026-05-23 honest-audit follow-up

The four-agent code review that landed this date drove the following
fixes. See git log for the per-bundle commits; the bundles in
chronological order:

- **Telemetry + IMAP-client-info moved into runtime hardening.**
  `toolkit.telemetry.*` (9 prefs), `datareporting.healthreport.uploadEnabled`,
  `datareporting.policy.dataSubmissionEnabled`, `mail.imap.use_client_info`
  and `mail.server.default.send_client_info` were previously only in
  `user-js/onionbird-user.js` — so addon-only installs leaked telemetry.
  Now they live in `HARDENING_PREFS` and re-assert at runtime.
  `HARDENING_PREFS` entry count: 99 → 110.
- **DNS-trap fail-closed test un-skipped.** New `dns-trap-blackhole`
  sidecar compose service + two new tests at
  `test_feature_dns_forward.py` close the previously-skipped P0 gap.
  Integration suite went from `148 passed, 1 skipped` to
  `160 passed, 0 skipped` over the session.
- **Application-layer send-block.** New `compose.onBeforeSend`
  listener in `addon/background.js` cancels outgoing sends when the
  canary's last verdict was `leak_detected`, persisted in
  `storage.local` under key `onionbird.leakVerdict`. Previously, a
  leak verdict only logged a warning — the fail-closed guarantee
  relied entirely on Mozilla honoring `network.proxy.failover_direct`
  at the transport layer.
- **Clearnet SMTP DNS-leak coverage** added at
  `test/integration/test_feature_clearnet_smtp.py` — proves the 100%
  Tor promise holds for users with clearnet mail providers (Gmail,
  Outlook, corporate Exchange), not only onion mailboxes.
- **Tautological tests replaced.** UA / Message-ID / HELO test files
  now install the addon and drive enableHardening end-to-end instead
  of bypassing the addon entirely via `Services.prefs.set*Pref`.
- **MV3 functional test** added — fails (rather than silently passes
  via skip) when MV3 install succeeds but the addon does not run.
- **Reinstall test** added — covers the `onInstalled(reason="install")`
  re-enable path that was previously source-grep only.
- **Manifest equivalence checks** in `scripts/build-xpi.sh` widened
  from `version + gecko.id` to `permissions + experiment_apis +
  options_ui + background.scripts`.
- **`compose` permission** added to MV2 + MV3 manifests (required
  for the new send-block listener).
- **License relicensed** from GPL-3.0-or-later to MPL-2.0 (aligns
  with Thunderbird itself and the ATN ecosystem). SPDX headers
  added to all source files.
- **Tails / Whonix dropped from the "Tor-mail landscape" feature
  comparison** across all 21 READMEs — they are OS-layer projects,
  not MUA-layer alternatives. Replaced with a new "Stack with a
  Tor-hardened OS" callout pointing at https://tails.net /
  https://www.whonix.org as defense-in-depth.
- **New section: "OnionBird vs TorBirdy — feature-by-feature"** in
  EN + DE READMEs. Honest, critical, includes the "where both still
  fall short" sub-section (iTIP/iMIP, OpenPGP signing time,
  inherent SMTP-AUTH disclosure).
- **`addon/lib/` shared-validators extraction** (B1) and
  **`_enableHardeningImpl` decomposition** (B3) were deliberately
  deferred — both are medium-risk architectural refactors with
  limited immediate user-visible value relative to the bundle's
  security work. Tracked in this file as future work.

## Known regressions discovered but NOT fixed this session

These need follow-up bundles:

- **`mail.identity.<id>.FQDN` not written reliably under temporary
  install.** During Bundle 3 investigation, the per-identity FQDN
  write path was observed to not persist in some scenarios (the
  snapshot/restore cycle on temporary-install completes before the
  per-identity write reaches Services.prefs). User-visible behavior
  on regular install is unchanged (verified by
  `test_feature_real_send.py::test_message_id_fqdn_overridden_in_real_send`
  on the wire), but the addon-side write path needs investigation.
- **Drift-repair latency.** A test that simulates a 3rd-party flip
  of a hardened pref (`test_existing_install_re_asserts_on_pref_drift`)
  failed within the 75s budget — drift is not deterministically
  repaired within that window even with an account-event trigger.
  Removed from the suite pending a real investigation.

## 5-agent re-audit (2026-05-23 evening) — findings on this session's 7 commits

A second 5-agent review immediately after the bundle work shipped.
Agents covered Security, Code-Quality, Tests, Build/Release/Supply-
chain, and UX/Claims-vs-Code. Findings below are NEW (not in any
earlier table) and were verified by spot-check against the code.

### P0 — would break the 100%-Tor claim if shipped

| # | Agent | Title | Pointer |
|---|---|---|---|
| F-042 | security | `LEAK_VERDICT_KEY` never cleared on `disableHardening`. Re-enable inherits stale verdict; a stale `leak_detected` blocks all sends for ≤10 min until the next periodic canary; a stale `clean` lets the gate be bypassed on the next session before the first canary fires. | `addon/background.js:1119-1211` (`_disableHardeningImpl` only removes `STORAGE_KEY`); fix: `storage.local.remove([STORAGE_KEY, LEAK_VERDICT_KEY])` plus an explicit `recordLeakVerdict({state:"clean"})` at the end of `_enableHardeningImpl`. |
| F-043 | security | `readLeakVerdict` fails **OPEN** on storage error or corrupt verdict shape. `storage.local.get` throw → `null` → listener short-circuits → send proceeds. Garbled `verdict.state` (typo, wrong type) also passes through. | `addon/background.js:1320-1348`; fix: treat any non-`"clean"` state — including `null`, missing key, or unrecognised string — as fail-closed when a snapshot exists (= hardening active). |
| F-044 | security | `applyPrefs` atomic-validation gate is unchanged. With 110 entries in `HARDENING_PREFS` (Bundle 2 grew this from 99), a single `network.proxy.socks=null` (from a failed SOCKS probe) rejects the entire batch → SOCKS-routing pref set is silently NOT written. Threat is "Tor routing collapses lautlos" while the addon thinks it failed cleanly. | `addon/experiments/onionbird/implementation.js:1177-1242`; fix: per-pref validation and per-pref write so we apply as many fail-closed prefs as possible. Update `applyPrefs` JSDoc / B-007 comment that claims "atomic". |
| F-045 | tests | The 8 new `test_feature_send_block_on_leak.py` tests are 7/8 STRUCTURAL (file-grep over `background.js`). Same anti-pattern Bundle 3 was supposed to retire. **3 concrete regressions identified that current tests would NOT catch**: (1) writing the verdict to `storage.session` instead of `storage.local` (compose-block silently breaks across TB restart); (2) making `IDENTITY_HARDENING_PREF_RE` accept `mail.identity.X.username` (privilege escalation through allowlist); (3) removing `network.proxy.failover_direct=false` from `HARDENING_PREFS` write path (Tor transport fail-closed silently breaks). | `test/integration/test_feature_send_block_on_leak.py`; fix: open a compose window via Marionette, pre-populate `storage.local`, attempt send, assert notification bar. |
| F-046 | tests | `test_feature_message_id.py` (rewritten in Bundle 3) introduced a **new tautology**: `test_addon_allowlist_accepts_identity_fqdn_writes` re-defines the exact `IDENTITY_HARDENING_PREF_RE` literal in the test and tests its own copy. If the addon's regex breaks, the test still passes. | `test/integration/test_feature_message_id.py:85-101`; fix: drive `browser.onionbird.applyPrefs` with attacker-shaped pref names and assert it's rejected. |
| F-047 | tests | **Two tests that found real bugs were DELETED** instead of `xfail`-marked: per-identity FQDN write under temporary install (F-035-followup), drift-repair-latency. Hiding a known regression by deletion is the worst possible audit posture. | `test/integration/test_feature_upgrade_path.py` (drift-repair removed), `test_feature_message_id.py` (per-identity write removed); fix: re-introduce both as `@pytest.mark.xfail(strict=True)`. |
| F-048 | ux | Application-layer **`compose.onBeforeSend` send-block is not mentioned in any README**. This is the single biggest user-visible feature from this session. Marketing-vs-reality miss. | `README.md`, `README.de.md` (TorBirdy comparison table at `:140` should add a row). |
| F-049 | ux | **README test-count claim `160` is wrong** — actual `def test_` count across `test/integration/` is ≈144; with parametrize fan-out maybe ≤162 collected. Number appears in 4 places (`README.md:165, :319`, `README.de.md:174, :339`). | fix: either correct the count or auto-inject it from `pytest --co -q` output. |
| F-050 | ux | **18 of 19 translated READMEs have orphan `U+FE0F` (Variation Selector-16)** without a preceding base codepoint at the start of the new "Stack with a Tor-hardened OS" callout — renders as a blank box. Caused by an emoji placeholder my patch script dropped. EN/DE not affected. | `README.{af,ar,be,fa,fr,he,hi,id,ku,pl,pt,ru,th,tr,uk,ur,vi,zh-CN}.md` — single sed across all 18, or replace with the intended ⚠️ glyph. |
| F-051 | code-quality | **4 of 7 audit-IDs in the new `docs/audit-ids.md` glossary map incorrectly** to source-comment usage. Glossary was written from memory + `follow-up.md` rather than by walking the source. Spot-checked: `F-022`, `P1-T3-1`, `P1-T3-4`, `P0-T3-2` mappings do not match the source-comment context. The current state is worse than no glossary. | `docs/audit-ids.md`; fix: walk every B-/F-/P0-T3-/P1-T3-/Round-4/I- tag in source and rebuild the table, OR delete the file and replace with a `git grep <id>` invocation. |
| F-052 | build | **`make sign` uses `--source-dir=addon`** (Makefile:49) — web-ext re-zips with its own rules, so the published SHA-256 ≠ the SHA the validator audited. | `Makefile:49`; fix: `--source-dir=$(XPI)` plus add `make validate-xpi` as a `sign` dependency. |
| F-053 | build | Build is NOT reproducible across clones. `scripts/build_xpi.py:42` does not honor `SOURCE_DATE_EPOCH`; mtime from disk ends up in the zip. Reviewers cannot re-verify the published SHA from a fresh checkout. | `scripts/build_xpi.py`; fix: explicit `ZipInfo(arc, date_time=epoch_tuple)`, `compress_type=ZIP_DEFLATED`, `compresslevel=6`. |

### P1 — robustness / fail-mode / drift

| # | Agent | Title | Pointer |
|---|---|---|---|
| F-054 | code-quality | Redact/summarize log primitives duplicated across `background.js` (`summarize*ForLog`) and `options.js` (`redact*ForLog`) — same code, different names. Drift = inconsistent log redaction between background and UI surfaces = real privacy risk. | extract to `addon/lib/log_redact.js`. |
| F-055 | security | `_enableHardeningImpl` window between `applyPrefs` (step 1) and `runSelfTest` (step 4). User clicks Send during that window → no leak verdict yet, no identity-FQDN rewrite, possibly stale verdict. | `addon/background.js:1027-1107`; fix: per-process "hardening pending" flag that `compose.onBeforeSend` also gates on. |
| F-056 | security | `getMessageIdFallbackFqdn` not memoised in-process. If `Services.prefs` is policy-locked (enterprise policies.json), the catch swallows the error and the function generates a fresh value every call — Message-ID FQDN changes mid-session for identities without a usable From-domain. | `addon/experiments/onionbird/implementation.js:857-869`; fix: module-level `let _cachedFallback`. |
| F-057 | security | Adding `compose` permission to manifests granted the WHOLE `browser.compose` namespace (`sendMessage`, `setComposeDetails`, `listAttachments` …). None used today. Future supply-chain compromise of background.js gains compose-window control. | `addon/manifest.json:17-21`, `manifest.mv3.json:17-21`; fix: nothing in the manifest format lets us narrow further, but document the design choice and audit the listener body never calls anything beyond `onBeforeSend`. |
| F-058 | tests | `test_feature_clearnet_smtp.py::test_clearnet_lookup_routes_through_dns_trap` opens a generic `nsISocketTransportService` socket — does NOT exercise TB's SMTP layer (`nsSmtpService`/`SmtpClient`). Tests container plumbing, not the README's SMTP claim. | replace with a real SMTP server config + actual `OutgoingServer.sendMailMessage` invocation. |
| F-059 | tests | `test_feature_mv3_functional.py` uses `pytest.skip` on install failure — same anti-pattern it was meant to fix in `test_mv3_install_smoke`. | `test/integration/test_feature_mv3_functional.py:37-39`; fix: `pytest.xfail(strict=False)` so the day Mozilla flips MV3 support the suite turns green visibly instead of moving from skip→pass silently. |
| F-060 | build | Tor container unpinned (`alpine:3.20` + `apk add tor`); Tor version is whatever Alpine repos serve on build day. Base images (debian, python, alpine) tag-pinned, not digest-pinned. Only TB binary is SHA-256-pinned. | `test/containers/Containerfile.{tor,thunderbird,runner}`; fix: pin alpine `tor` version explicitly + use `@sha256:…` digests for base images. |
| F-061 | build | `web-ext lint` is never run before `make sign`. `make lint` swallows missing web-ext (`|| echo "(web-ext not installed)"`); `make sign` doesn't depend on lint. | `Makefile:43-56`; fix: make `lint` a hard dep of `sign`, make missing `web-ext` an error in lint instead of a no-op skip. |
| F-062 | build | `API_VERSION = "0.1.0"` literal in `implementation.js:28` is hand-maintained; will drift from `manifest.json` version. No build-time assertion. | `addon/experiments/onionbird/implementation.js:28`; fix: read from `WebExtension.id` / pass in via parent message, OR add a `build-xpi.sh` assertion that `API_VERSION` literal == manifest version. |
| F-063 | ux | README PTR claim oversells: "shared public suffixes (`co.uk`) explicitly rejected" — code has no PSL check, only exact-host-or-`.host` suffix match. Operator must configure a full FQDN canary (`torproject.org` works, `co.uk` would not, but only because of the suffix rule, not a PSL). | `README.md:157, README.de.md:166`; fix: reword to "PTR must equal the canary host exactly or end in `.<canary-host>`; operator must configure a full FQDN, not a registry suffix." |
| F-064 | ux | First-run with no Tor running: addon silently auto-enables → SOCKS probe fails → fail-closed prefs apply → user's email simply stops sending, no notification. Only feedback is the `compose.onBeforeSend` cancel message when they try to send. | `addon/background.js:1530`; fix: `browser.notifications.create()` on auto-enable SOCKS-probe failure ("OnionBird installed, no Tor on 9050/9150 — open Options to configure"). Requires adding `notifications` permission. |

### P2 — polish

| # | Agent | Title |
|---|---|---|
| F-065 | code-quality | `addon/experiments/onionbird/schema.json` lacks `minimum`/`maximum` on `tries`, `socksPort` (enforced in code, not at the schema boundary). |
| F-066 | code-quality | Test-env naming (`T0R_*`, `T0_*`, `t0net`, `t0_tor`, …) still uses the legacy `t0raddon` prefix. Either rebrand to `OB_*` / `obnet` or document the deliberate non-migration. |
| F-067 | build | Source-zip ships `addon/lib/.gitkeep`; harmless but inconsistent with XPI exclusion. Add `.gitkeep` to source-zip exclude list. |
| F-068 | build | Manifest equivalence check does not compare `host_permissions`. MV3 has `"host_permissions": []`; an accidental hostname addition there wouldn't fail. |
| F-069 | ux | `addon/_locales/en/messages.json` has 0 `description:` fields. Translator notes are absent for ambiguous keys (`canary*`, `helpTldr*`, `flowed`, `snapshot`). Affects future translation wave for hotspot languages (my, ug, bo, am, ti, ps, bn, ka, sw). |
| F-070 | ux | `LICENSE` file ships in source-zip but NOT inside the XPI. End-users unpacking the XPI have no license discoverability in-tree. |
| F-071 | ux | `addon/ui/options.html` has no SPDX license header (HTML comment); all other JS files do. |

## How to prioritise

Items in **P0** are deployment blockers for the "100% Tor" mandate.
F-001, F-002, F-004, F-011 are the highest-impact for end users in
realistic configurations. F-003 is the highest-impact in adversarial
contexts (sharing a workstation).

For the 2026-05-23 re-audit findings: **F-042 (verdict-clear-on-disable),
F-043 (readLeakVerdict fail-open), F-044 (applyPrefs atomic regression)**
are the three that materially weaken the just-shipped send-block and
should be the next bundle's focus. F-045/F-046/F-047 are the test-
quality follow-ups that prove (or disprove) the fixes.

P1 items are correctness / robustness improvements; they don't open new
leak paths but reduce user trust if hit.

P2 is polish.

## 5-agent third audit (2026-05-24) — findings on commit 9a3cb69

After landing the F-042..F-053 bundle that closed the previous
re-audit's P0s, a third 5-agent review was dispatched against HEAD
`9a3cb69` to catch what the just-shipped fixes themselves might have
missed. Five independent agents covered Security/Leak-Path,
Code-Quality/Maintainability, Test-Suite Quality, Build/Release/Supply-
Chain, and UX/Claims-vs-Code. The Code-Quality agent's findings were
renumbered to `F-089..F-107` to avoid collision with Security's
`F-072..F-088`; the unified ID stream covers `F-072..F-165` (94 new
findings).

The pattern across all five agents is consistent: the F-042..F-053
bundle was **technically correct but locally scoped** — each fix
closed the specific bug it targeted but did not search for the same
class of bug elsewhere. Net result: a fresh wave of P0 findings, half
of which are *exactly symmetric* to bugs the previous bundle just
closed (e.g. F-072 is the F-043 fix-pattern missed in the sibling
`readSnapshotState`; B-072 is the F-053 reproducibility property
missed for the source.zip).

### P0 — would break the 100%-Tor claim, ship a non-reproducible
### artifact, or make the green test suite meaningless

| ID | Domain | Title | Pointer (file:line) | Fix sketch | Why P0 |
|----|---|---|---|---|---|
| F-072 | sec | `compose.onBeforeSend` fail-OPEN when `isHardeningActive()` storage-get throws (`readSnapshotState` symmetric to the F-043 fix) | `addon/background.js:957-972` + `:1373-1376` | try/catch in `readSnapshotState`, return corrupt-marker, treat as fail-closed in listener | F-043 closed the same hole in `readLeakVerdict` but not in the sibling — fresh storage hiccup re-opens the send-block gate |
| F-073 | sec | Message-ID FQDN leaks user's onion mailbox address (`pickFqdn` returns onion from-domain literally) | `addon/experiments/onionbird/implementation.js:1456-1466` | `if (isOnionHost(dom)) fall through to fallbackFqdn` | An onion-mailbox user — the flagship use case — gets their `.onion` address printed in every outbound Message-ID; the bytes go via Tor but the application-layer header still discloses |
| T-072 | tests | `test_F044_apply_prefs_per_pref_validate_and_write` is grep-only and passes for fail-on-first-bad-pref regression | `test/integration/test_audit_fixes.py:407-457` | Behavioural: `browser.onionbird.applyPrefs([valid, invalid, valid])` and assert valid prefs were actually written | The headline P0 of the F-044 bundle has zero behavioural coverage — a partial revert passes the structural test |
| T-073 | tests | `test_e2e_tor_send.py` (headline E2E) re-implements hardening prefs in the test script via `Services.prefs.setXxxPref` instead of installing the addon | `test/integration/test_e2e_tor_send.py:89-101` | Install XPI, poll for `mailnews.headers.sendUserAgent=false`, send | The README "E2E Tor send" promise can regress fully without this file going red |
| T-074 | tests | `test_feature_real_send.py` sets hardening prefs itself then asserts Mozilla honoured them | `test/integration/test_feature_real_send.py:182-269` | Same fix as T-073 — drive enableHardening, drop the in-test `set_pref` of any pref the addon owns | "Load-bearing test that the addon defends against header leaks" tests Mozilla, not OnionBird |
| T-075 | tests | `test_build_is_reproducible_with_source_date_epoch` silently catches `OSError` on `os.utime` (read-only `/addon` mount) — never actually verifies mtime drift is normalised | `test/unit/test_build_reproducibility.py:76-85` | Copy `/addon` to `tmp_path`, vary mtime there, then compare SHAs | The F-053 reproducibility audit-anchor property is unverified; the test passes because the drift never happens |
| T-076 | tests | F-042/F-043 disable-clears-verdict + listener-fail-closed tests are body-grep only (no compose attempt, no synthetic storage state) | `test/integration/test_feature_send_block_on_leak.py:167-276` | Marionette: open compose, prime `storage.local`, attempt send, inspect cancel notification | The new send-block's only evidence fails OPEN on obvious regressions like `if (verdict.state !== "leak_detected") return;` |
| B-072 | build | `make sign` ships a NON-reproducible source.zip — the validate-xpi reproducible source.zip is overwritten by the legacy Makefile `zip -rq` recipe | `Makefile:36-41` + `Makefile:49,52` | Delete the Makefile $(SRCZIP) recipe; let `validate-xpi` (build-xpi.sh) own it | F-053 fixed XPI reproducibility; the source.zip ATN reviewers actually open is still non-reproducible across runs |
| B-073 | build | `make build` does NOT depend on `scripts/build_xpi.py` — bug-fix in build script + `make build` ships stale XPI | `Makefile:23,31` | `$(XPI): scripts/build_xpi.py $(shell find $(ADDON_DIR) ...)` | A fix to the build script doesn't trigger a rebuild; reviewer's clean clone produces different SHA |
| B-074 | build | `make sign` ABI broken on hosts without `/usr/bin/zip` — Makefile recipe wins over build-xpi.sh's python-zip fallback | `Makefile:39` | Replace with `@bash scripts/build-xpi.sh --no-mv3` | Hardened CI images / hosts without zip can't sign |
| B-075 | build | `atn-sign.sh` not idempotent on partial network failure — upload UUID lost if `versions/` POST fails | `scripts/atn-sign.sh:80-116` | Persist `$UPLOAD_UUID` to `build/.atn-upload-uuid` before versions POST, support `ATN_RESUME_UUID` | Lost upload + 409 on retry burns ATN quota and review windows |
| B-076 | build | `atn-sign.sh` `set -e` does not cover `$(…)` command-substitution failures (no `shopt -s inherit_errexit`) | `scripts/atn-sign.sh:16,77,80,85,91,95,97,110,114` | Add `shopt -s inherit_errexit`, audit each `$()` for non-empty check | Empty JWT silently sent, polling loop hits `/addons/upload//` | 
| B-077 | build | `atn-sign.sh` parses ATN response fields by exact key with `.get('processed', False)` → silent 5-min loop on schema rename | `scripts/atn-sign.sh:85,95,97` | `.get('processed', None)` + `assert processed is not None` | A future ATN API field rename produces a confusing timeout instead of a fast error |
| U-072 | ux | `compose.onBeforeSend` cancelMessage is hardcoded ENGLISH in 21+9=30-locale addon — the single most user-visible privacy-critical message in the whole product is untranslated | `addon/background.js:1397-1400` | Add `sendBlockedCancelMessage` to all 30 `messages.json` with `$REASON$` placeholder; `browser.i18n.getMessage(...)` | FA/AR/HE/BO/MY user hits English wall during the privacy-critical block, disables the addon |
| U-073 | ux | F-048 send-block row only landed in EN+DE README — missing from 19 translated comparison tables | grep across `README.{af,ar,be,es,fa,fr,he,hi,id,ku,pl,pt,ru,th,tr,uk,ur,vi,zh-CN}.md` | Re-run the patch script that did the de-table-row deletion, but for the send-block row addition | Translated READMEs are stale relative to EN/DE — undermines the 30-locale equality claim |
| U-074 | ux | cancelMessage tells user "Open OnionBird Options → re-run the Tor test" — but "Test Tor now" button does NOT update the leak verdict; user follows the instructions, send stays blocked | `addon/background.js:1397-1400` + `addon/ui/options.html:200,222` | Change message to "DNS leak status → Run self-test now" OR merge the two buttons | Direct UX trap authored by the F-043 fix; user concludes addon is broken |
| U-075 | ux | README claims "zero skipped" but suite has 8 `pytest.skip` calls under MV3/host-only conditions | `README.md:165,320`, `README.de.md:174,340` | Reword "0 skipped in the standard pod env (`make test-up && make test-integration`); MV3-install-smoke and host-build-only scenarios skip when preconditions aren't met" | Reviewer runs fresh `make test-integration`, sees skips, concludes README lies |
| U-076 | ux | F-049 NOT fixed: README still says `160 container-driven integration tests` in 4 places; commit message says `172 passed`; `def test_` count is 149 — all three numbers disagree | `README.md:165,320`, `README.de.md:174,340` | Auto-inject from `pytest --co -q` at build time, OR fix to 172 with "(149 test functions, 172 collected with parametrize)" footnote | The whole F-049 honesty-about-test-coverage point regressed |
| U-077 | ux | F-051 NOT fixed: `docs/audit-ids.md` still has at least 5 wrong mappings (F-001, F-003, F-008, F-022, F-023) | `docs/audit-ids.md:47-57` | Delete the glossary; replace with a CONTRIBUTING.md one-liner: "`git grep -n '\\b[BF]-[0-9]{3}\\b\\|P[0-3]-T[0-9]-[0-9]\\|Round-4 P[0-9]' addon/` then look up in `docs/follow-up.md`" | Worse than no glossary — actively misleads readers into citing the wrong finding |
| U-078 | ux | `docs/audit-2026-05-21-bug-report.md` B-007 says `applyPrefs` returns `rolled_back`/`rollback_failed` and "rolls back partial writes" — but F-044 deliberately removed the rollback this session. Doc now ships a false security claim referencing a non-existent test_F023_* | `docs/audit-2026-05-21-bug-report.md:24` | Update to "`applyPrefs` returns `{applied, failed}` per-pref, intentionally NOT atomic — see F-044" | Auditor reading B-007 believes addon has all-or-nothing semantics; actual behaviour is per-pref-best-effort |

### P1 — robustness / fail-mode / drift (49 findings)

Security: `F-074` install-user-js.sh writes worse-fingerprint
`localhost.localdomain` per-identity vs addon's default `from_domain`
mode; `F-075` applyHardeningToAllIdentities ignores onion-only gating
that the SMTP path applies (clearnet identities have reply-to/vCard
wiped behind user's back); `F-076` `onionbird.messageid.fqdn_fallback`
per-install random value survives disable AND uninstall (forensic
fingerprint); `F-077` `_enableHardeningImpl` corrupt-snapshot branch
snapshots from the HARDENED state — disable becomes a silent
permanent no-op for any user whose snapshot ever corrupts; `F-078`
inconclusive verdict blocks send for ≤10 min with no in-compose
"recheck Tor now" affordance; `F-079` cancelMessage hardcoded EN
(duplicate of U-072 from a different angle); `F-080` stale leak
verdict race in enable success-tail (window between
startHardeningMonitors and recordLeakVerdict-clean write); `F-081`
auto-enable on install with no Tor → silent send-block, no
notification (F-064 was deferred; now strictly worse with the send-
gate landed); `F-082` atn-sign.sh JWT re-mints every poll, secret in
60 successive Python process envs.

Code-Quality: `F-089` (was CQ-072) triplicated IP/host validators in
background.js + implementation.js + install-user-js.sh — `addon/lib/`
extraction now load-bearing; `F-090` summarizeErrorForLog
triplication parent+runtime+UI; `F-091` two parallel pref-name
allowlists (`HARDENING_PREFS` vs `ALLOWED_PREF_NAMES`) with no
build-time equivalence assertion; `F-092` SMTP+identity hardening
regex defined 3× across files; `F-093` MESSAGE_ID_FQDN_MODES set
defined 3× (bg + impl + options.html literal); `F-094` 5-fold
duplication of `MailServices.outgoingServer || MailServices.smtp`
iteration boilerplate (~25 LoC × 5); `F-095` `_enableHardeningImpl`
B3-decomp seams (4 clean function boundaries identified); `F-096`
`setPrefValue` silent no-op when name not in array (catches future
HARDENING_PREFS refactor); `F-097` `applyHardeningToAllSmtpServers`
parameter is dead-but-exposed.

Tests: `T-077` (was reported) classifyCanary tautology (test
re-defines its own copy); `T-078` dns-trap fail-closed tests verify
container plumbing, not TB acting on it; `T-079` autouse
`reset_global_prefs` silent-swallow defeats isolation; `T-080`
test_F052 silently skips on missing Makefile mount; `T-081`
`time.sleep(N)` flakes (4 specific sites); `T-082` F-047 xfail-strict
recommendation never actioned (per-identity FQDN + drift-repair
deletions stay deleted); `T-083` `test_experiment_api_via_pref`
literally tests Mozilla's pref-service, not the experiment API.

Build: `B-078` source.zip ships `addon/lib/.gitkeep` (F-067 not
addressed for source-zip); `B-079` manifest equivalence skips
`content_security_policy`, `web_accessible_resources`,
`host_permissions`, `icons`, `strict_min_version`; `B-080` base-image
digests not pinned (provides specific @sha256: digests for
alpine/debian/python); `B-081` Tor APK version not pinned;
`B-082` SHA256SUMS fetched over TLS-only, no GPG verification of
Mozilla TB tarball; `B-083` `API_VERSION` literal vs manifest version
has no build-time equivalence check; `B-084` `make sign` not gated on
`lint`; `B-085` `atn-sign.sh` requires curl ≥ 7.76 (--fail-with-body)
with no preflight; `B-086` SPDX headers missing on 5 source files
(scripts/atn-sign.sh, build_xpi.py, build-xpi.sh,
install-user-js.sh, tb_gui.py, ui/options.html — F-071 only flagged
one); `B-087` source.zip root-file list drifts between Makefile +
build-xpi.sh; `B-088` no `icons` block in either manifest, no
bundled brand mark; .

UX: `U-079` `compose.onBeforeSend` unavailable path silently
console.warns (no Options surface, no verdict marker); `U-080`
F-043 fail-closed has no Options-page surface (status shows ACTIVE
while every send is silently being cancelled); `U-081`
`privacy.resistFingerprinting` forces TB UI to en-US, undocumented
side-effect in 100%-Privacy-Policy section; `U-082` 3+3 broken
anchor links in EN+DE README (stack-with-tor-hardened-os anchors
point at bold-text, not headings); `U-083` `README.es.md` missed BOTH
the Tails/Whonix table-row deletion AND the F-048 send-block update
(documentation lies about its own scope); `U-084` "Stack with a Tor-
hardened OS" callout is English text sandwiched in 18 translated
READMEs; `U-085` README discloses calendar iTIP leaks as known gap,
threat-model.md is silent on calendar metadata; `U-086` README
discloses `Authentication-Results: smtp.auth` disclosure, threat-
model.md is silent; `U-087` README PTR claim ("public suffixes
explicitly rejected") oversells — no PSL parse; `U-088` threat-
model says `Content-Language` is mitigated by "compose-time strip"
but no such code exists; `U-089` options.html SPDX header still
missing (F-071 ack but unfixed); `U-090` README/threat-model drift
on ECH/HTTPS-RR mitigation row.

### P2 — polish (24 findings)

`F-083..F-088` (sec): verdict-state allowlist hardening, getStoredSnapshot
collapse, enable race de-dup, default-identity-FQDN snapshot
documentation, canary anchor jitter, atn-sign log-redaction.

`F-098..F-107` (cq, was CQ-081..CQ-090): dead `clearPref`,
getMessageIdFqdnPrefs vs pickFqdn dual read path, hardcoded EN
cancelMessage (mirrors U-072), socks5Resolve/socks5ResolvePtr 80-LoC
duplication, constants drift (`MAX_SNAPSHOT_ENTRIES` vs
`MAX_PREF_SNAPSHOT_SIZE`), user.js prefs not promoted to
HARDENING_PREFS, no-snapshot disable result-shape inconsistency,
tb_gui.py silently drops symbolic-ref prefs, atn-sign.sh per-iteration
JWT mint undocumented, enable-fail leaves stale verdict unrecorded.

`T-084..T-086` (tests): test_F044 jsdoc-no-atomic test passes on
comment deletion too, test_B007 contract test never invokes
applyPrefs, test_F053_build_module_exposes_default_epoch accepts
DEFAULT_EPOCH=0.

`B-089..B-095` (build): pip --require-hashes not used, ruff pin
12 months stale, pyproject.toml has no [project] block,
ATN_API_SECRET in 7 successive Python process envs (mirrors F-082),
JWT exp 240s wider than Mozilla's 60s sample, no shellcheck
pre-commit hook, no automated test exercises atn-sign.sh at all.

### How to prioritise this wave

The 21 P0s split cleanly: **F-072, F-073 are addon-code fixes** that
ship in the same surface as the bundle just landed; **B-072..B-077
are build/release** and block any honest ATN sign call; **U-072..U-078
are user-trust** and break the addon for non-EN-speaking users on
day one; **T-072..T-076 are test-coverage** and turn the 172-green
suite into a participation trophy without action.

A rational sequence for the next 3 bundles:

1. **Bundle A** — F-072 + F-073 (the 2 security P0s; smallest delta,
   same files as the 9a3cb69 bundle).
2. **Bundle B** — U-072 + U-073 + U-074 + U-076 + U-077 + U-078
   (UX/docs honesty pass; mostly README + i18n key additions; no
   code-correctness risk).
3. **Bundle C** — B-072..B-077 + T-075 (build reproducibility +
   reproducibility test that actually verifies it; supply-chain
   hardening before any ATN call).

Then attack T-072..T-074 + T-076 by replacing structural tests with
the behavioural shapes the agents specified; this finally validates
the F-042..F-053 bundle's claimed properties. Then P1s by domain.

## Findings from the F-047/T-076 follow-up (2026-05-24, late session)

(The earlier handoff labelled this work "F-074" by mistake. F-074 per
the table above is the unrelated `install-user-js.sh` finding, fixed
in Bundle H. T-074 was the re-introduced test for the **F-047**
"deleted tests" finding; running it surfaced F-166 below.)

Re-introduced T-074 as a regular test (was `xfail(strict=True)`) and
implemented T-076 as a real behavioural test (was `xfail(strict=False)`
with `NotImplementedError`). T-074 immediately surfaced a previously-
silent regression that the structural / on-the-wire tests had been
hiding:

| ID | Severity | Domain | Title | Pointer | Root cause | Status |
|---|---|---|---|---|---|---|
| F-166 | **P0** | sec | `randomHex` calls `globalThis.crypto.getRandomValues` which is **undefined** in the Experiments-API parent-process sandbox; the resulting `TypeError` is uncaught in `getMessageIdFallbackFqdn`, which kills the entire `applyHardeningToAllIdentities` function. Effect: **no per-identity Message-ID FQDN is written for ANY identity (not just no-from-domain ones)**, the per-install random fallback (`m<hex>.invalid`) is never persisted, and every Tor canary `randomIsolationToken()` throws (silently swallowed inside the SOCKS-probe try/catch, so probes degrade to "no isolation" without any user-visible signal). The structural test `test_message_id_fqdn_overridden_in_real_send` kept passing because TB's global FQDN fallback fills the Message-ID header on the wire even when the per-identity write never happened — green-but-meaningless | `randomHex` in `addon/experiments/onionbird/implementation.js`; blast radius is `getMessageIdFallbackFqdn` and `randomIsolationToken` (used by `probeSocks` and the canary self-test path) | Sandbox at this depth doesn't expose WebCrypto; the original code assumed a browser-like global. `globalThis.crypto.getRandomValues` was the **only** WebCrypto call site in `implementation.js`, so this code path has been broken since `randomHex` was first introduced — present-from-day-one, not a regression. Only exposed when T-074 stopped relying on the test setting the pref itself | **FIXED**: hoisted `Cc` next to existing `Ci`, made `randomHex` prefer WebCrypto when available (fuzz/sandbox contexts may inject one) and fall back to `nsIRandomGenerator` from XPCOM otherwise. The XPCOM path always works in parent-process. |
| F-083 | P2 | sec | `recordLeakVerdict(verdict)` accepted any object as the verdict argument and persisted it verbatim to storage.local. Consumers gate on `verdict.state === "clean"` so unknown states fail-closed (good), but a typo at a writer (`state: "clena"` instead of "clean") silently starts blocking every send forever — no test would catch the typo at write time. Also: malformed verdict objects with extra fields could persist PII / unbounded payloads. | `addon/background.js:recordLeakVerdict` | Original implementation just stored the input; the contract was implicit. | **FIXED**: `VALID_VERDICT_STATES` Set + `VERDICT_ALLOWED_KEYS` Set + `normalizeLeakVerdict(input)` helper that validates the state against the allowlist and drops unexpected keys. Unknown state → return null (no write). Tests in `test_feature_verdict_allowlist.py` assert both the allowlist's existence AND that recordLeakVerdict consults it. |
| F-087 | P2 | sec/fingerprinting | The periodic canary hammered `check.torproject.org` every `SELF_TEST_INTERVAL_MS`. A passive observer who sees TB-shaped DNS-via-Tor lookups hitting that target at regular cadence can fingerprint the user as an OnionBird canary source — the Tor-routed bytes are private, but the periodicity + the fixed target are the signal. | `addon/background.js` (constants + `announceSelfTest`) | Single-target convenience; no rotation mechanism existed. | **FIXED**: `CANARY_ANCHOR_HOSTS` rotation pool (`check.torproject.org`, `www.torproject.org`, `bridges.torproject.org`, `duckduckgo.com`, `debian.org` — each individually plausible non-OnionBird Tor-side lookup). `pickCanaryAnchorHost()` picks per probe; `announceSelfTest` consumes it. The verdict invariant (`system_ip ∈ tor_ips` for the chosen target) holds for each anchor independently. |
| F-088 | P2 | sec/secrets-hygiene | `scripts/atn-sign.sh` exposed JWT bearer credentials via two log surfaces: a `bash -x` wrapper invocation would print every `$JWT` expansion to stderr (caught in CI logs / terminal scrollback), and curl error output on some verbose-failure paths can include the request-as-sent (Authorization header included). | `scripts/atn-sign.sh` | Defensive log hygiene not previously considered for a script that's rarely run. | **FIXED**: explicit `set +x` at script top (defeats `bash -x` / `SHELLOPTS=xtrace`); `redact_secrets()` function that replaces literal `$JWT` / `$ATN_API_SECRET` AND any JWT-shaped (header.payload.signature base64url) string with placeholder tokens before output. Tests in `test_atn_sign_helpers.py` exercise the redactor with two scenarios (literal value redaction + shape-only detection when the env var isn't set). |
| T-084 | P2 | test-quality | `test_F044_apply_prefs_jsdoc_does_not_claim_atomic` asserted `"atomic" not in window` but did NOT assert the comment block itself existed — deleting the entire jsdoc would pass the test even though the documentation was wholly removed. Classic green-but-meaningless. | `test/integration/test_audit_fixes.py` | Original test was a single-sided assertion. | **FIXED**: also assert that the comment window contains one of `per-pref` / `per pref` / `best-effort` / `fail-as-many-as-possible` — the per-pref semantics description. Mutation-verified: stripping all those markers from impl.js makes the test fail. |
| T-085 | P2 | test-quality | `test_B007_apply_prefs_contract` ran a chrome-context JS loop that called `Services.prefs.setBoolPref / setIntPref / setCharPref` directly — testing Mozilla's pref service, not the addon's `browser.onionbird.applyPrefs` wrapper. The test passed even if the addon's applyPrefs was deleted. Classic green-but-meaningless. | `test/integration/test_audit_fixes.py:test_B007_apply_prefs_contract` | Original test was a contract-by-simulation rather than a contract-by-observation. | **FIXED**: replaced with a structural assertion on the impl.js `applyPrefs` body — return statement must mention both `applied` and `failed` fields, AND both arrays must be `.push()`ed within the body (catches "shape is right but arrays stay empty" regressions). Mutation-verified: replacing `failed.push` with a sed-comment in the applyPrefs body makes the test fail. |
| T-086 | P2 | test-quality | `test_build_module_exposes_default_epoch` checked `isinstance(mod.DEFAULT_EPOCH, int)` — DEFAULT_EPOCH = 0 (Unix epoch zero) would pass even though it's a footgun fallback (some zip writers reject it on some platforms; 1970 mtimes scream "uninitialized constant" to artifact auditors). | `test/unit/test_build_reproducibility.py` | Type-only assertion was too lenient. | **FIXED**: also assert `DEFAULT_EPOCH >= 1262304000` (2010-01-01 UTC). Any regression to Unix-epoch-zero / unset / divide-by-zero fails the test loudly. Current value `1577836800` (2020-01-01) passes. |
| B-095 | P2 | test-coverage | `scripts/atn-sign.sh` had ZERO automated test coverage. The only validation was a green ATN upload — meaning bugs surfaced only on the production-style invocation, after credentials were already in play. | `scripts/atn-sign.sh` | One-shot release-tool tradition. | **FIXED**: `test/integration/test_atn_sign_helpers.py` covers the testable fragments — `redact_secrets` literal + shape redaction, `set +x` preamble presence, `mint_jwt` structural (HS256 declared, reads ATN_API_SECRET from env, defined as a function). The full upload path stays a manual gesture gated on real credentials. |
| F-175 | P2 | ux/i18n | The F-081 auto-enable-failure desktop notification (title + body) shipped as hardcoded English string literals — bypassing the `browser.i18n.getMessage` path every other user-visible string uses. A Farsi / Burmese / Bengali user (F-168-cited repression-hotspot locales) saw English when their sends started failing — exactly the population the localised cancelMessage work (U-072) was meant to serve. | `addon/background.js` (onInstalled notification block) | F-081 added the surface in a hurry to close the silent-block UX trap; the strings stayed inline. | **FIXED**: 4 new i18n keys (`autoEnableNotificationTitle{SocksUnreachable,CanaryFail}` × `Message`) propagated to all 30 locales via `scripts/add-autoenable-notification-i18n.py` (en + de hand-translated; other 28 en-fallback). Background.js uses `browser.i18n.getMessage` for both title and message. Tests in `test_feature_autoenable_notification.py` assert both the i18n call presence AND the absence of any hardcoded English fragments that would survive a half-converted regression. |
| F-174 | P1 | sec/fingerprinting | The companion `user-js/onionbird-user.js` blanks `calendar.useragent.extra` (line 112) but the addon-only install path's HARDENING_PREFS missed it entirely. Effect: a TB launched with the addon enabled but WITHOUT the companion user.js leaks the calendar User-Agent string in every CalDAV / DAV request — a per-TB-version fingerprint distinct from the Mail UA and undefended by `mailnews.headers.sendUserAgent`. Symmetric to the F-074 direction (addon writes X that user.js doesn't, fixed in Bundle H); this is the reverse direction (user.js writes Y that addon doesn't), surfaced by a cross-cutting bug-search pass. The other 4 user.js → addon asymmetries (`mail.shell.checkDefaultClient`, `mail.rights.{version,acceptedEULA}`, `javascript.allow.mailnews`) are cosmetic / legacy and intentionally left out. | `addon/background.js` (HARDENING_PREFS), `addon/experiments/onionbird/implementation.js` (ALLOWED_PREF_NAMES) | The pref doesn't share the same prefix as the mail UA pref family — easy to miss in a name-prefix grep. Bundle H's symmetric audit only checked one direction. | **FIXED**: added `{ name: "calendar.useragent.extra", value: "" }` to HARDENING_PREFS + `"calendar.useragent.extra"` to ALLOWED_PREF_NAMES. Test `test_F174_calendar_useragent_extra_is_hardened` asserts both. |
| F-173 | P1 | test-hygiene | `reset_global_prefs` (autouse fixture) didn't clear `network.predictor.enabled` and `network.prefetch-next`. `test_behavioural_addon_drives` sets these to "leak-on baseline" (True/True) before installing the addon to prove the addon flips them; if install fails mid-way OR another test installs after, the leak-on state persists into later tests that expect TB defaults. Same test-pollution class as F-168 I-2 (addon-owned prefs sweep) but for TB-managed prefs. | `test/integration/conftest.py:RESET_GLOBAL_PREFS` | F-168 I-2 fixed the `onionbird.*` sweep but didn't generalize to the predictor/prefetch pair the behavioural tests write. | **FIXED**: added both to the explicit prefs list. Other potentially-leaky prefs (e.g. `onionbird.audit.test` / `onionbird.smoke` test-only sentinels) are auto-covered by F-168 I-2's `onionbird.*` branch sweep. |
| F-171 | P1 | ux | The Options-page Reset button used the `socksOverrideStatusOk` ("OK") status string after clearing the override — same string the Save button uses on success. Reads as "saved" right after the user gestured to clear, contradicting the actual action. On a freshly-cleared state it implies a 127.0.0.1 override has been persisted (which isn't true — Reset clears the override entirely, falling back to the auto-detect ladder). | `addon/ui/options.js:resetSocksOverride` | First-pass F-168 implementation reused the existing OK key for brevity; the semantic mismatch only surfaces when a user actually exercises Reset. | **FIXED**: new i18n key `socksOverrideStatusReset` ("Override cleared — falling back to auto-detect on next enable.") added to all 30 locales (en+de hand-translated, other 28 en-fallback via `scripts/add-socks-override-i18n.py`). `resetSocksOverride` uses the new key. |
| F-172 | P1 | sec/ux | `runSelfTest`'s `assertAllowedSocksEndpoint(socksHost, socksPort)` call had the same chicken-and-egg trap as F-168 I-1 (Test button). If a UI-triggered Run-self-test fires before the user-override has been applied to `network.proxy.socks`, the gate rejects an IP-literal endpoint with the misleading "SOCKS endpoint not allowed" error. Less common than the Test-button case (users usually click Test first), but the same plumbing needs the same fix. | `addon/experiments/onionbird/implementation.js:runSelfTest` | F-168 I-1 added the `userProbe` opt-out to `probeSocks` but missed the symmetric runSelfTest path. | **FIXED**: thread `cfg` (the runSelfTest options object that already carries the caller's intent) as the 3rd arg to `assertAllowedSocksEndpoint`. Structural test `test_F172_run_self_test_honours_user_probe_bypass` asserts the 3-arg call shape. |
| F-170 | **P0** | sec/ux | The Options-page Save handler called `setSocksOverride("host", host)` then `setSocksOverride("port", port)` sequentially. The impl treats `port === 0 / "" / null` as a clear-sentinel — so if the port input was ever 0 (or the port write failed for any other reason after the host write succeeded), the result was a HALF-SET pair: host persisted in about:config, port cleared. `getSocksOverride` returns null for any half-set pair, so the override was **silently inert** — the user saw `socksOverrideStatusOk` ("saved") while `enableHardening` kept falling through to the 127.0.0.1 fallback ladder. On Whonix that means "you think you configured the gateway, the addon ignores you, fail-closed blocks every send with no UX cue". The dangerous case is masked because options.js DOES validate `port >= 1` client-side, but any future caller bypassing that gate (or a future regression of the client-side check) re-opens the silent-inert state. | `addon/ui/options.js:saveSocksOverride` (pre-fix two-step), `addon/experiments/onionbird/implementation.js:setSocksOverride` (the empty-sentinel branch) | Two-step sequential write was the most-obvious implementation but is non-atomic; nothing in the API surface prevented half-state from being persisted. | **FIXED**: new `setSocksOverridePair({host, port})` API in implementation.js validates BOTH inputs first and writes BOTH in the same parent-process tick (or writes neither on rejection). options.js Save handler calls only the pair API; the granular `setSocksOverride(field, value)` stays for cases that legitimately need to clear one half. Structural test `test_F170_save_handler_writes_host_and_port_atomically` asserts both ends. |
| F-169 | **P0** | sec | `_disableHardeningImpl` gated `clearAddonOwnedPrefs()`, `storage.local.remove([STORAGE_KEY, LEAK_VERDICT_KEY])`, AND `stopHardeningMonitors()` all inside `if (ok)`. `ok` requires ALL of the 110+ HARDENING_PREFS restore + SMTP-clear + identity-clear + scrubLogins steps to succeed. A single failed pref restore — very plausible given the surface — caused **three forensic-marker leaks across the user's explicit disable gesture**: (a) the user's `onionbird.socks.host` (Whonix gateway IP / custom Tor SOCKS) persisted in about:config — exact "this user runs Whonix" fingerprint surviving disable AND uninstall; (b) the F-076 per-install random `m<10hex>.invalid` fallback FQDN persisted (re-opening the F-076 hole); (c) the storage.local snapshot + leak verdict persisted, meaning a subsequent re-enable would re-snapshot from a corrupted state and the F-042 fail-closed window re-opened. Note: `clearDnsCache` was correctly OUTSIDE the gate — the inconsistency made the bug easy to miss in review. | `addon/background.js:_disableHardeningImpl` | The original `if (ok)` block bundled three categories that have different invariants: pref restoration is "did we revert everything", forensic scrub is "did we leave no marker behind", monitor stop is "did we wind down cleanly". Restoration failure shouldn't cascade into the other two — those are independent. | **FIXED**: hoisted `storage.local.remove` + `clearAddonOwnedPrefs` out of the `if (ok)` gate; each now in its own try/catch so a failure in one doesn't cascade to the other. `stopHardeningMonitors` stays inside the gate (it logically belongs with the success path). Behavioural tests in `test_feature_disable_cleanup.py` parse the function body and assert both calls are NOT inside the `if (ok)` block. Mutation-verified: moving either call back inside the block makes the corresponding test go RED. |
| F-168 | feature | sec + ux | Users on Whonix / Tails-via-non-default / custom Tor configs had no way to point the addon at a specific SOCKS endpoint without editing about:config — which the addon then overwrote on next enable. New addon-owned prefs `onionbird.socks.host` + `onionbird.socks.port` persist a user-chosen override; resolution-order in `enableHardening` is **caller-supplied → user-override → existing-pref → fail-closed ladder**. Strict gate: loopback (`localhost` / 127.x / `::1`) or IP literal only — DNS-resolvable hostnames are rejected because the SOCKS host itself would be resolved via the system resolver before Tor (same leak class as B-001). Validation is mirrored at both write-time (`setSocksOverride` API in implementation.js) and read-time (`getSocksOverride` defense-in-depth against about:config edits). Options page exposes Host + Port inputs, Save/Reset/Test buttons, and a "TB had X configured; your override replaces it" warning when the existing pref drifts from the override. New i18n keys (`socksOverride*`) propagated to all 30 locales — en + de hand-translated, other 28 fall back to en text via `scripts/add-socks-override-i18n.py`. | `addon/experiments/onionbird/implementation.js` (`setSocksOverride` / `getSocksOverride`, `ADDON_OWNED_PREF_NAMES`), `addon/background.js` (override candidate prepended in `detectSocksConfig`), `addon/ui/options.{html,js}` (UI section + handlers), `addon/_locales/*/messages.json` (11 keys × 30 locales) | Pre-existing API surface didn't have a way to surface user choice — the only path was the fail-closed ladder which assumed loopback Tor. The override candidate is prepended in `detectSocksConfig` so it sits between caller-supplied (explicit "use these now") and existing-pref (TB's current config). | **SHIPPED**: 8 new tests in `test_feature_socks_override.py` cover the allowlist, schema, validator, override-resolution, behavioural end-to-end, and Options UI surface. Behavioural test mutation-verified: removing the override candidate in `detectSocksConfig` makes the test fail (`network.proxy.socks` stays at 127.0.0.1 instead of the resolved tor IP); restoring makes it pass. Structural tests for the schema + allowlist also mutation-verified. The read-time validator in `getSocksOverride` is intentionally untested behaviourally — `coreFailClosedPrefs`'s `safeConfiguredSocksHostOrDefault` rewrites bad hosts to `127.0.0.1` regardless, so its load-bearing behaviour requires a 2-mutation scenario to surface. Test pollution gap closed: `reset_global_prefs` now also clears `onionbird.socks.host/port` between tests. |
| F-167 | P1 | ux + telemetry-suppression | The hardening blanks `app.support.baseURL` to `""`. TB's built-in `chrome://global/content/elements/moz-support-link.mjs` constructs every help-icon URL via `new URL(supportPage, app.support.baseURL)` — empty base throws `TypeError: URL constructor: <supportPage> is not a valid URL` and spams the Browser Console with one error per rendered help link (`add-on-badges`, dozens of others). Visible immediately on opening about:addons, Options dialogs, etc. — looks like the addon is breaking the host application. The hardening's *intent* is right (no phone-home to Mozilla's support URLs leaking UA + lang + TB-version), but blanking the base-URL is the wrong implementation. | `addon/background.js`, HARDENING_PREFS entry for `app.support.baseURL` (~line 223) | The original Round-4 P3-1/P3-4 cluster blanked several phone-home URLs to `""`. For terminal endpoints (`app.update.url`, `extensions.update.url`, `mail.update.url`, `breakpad.reportURL`) `""` is fine because they go straight into `fetch("")` which fails cleanly without DOM-level side effects. `app.support.baseURL` is different — it's a *base URL for relative resolution*, parsed by the WHATWG URL constructor in UI render paths. Empty base → TypeError on every help-link DOM element. | **FIXED**: set value to `https://onionbird.invalid/`. `.invalid` TLD is RFC-2606 reserved as guaranteed-unresolvable, so the URL constructor accepts it without throwing, click-through fails cleanly via Tor (no phone-home leak), no JS-error cascade. Regression test in `test_audit_fixes.py::test_F167_app_support_baseurl_is_parseable_url` asserts the value parses as http(s) URL with non-empty host and trailing `/`; mutation-verified by reverting to `""` (test goes RED) and restoring (GREEN). |

Verified end-to-end:

- **T-074** (`test_T074_addon_writes_identity_fqdn_without_test_setpref`)
  now passes as a regular test. Diagnostic probe before/after confirms
  the per-identity FQDN write produces:
  `mail.identity.id12.FQDN = "ma1c69884c148db1f1975.invalid"` (the
  per-install random fallback for an identity with no usable
  from-domain), and the from-domain branch writes `"anon.invalid"`
  for the regular identities. `mail.identity.default.FQDN` also
  populates, which was previously also empty.
- **T-076** (`test_T076_compose_onbeforesend_cancels_send_on_leak_verdict`)
  now drives a real Marionette compose-window send via
  `MailServices.compose.OpenComposeWindowWithParams` →
  `goDoCommand("cmd_sendNow")`. The disambiguator between "cancelled
  by addon" and "send tried but transport failed" is a
  `nsIMsgSendListener` registered on `gMsgCompose` BEFORE the send is
  triggered: a successful `onBeforeSend` cancel means
  `onStartSending` never fires. **Mutation-verified**: temporarily
  replacing the cancel-branch `return { cancel: true, … }` with `return;`
  causes the test to fail with `start_sending: True`; restoring the
  return makes it pass. SMTP-trap assertion serves as a
  belt-and-braces second witness.
- New TBClient helper: `open_compose_window_and_send(...)` —
  reusable for future tests that need to exercise the compose-window
  send path rather than `nsIMsgCompose.sendMsg` directly (the latter
  does not route through the WebExt `compose.onBeforeSend` hook and
  cannot be used to test that surface).

### Implications for other code paths

Because `randomHex` is also used by `randomIsolationToken`, every
Tor-canary SOCKS5 lookup has been issuing requests without the
per-probe isolation token since the canary surface was wired. Two
follow-up consequences worth tracking (deferred — fix landed,
verification would be its own bundle):

1. The canary's "different circuit per probe" property — promised in
   `addon/experiments/onionbird/implementation.js` near the canary
   anchor jitter logic — was actually "all probes share whatever
   circuit Tor pinned for the first request". After this fix,
   isolation tokens are non-empty, so Tor's `IsolateClientAddr` /
   `IsolateSOCKSAuth` semantics kick in for the first time.
2. There is no test that asserts the SOCKS auth bytes are non-zero
   — every probe used to be "valid SOCKS handshake with
   default-isolation". A regression test that observes the SOCKS5
   auth-method payload on the wire would catch a future revert.

## P2 cleanup pass (2026-05-25)

Triaged the 24 P2 items from the "5-agent third audit (2026-05-24)"
P2-polish section. **7 fixed** in commit-of-this-date (catalogued
above): F-083 (verdict allowlist), F-087 (canary rotation), F-088
(log-redact), T-084/T-085/T-086 (test-quality strengthening), B-095
(atn-sign coverage).

**Wontfix / deferred-by-design** (with rationale per item — all kept
out of the fix bundle because the cost-benefit doesn't justify
maintainer time given the risk profile):

- **F-084 `getStoredSnapshot` collapse**: 1-liner wrapper around
  `readSnapshotState().snapshot`. Inlining at the 2 call sites would
  save 4 lines but break call-site readability. Keep as-is.
- **F-085 enable race de-dup**: `enqueueHardeningMutation` already
  serializes all enable/disable/re-assert calls through a single
  promise chain. Reviewer flagged a theoretical race but didn't
  identify a concrete path; the existing serialization handles every
  case I could enumerate. Wontfix without a repro.
- **F-086 default-identity-FQDN snapshot documentation**: comment-
  only fix. The behaviour is correct (default-identity branch IS
  hardened in `applyHardeningToAllIdentities`); the missing doc is
  cosmetic. Skip.
- **F-098 dead `clearPref`**: the `clearPref` API method is exposed
  for symmetry with `setPref` even though no caller uses it today.
  Removing it would just churn the schema — wontfix.
- **F-099 dual-read paths (`getMessageIdFqdnPrefs` vs `pickFqdn`)**:
  the two paths serve different consumers (UI vs apply-time). Could
  be unified but the current shape is auditable per-path. Skip without
  a concrete bug.
- **F-100 hardcoded EN cancelMessage**: DUPLICATE of U-072 which was
  fixed in Bundle M. Already closed; just not crossed off the list.
- **F-101 socks5Resolve / socks5ResolvePtr 80-LoC duplication**: real
  duplication but the two functions have subtly different state
  machines (PTR vs A-record SOCKS5 RESOLVE commands). Refactor would
  need careful test coverage. Defer until there's a third caller that
  forces the abstraction.
- **F-102 constants drift** (`MAX_SNAPSHOT_ENTRIES` vs
  `MAX_PREF_SNAPSHOT_SIZE`): doc-only.
- **F-103 user.js prefs not promoted**: DUPLICATE of F-174 which was
  fixed (calendar.useragent.extra added; other 4 are cosmetic and
  documented in the F-174 row).
- **F-104 no-snapshot disable result-shape inconsistency**: caller
  (UI) tolerates the variation. Cosmetic.
- **F-105 `scripts/tb_gui.py` silently drops symbolic-ref prefs**:
  dev tool, not user-facing. Keep deferred until someone actually
  trips over it.
- **F-106 atn-sign.sh per-iteration JWT mint undocumented**: doc-only;
  the F-088 fix added enough context inline.
- **F-107 enable-fail leaves stale verdict unrecorded**: addressed
  implicitly by F-080 (`recordLeakVerdict({state: "enable-in-progress"})`
  is called BEFORE `applyPrefs`, so a mid-enable failure leaves the
  enable-in-progress verdict — which is correctly handled as non-clean
  by the onBeforeSend listener). F-083's normalizer doesn't drop it
  (`enable-in-progress` is in VALID_VERDICT_STATES). No further work
  needed.
- **B-089 pip `--require-hashes`**: would tighten the runner Python
  deps but they're already in a dedicated container with a frozen
  base image. Cost-benefit doesn't justify the maintenance churn
  for a release tool only the maintainer runs.
- **B-090 ruff pin 12 months stale**: cosmetic; ruff is stable on the
  pinned features the project uses.
- **B-091 pyproject.toml `[project]` block**: would help if the
  project ever wanted to be `pip install`able. It's not. Skip.
- **B-092 ATN_API_SECRET in 7 successive Python process envs**:
  mirrors F-082 (the pre-F-082 state). F-082 already reduced from 60
  re-mints to 1 by minting a single 290s JWT for the polling window.
  Going further (e.g. stdin-passing the secret to each python `-c`)
  is a meaningful hardening but adds significant bash plumbing for
  marginal real-world risk reduction (operator's machine is already
  trusted for the env to be set at all).
- **B-093 JWT exp 240s wider than Mozilla's 60s sample**: Mozilla's
  60s assumes per-iteration re-mint; F-082 deliberately chose the
  longer window to avoid the secret-in-env-per-iteration leak. Trade-off
  documented in the script's inline comment. Accept.
- **B-094 no shellcheck pre-commit hook**: maintainer runs shellcheck
  manually as part of release. Pre-commit-hook installation would
  require a hooks-management system the project doesn't have.

Net of this pass: 7 fixed (commit on this date), 17 documented as
wontfix-by-design with explicit rationale. **The "100% Tor" rule is
unaffected** — none of the wontfix items represent an anonymity gap;
they're cosmetic, tooling, or accepted trade-offs.
