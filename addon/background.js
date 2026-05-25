// SPDX-License-Identifier: MPL-2.0
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
"use strict";

const VERSION = browser.runtime.getManifest().version;

// SOCKS proxy defaults — points at LOCAL Tor by default.
// B-001 fix: previously hardcoded to "tor" (a container DNS name).
const DEFAULT_SOCKS_HOST = "127.0.0.1";
const DEFAULT_SOCKS_PORT = 9050;        // system Tor
const TOR_BROWSER_SOCKS_PORT = 9150;    // Tor Browser bundle
const SELF_TEST_HOST = "check.torproject.org";
const TOR_TEST_HOST = "example.com";

// F-087: canary anchor rotation. A passive observer who sees TB-shaped
// DNS-via-Tor lookups hitting `check.torproject.org` every SELF_TEST_
// INTERVAL_MS can fingerprint the user as an OnionBird canary source
// even though the lookups go through Tor (the periodicity + fixed
// target are themselves the signal). We rotate among a small pool of
// targets that are individually plausible non-OnionBird lookups:
//   - check.torproject.org: canonical Tor-Project check service
//   - www.torproject.org: navigating the project's marketing site
//   - bridges.torproject.org: a bridge-fetch path
//   - duckduckgo.com: search-via-Tor is a classic "I use Tor" pattern
//     unrelated to OnionBird
//   - debian.org: package-mirror lookup; routinely Tor-resolved by
//     security-aware users
// The verdict invariant (system_ip ∈ tor_ips for the chosen target)
// holds for each anchor independently, so rotation doesn't weaken the
// canary's correctness — it just removes the per-target fingerprint.
const CANARY_ANCHOR_HOSTS = [
  "check.torproject.org",
  "www.torproject.org",
  "bridges.torproject.org",
  "duckduckgo.com",
  "debian.org",
];

function pickCanaryAnchorHost() {
  // Crypto-grade pick isn't necessary; what matters is non-zero entropy
  // per probe so the rotation isn't predictable from a fixed seed.
  // Math.random() is fine for fingerprint-defence purposes here (this
  // is NOT a key derivation).
  const idx = Math.floor(Math.random() * CANARY_ANCHOR_HOSTS.length);
  return CANARY_ANCHOR_HOSTS[idx] || SELF_TEST_HOST;
}

// Prefs that get touched by enable-hardening. Snapshotted before write so
// disable-hardening can restore the user's original values.
// B-007 / F-044: per-pref apply with structured failure report. Fail-
// closed prefs that succeed are kept in place even when a later pref in
// the batch fails, so a single bad entry cannot collapse the entire
// SOCKS-routing set back to clearnet.
const HARDENING_PREFS = [
  // SOCKS proxy
  { name: "network.proxy.type", value: 1 },
  { name: "network.proxy.socks", value: DEFAULT_SOCKS_HOST },
  { name: "network.proxy.socks_port", value: DEFAULT_SOCKS_PORT },
  { name: "network.proxy.socks_version", value: 5 },
  { name: "network.proxy.socks_remote_dns", value: true },
  // B-001 part 2: fail closed if proxy host is unreachable
  { name: "network.proxy.failover_direct", value: false },

  // Anti-fingerprint
  { name: "mailnews.headers.sendUserAgent", value: false },
  // F-174: the addon-only install path was missing the calendar
  // User-Agent suppression that the companion user.js had at line 112.
  // mailnews.headers.sendUserAgent only suppresses the *mail* UA;
  // calendar.useragent.extra leaks a separate string in every CalDAV
  // / DAV request, per-TB-version fingerprintable. Symmetric to the
  // F-074 case (addon writes X that user.js doesn't); this is the
  // reverse direction caught by a cross-cutting bug-search pass.
  { name: "calendar.useragent.extra", value: "" },
  // B-005: Date UTC + locale spoof. Has side effects on screen rounding, locale.
  { name: "privacy.resistFingerprinting", value: true },

  // Networking
  { name: "network.dns.disableIPv6", value: true },

  // Defense-in-depth: independent leak surfaces beyond SOCKS5+remoteDNS.
  // TB 140's SmtpClient honors remoteDNS empirically (verified by
  // external/test_dns_leak_audit.py::test_S9), but these prefs close
  // adjacent paths that could leak without it.
  { name: "network.trr.mode", value: 5 },                  // DNS-over-HTTPS off-by-choice
  { name: "network.proxy.no_proxies_on", value: "" },      // no SOCKS bypass exemptions
  { name: "media.peerconnection.enabled", value: false },  // no WebRTC IP leak
  { name: "network.dns.disablePrefetch", value: true },
  { name: "network.predictor.enabled", value: false },
  { name: "network.prefetch-next", value: false },
  { name: "geo.enabled", value: false },

  // Remote content / images — Round-4 P0: removed
  // `permissions.default.image=2` (was a B-016 ADR conflict; broke
  // calendar invites, account-wizard logos, inline help images for
  // zero anonymity benefit since `mailnews.message_display.disable_
  // remote_image` already blocks the leak surface in mail rendering).
  { name: "mailnews.message_display.disable_remote_image", value: true },

  // HTML render hardening (Round-4 P0-1): blocks remote-resource paths
  // beyond <img> — <video>, <link rel=prefetch>, CSS url(...), @font-
  // face, @import, <iframe>. Force plaintext rendering of HTML mail.
  { name: "mailnews.display.html_as", value: 3 },
  { name: "mailnews.display.prefer_plaintext", value: true },
  { name: "mailnews.display.disallow_mime_handlers", value: 100 },

  // Reply-header minimization
  { name: "mailnews.reply_header_type", value: 1 },
  { name: "mailnews.reply_header_authorwrote", value: "%s" },

  // Content-Type fingerprint (reallife audit 2026-05-22): TB's default
  // emits `format=flowed` in the Content-Type header on outbound plain
  // text. RFC 3676 is a real format but very few non-TB-family clients
  // send it — it's a client-class fingerprint. Suppress to ship plain
  // text/plain without the format= parameter.
  { name: "mailnews.send_plaintext_flowed", value: false },
  { name: "mailnews.display.disable_format_flowed_support", value: true },

  // Auto-config (DNS-leak vector)
  { name: "mailnews.auto_config.fetchFromISP.v2", value: false },
  { name: "mailnews.auto_config_url", value: "" },
  { name: "mailnews.mx_service_url", value: "" },
  { name: "mailnews.auto_config.guess.enabled", value: false },

  // Startup network beacons that fire before/during addon load
  { name: "network.connectivity-service.enabled", value: false },
  { name: "network.captive-portal-service.enabled", value: false },
  { name: "browser.safebrowsing.malware.enabled", value: false },
  { name: "browser.safebrowsing.phishing.enabled", value: false },
  { name: "extensions.blocklist.enabled", value: false },
  { name: "media.gmp-manager.url", value: "" },
  { name: "services.settings.server", value: "" },
  { name: "dom.push.serverURL", value: "" },

  // Update phone-home — TB and the addon system both ping Mozilla on a
  // schedule. Even routed through SOCKS these are HTTP beacons that
  // disclose the addon set and TB version to an observer. Tor users
  // typically update out-of-band (Tails/Whonix package updates).
  { name: "app.update.enabled", value: false },
  { name: "app.update.auto", value: false },
  { name: "app.update.background.scheduling.enabled", value: false },
  { name: "app.update.url", value: "" },
  { name: "extensions.update.enabled", value: false },
  { name: "extensions.update.url", value: "" },
  { name: "extensions.systemAddon.update.enabled", value: false },

  // OCSP + speculative-connect (F-022): OCSP fires a clearnet HTTP
  // request to the issuing CA on every TLS handshake — that's an
  // independent system-DNS lookup + connect that the addon's SOCKS
  // routing doesn't fully cover. Tradeoff: revoked certs are accepted.
  // For a Tor-anonymity profile this is the right call; for everyone
  // else it's a regression. Document loudly in README.
  { name: "security.OCSP.enabled", value: 0 },
  { name: "security.OCSP.require", value: false },
  { name: "network.http.speculative-parallel-limit", value: 0 },
  { name: "network.predictor.enable-prefetch", value: false },

  // Round-4 P0-2: crash reporter sends minidump + addon list + locale
  // + OS build to crash-reports.mozilla.com over CLEARNET (separate
  // process, doesn't honor network.proxy). Disable at the URL level so
  // even a re-enabled crash reporter can't beacon.
  { name: "breakpad.reportURL", value: "" },
  { name: "toolkit.crashreporter.include_extensions", value: false },
  { name: "toolkit.crashreporter.submitURL", value: "" },

  // Round-4 P0-3: lock off Mozilla Sync / Firefox Accounts. If a user
  // ever activates FxA, profile creds + address book replicate to
  // accounts.firefox.com. Default-off, locked here for defense.
  { name: "services.sync.enabled", value: false },
  { name: "services.sync.serverURL", value: "" },
  { name: "identity.fxaccounts.enabled", value: false },

  // Round-4 P0-4: desktop notifications expose IMAP-IDLE arrival
  // events AND sender + subject of incoming mail to libnotify / dbus
  // (Linux) / Action Center (Windows) — every process on the session
  // bus sees the leak.
  { name: "mail.biff.show_alert", value: false },
  { name: "mail.biff.show_tray_icon", value: false },
  { name: "mail.biff.use_system_alert", value: false },
  { name: "mailnews.notifications.enabled", value: false },

  // Round-4 P0-D: TRR endpoint+bootstrap cleared. trr.mode=5 is the
  // primary off-switch, but a saved URI lets a future mode-flip resume
  // DoH lookups immediately.
  { name: "network.trr.uri", value: "" },
  { name: "network.trr.custom_uri", value: "" },
  { name: "network.trr.bootstrapAddress", value: "" },
  { name: "network.trr.confirmationNS", value: "skip" },

  // Round-4 P1-1: TLS floor. Since OCSP is off (revoked certs accepted),
  // raise everything else. 0-RTT in particular is a replay channel for
  // SMTP's deterministic command sequence.
  { name: "security.tls.version.min", value: 3 },           // TLS 1.2
  { name: "security.tls.version.enable-deprecated", value: false },
  { name: "security.tls.enable_0rtt_data", value: false },
  { name: "security.ssl.require_safe_negotiation", value: true },

  // Round-4 P1-3: ICE-no-host. peerconnection.enabled=false already,
  // but Mozilla has regressed twice (bugs 1265719, 1407056) — these
  // pin the no-host behaviour so a regression can't leak host candidates.
  { name: "media.peerconnection.ice.no_host", value: true },
  { name: "media.peerconnection.ice.default_address_only", value: true },
  { name: "media.peerconnection.ice.proxy_only_if_behind_proxy", value: true },

  // Round-4 P1-5: ECH (Encrypted Client Hello) requires an independent
  // HTTPS-RR DNS lookup that lives outside the SOCKS-remote-DNS path.
  { name: "network.dns.echconfig.enabled", value: false },
  { name: "network.dns.use_https_rr_as_altsvc", value: false },

  // Round-4 P1-6: TB-specific update URL distinct from app.update.url.
  { name: "mail.update.url", value: "" },

  // Round-4 P1-10: send format and charset. Default send_format=4
  // emits multipart/alternative (text/plain AND text/html). We force
  // plaintext-only to drop the wrapper; UTF-8 charset eliminates the
  // de_DE-vs-en_US disclosure in Content-Type.
  { name: "mailnews.send_format", value: 1 },
  { name: "mailnews.send_default_charset", value: "UTF-8" },
  { name: "mailnews.view_default_charset", value: "UTF-8" },

  // Round-4 P2-1: DOM features no mail client should invoke. Belt-and-
  // braces against regressions that expose them via HTML mail rendering.
  { name: "dom.serviceWorkers.enabled", value: false },
  { name: "dom.push.enabled", value: false },
  { name: "dom.indexedDB.enabled", value: false },
  { name: "dom.storageManager.enabled", value: false },
  { name: "dom.webnotifications.enabled", value: false },
  { name: "dom.battery.enabled", value: false },
  { name: "dom.vr.enabled", value: false },
  { name: "dom.gamepad.enabled", value: false },

  // Round-4 P2-2: Media APIs (DRM phones home to Widevine CDN; getUserMedia
  // exposes mic/cam; webspeech leaks to Google's recognition service).
  { name: "media.eme.enabled", value: false },
  { name: "media.gmp-widevinecdm.enabled", value: false },
  { name: "media.navigator.enabled", value: false },
  { name: "media.webspeech.recognition.enable", value: false },
  { name: "media.webspeech.synth.enabled", value: false },
  { name: "media.autoplay.default", value: 5 },

  // Round-4 P2-3: IDN homograph defense. Force punycode display in
  // From: addresses so spoofs (paypa1.com with Cyrillic а) are visible.
  { name: "network.IDN_show_punycode", value: true },

  // Round-4 P2-4: cookie store hardening in mail context. Session-only
  // + reject-trackers eliminates the durable cross-message tracking
  // surface that survives even with remote images off (HTML attachments
  // opened in-context).
  { name: "network.cookie.cookieBehavior", value: 5 },
  { name: "network.cookie.lifetimePolicy", value: 2 },

  // Round-4 P2-6: phishing/scam-detection URL list — local check only;
  // empty the list so no network update fires.
  { name: "mailnews.scam_detection.url_indicators", value: "" },

  // Round-4 P2-7: address-book auto-collect off. Otherwise every Tor-
  // routed recipient lands in "Collected Addresses" as durable local
  // evidence of who the user mailed.
  { name: "mail.collect_email_address_outgoing", value: false },
  { name: "ldap_2.autoComplete.useDirectory", value: false },

  // Round-4 P3-1/P3-4: small final-mile beacons.
  // F-167: must be a *parseable URL* even though we want it dead — TB's
  // `moz-support-link.mjs` does `new URL(supportPage, app.support.baseURL)`
  // for every "?" help icon (about:addons, Options dialogs, …). Setting
  // this to "" makes the URL constructor throw `TypeError: ... is not a
  // valid URL` and spams the browser console with one error per rendered
  // help link. The `.invalid` TLD is RFC-2606-reserved as guaranteed
  // unresolvable, so click-through fails cleanly without the JS-error
  // cascade — same phone-home suppression, no UI fallout.
  { name: "app.support.baseURL", value: "https://onionbird.invalid/" },
  { name: "intl.accept_languages", value: "en-US, en" },

  // Round-4 P1-7: captive-portal/connectivity URLs blank even though
  // the services are off — defense if a future re-enable kicks in.
  { name: "captivedetect.canonicalURL", value: "" },
  { name: "network.connectivity-service.IPv4.url", value: "" },
  { name: "network.connectivity-service.IPv6.url", value: "" },

  // Telemetry / health-report submission. Historically these lived only
  // in user-js/onionbird-user.js, which left a hole: a user who
  // installs the XPI without running install-user-js.sh kept telemetry
  // ON. README claim "no telemetry" must hold for the addon-only path,
  // so re-assert at runtime.
  { name: "toolkit.telemetry.enabled", value: false },
  { name: "datareporting.healthreport.uploadEnabled", value: false },
  { name: "datareporting.policy.dataSubmissionEnabled", value: false },
  { name: "toolkit.telemetry.archive.enabled", value: false },
  { name: "toolkit.telemetry.bhrPing.enabled", value: false },
  { name: "toolkit.telemetry.firstShutdownPing.enabled", value: false },
  { name: "toolkit.telemetry.newProfilePing.enabled", value: false },
  { name: "toolkit.telemetry.shutdownPingSender.enabled", value: false },
  { name: "toolkit.telemetry.updatePing.enabled", value: false },

  // IMAP / NNTP client-info disclosure: leaks TB version + locale in
  // ID/CAPABILITY responses to clearnet IMAP servers. Same gap as
  // telemetry — needs to be enforced at runtime, not only via user.js.
  { name: "mail.imap.use_client_info", value: false },
  { name: "mail.server.default.send_client_info", value: false },
];

const HARDENING_PREF_NAMES = HARDENING_PREFS.map((p) => p.name);
const STORAGE_KEY = "onionbird.snapshot";
// Application-layer send-block: when the canary reports leak_detected
// or an inconclusive verdict, store the verdict here so the compose
// onBeforeSend hook can cancel sends instead of relying solely on
// Mozilla honoring `network.proxy.failover_direct=false`.
const LEAK_VERDICT_KEY = "onionbird.leakVerdict";
const ACCOUNT_REASSERT_MS = 60 * 1000;
const SELF_TEST_INTERVAL_MS = 10 * 60 * 1000;
// F-078: after an inconclusive verdict the listener blocks every
// send. Retry the canary quickly a few times before backing off to
// the normal SELF_TEST_INTERVAL_MS, so a transient hiccup doesn't
// keep blocking for the full 10 min interval. 3 retries at 30 s
// each plus the next periodic = total ≤ 1.5 min remediation window
// for the common transient case (vs ~10 min before this finding).
const INCONCLUSIVE_RETRY_MS = 30 * 1000;
const INCONCLUSIVE_RETRY_LIMIT = 3;
const MAX_DNS_HOST_LENGTH = 253;
const MAX_DNS_LABEL_LENGTH = 63;
const MAX_PREF_NAME_LENGTH = 256;
const MAX_PREF_STRING_LENGTH = 65536;
const MAX_SNAPSHOT_ENTRIES = 4096;
const PREF_INT_MIN = -2147483648;
const PREF_INT_MAX = 2147483647;
const MESSAGE_ID_FQDN_LABEL_SHAPE =
  /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
const ALL_NUMERIC_IPV4_SHAPE = /^\d{1,3}(\.\d{1,3}){1,3}$/;
const SNAPSHOT_SMTP_PREF_RE =
  /^mail\.smtpserver\.[A-Za-z0-9_]+\.(hello_argument|try_ssl)$/;
const SNAPSHOT_IDENTITY_PREF_RE =
  /^mail\.identity\.[A-Za-z0-9_]+\.(FQDN|compose_html|reply_to|organization|attach_vcard|attach_signature|htmlSigText|htmlSigFormat)$/;
const MESSAGE_ID_FQDN_MODES = new Set([
  "from_domain",
  "localhost",
  "localhost.localdomain",
  "custom",
]);
const CORE_FAIL_CLOSED_PREF_NAMES = new Set([
  "network.proxy.type",
  "network.proxy.socks",
  "network.proxy.socks_port",
  "network.proxy.socks_version",
  "network.proxy.socks_remote_dns",
  "network.proxy.failover_direct",
  "network.proxy.no_proxies_on",
  "network.trr.mode",
  "network.dns.disableIPv6",
  "network.dns.disablePrefetch",
  "network.predictor.enabled",
  "network.prefetch-next",
  "mailnews.headers.sendUserAgent",
  "privacy.resistFingerprinting",
  "mailnews.message_display.disable_remote_image",
  "mailnews.display.html_as",
  "mailnews.display.prefer_plaintext",
  "mailnews.display.disallow_mime_handlers",
  "mailnews.auto_config.fetchFromISP.v2",
  "mailnews.auto_config_url",
  "mailnews.mx_service_url",
  "mailnews.auto_config.guess.enabled",
  "network.connectivity-service.enabled",
  "network.captive-portal-service.enabled",
  "security.OCSP.enabled",
  "security.OCSP.require",
  "network.http.speculative-parallel-limit",
]);

// Shared mutation queue (P0-T3-1): prevent overlapping enable/disable/reassert
// calls from corrupting the snapshot or racing pref restore vs re-apply. UI
// button-disable is not enough — anything that can `runtime.sendMessage`
// (a future companion addon, devtools) bypasses the UI.
let _hardeningMutationTail = Promise.resolve();
let _reassertInflight = null;
let _accountReassertTimer = null;
let _selfTestTimer = null;
let _accountReassertListenersStarted = false;
let _accountReassertHandlers = [];
// F-078: per-process count of consecutive inconclusive verdicts.
// Reset to 0 on any non-inconclusive result (clean or leak_detected).
let _inconclusiveRetries = 0;
let _inconclusiveRetryTimer = null;

function summarizeResult(result, appliedKey, failedKey) {
  const applied = Array.isArray(result && result[appliedKey])
    ? result[appliedKey].length
    : 0;
  const failed = Array.isArray(result && result[failedKey])
    ? result[failedKey].length
    : 0;
  return { applied, failed };
}

function countItems(value) {
  return Array.isArray(value) ? value.length : 0;
}

function maskIpForLog(ip) {
  if (!ip) return null;
  if (typeof ip !== "string" && typeof ip !== "number") return "<non-ip>";
  const value = String(ip);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    const parts = value.split(".");
    return `${parts[0]}.x.x.${parts[3]}`;
  }
  if (value.indexOf(":") !== -1) {
    const parts = value.split(":").filter(Boolean);
    if (parts.length <= 2) return "<ipv6>";
    return `${parts[0]}:...:${parts[parts.length - 1]}`;
  }
  return "<non-ip>";
}

function summarizeErrorForLog(error) {
  if (typeof error !== "string" || !error) return null;
  const text = error;
  if (/refused/i.test(text)) return "refused";
  if (/timeout/i.test(text)) return "timeout";
  if (/network unreachable|ENETUNREACH/i.test(text)) return "network-unreachable";
  if (/dns/i.test(text)) return "dns-error";
  if (/invalid/i.test(text)) return "invalid-input";
  return "error";
}

function summarizeSocksForLog(socks) {
  if (!socks) return null;
  return {
    ok: !!socks.ok,
    verified: !!socks.verified,
    source: typeof socks.source === "string" && socks.source ? socks.source : null,
    host: socks.host === "127.0.0.1" || socks.host === "localhost" || socks.host === "::1"
      ? socks.host
      : (typeof socks.host === "string" && socks.host ? "<configured>" : null),
    port: Number.isInteger(socks.port) ? socks.port : null,
    probes: countItems(socks.probes),
    error: summarizeErrorForLog(socks.error),
  };
}

function summarizeSocksProbeForLog(probe) {
  if (!probe) return null;
  return {
    source: typeof probe.source === "string" && probe.source ? probe.source : null,
    socks_host: probe.socks_host === "127.0.0.1" ||
        probe.socks_host === "localhost" ||
        probe.socks_host === "::1"
      ? probe.socks_host
      : (typeof probe.socks_host === "string" && probe.socks_host
        ? "<configured>"
        : null),
    socks_port: Number.isInteger(probe.socks_port) ? probe.socks_port : null,
    probe_host: typeof probe.host === "string" && probe.host ? "<probe-host>" : null,
    ok: !!probe.ok,
    error: summarizeErrorForLog(probe.error),
  };
}

function summarizeSelfTestForLog(result) {
  if (!result) return null;
  return {
    host: typeof result.host === "string" && result.host ? result.host : null,
    socks_host: result.socks_host === "127.0.0.1" ||
        result.socks_host === "localhost" ||
        result.socks_host === "::1"
      ? result.socks_host
      : (typeof result.socks_host === "string" && result.socks_host
        ? "<configured>"
        : null),
    socks_port: Number.isInteger(result.socks_port) ? result.socks_port : null,
    tor_ip_count: countItems(result.tor_ips),
    system_ip: maskIpForLog(result.system_ip),
    system_ip_count: countItems(result.system_ips),
    system_ptr_present: !!result.system_ptr,
    errors_count: countItems(result.errors),
    leak_detected: !!result.leak_detected,
    error: summarizeErrorForLog(result.error),
  };
}

function summarizeListResultForLog(result) {
  if (!result || typeof result !== "object") return null;
  const out = {};
  for (const key of [
    "applied",
    "failed",
    "skipped",
    "cleared",
    "removed",
    "rolled_back",
    "rollback_failed",
    "origins",
    "logins",
  ]) {
    if (Array.isArray(result[key])) out[`${key}_count`] = result[key].length;
  }
  if (typeof result.count === "number") out.count = result.count;
  if (typeof result.mode === "string") out.mode = result.mode;
  if (typeof result.skipped === "string") out.skipped = result.skipped;
  return out;
}

function summarizeHardeningResultForLog(result) {
  if (!result || typeof result !== "object") return null;
  return {
    ok: !!result.ok,
    reason: typeof result.reason === "string" && result.reason ? result.reason : null,
    socks: summarizeSocksForLog(result.socks),
    selfTest: summarizeSelfTestForLog(result.selfTest),
    prefs: summarizeListResultForLog(result.prefs),
    failClosed: summarizeListResultForLog(result.failClosed),
    smtp: summarizeListResultForLog(result.smtp),
    identities: summarizeListResultForLog(result.identities),
    logins: summarizeListResultForLog(result.logins),
  };
}

function hasFailures(result, key = "failed") {
  return Array.isArray(result && result[key]) && result[key].length > 0;
}

function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function isAllowedSnapshotPrefName(name) {
  return typeof name === "string" &&
    name.length > 0 &&
    name.length <= MAX_PREF_NAME_LENGTH &&
    (
      HARDENING_PREF_NAMES.includes(name) ||
      SNAPSHOT_SMTP_PREF_RE.test(name) ||
      SNAPSHOT_IDENTITY_PREF_RE.test(name)
    );
}

function isValidSnapshotValue(value) {
  return value === null ||
    typeof value === "boolean" ||
    (
      typeof value === "string" &&
      value.length <= MAX_PREF_STRING_LENGTH &&
      value.indexOf("\0") === -1
    ) ||
    (
      typeof value === "number" &&
      Number.isInteger(value) &&
      value >= PREF_INT_MIN &&
      value <= PREF_INT_MAX
    );
}

function snapshotValidationError(snapshot) {
  if (!isPlainObject(snapshot)) {
    return "snapshot must be an object";
  }
  const entries = Object.entries(snapshot);
  if (entries.length > MAX_SNAPSHOT_ENTRIES) {
    return `snapshot too large (max ${MAX_SNAPSHOT_ENTRIES})`;
  }
  for (const [name, value] of entries) {
    if (!isAllowedSnapshotPrefName(name)) {
      return `snapshot contains unknown pref: ${safeRuntimeCommand(name)}`;
    }
    if (!isValidSnapshotValue(value)) {
      return `snapshot contains invalid value for ${safeRuntimeCommand(name)}`;
    }
  }
  return null;
}

function enqueueHardeningMutation(label, fn) {
  const run = _hardeningMutationTail
    .catch((e) => {
      console.warn("[onionbird] previous hardening mutation failed:", e);
    })
    .then(() => {
      console.log(`[onionbird] hardening mutation: ${label}`);
      return fn();
    });
  _hardeningMutationTail = run.catch(() => undefined);
  return run;
}

function normalizeSocksPort(port) {
  if (port === undefined || port === null || port === "") return null;
  let n;
  if (typeof port === "number") {
    n = port;
  } else if (typeof port === "string" && /^[1-9]\d{0,4}$/.test(port.trim())) {
    n = Number(port.trim());
  } else {
    throw new Error(`invalid SOCKS port: ${port}`);
  }
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    throw new Error(`invalid SOCKS port: ${port}`);
  }
  return n;
}

function parseStrictIpv4Address(host) {
  if (typeof host !== "string") return null;
  const octets = host.split(".");
  if (octets.length !== 4) return null;
  const nums = [];
  for (const octet of octets) {
    if (!/^(0|[1-9]\d{0,2})$/.test(octet)) return null;
    const n = Number(octet);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    if (String(n) !== octet) return null;
    nums.push(n);
  }
  return nums;
}

function isValidIpv6Literal(host) {
  if (typeof host !== "string") return false;
  const value = host.toLowerCase();
  if (value === "::" || value.indexOf(":") === -1) return false;
  if (!/^[0-9a-f:]+$/.test(value)) return false;
  if ((value.match(/::/g) || []).length > 1) return false;
  if (value.includes("::")) {
    const [head, tail] = value.split("::");
    if (head.endsWith(":") || tail.startsWith(":")) return false;
    const headParts = head ? head.split(":") : [];
    const tailParts = tail ? tail.split(":") : [];
    const total = headParts.length + tailParts.length;
    return total > 0 &&
      total < 8 &&
      headParts.concat(tailParts).every(part => /^[0-9a-f]{1,4}$/.test(part));
  }
  const parts = value.split(":");
  return parts.length === 8 &&
    parts.every(part => /^[0-9a-f]{1,4}$/.test(part));
}

function isValidSocksDnsName(host) {
  if (typeof host !== "string") return false;
  const value = host.replace(/\.$/, "");
  if (!value || value.length > MAX_DNS_HOST_LENGTH) return false;
  const labels = value.split(".");
  return labels.every(label =>
    label.length > 0 &&
    label.length <= MAX_DNS_LABEL_LENGTH &&
    /^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?$/.test(label)
  );
}

function isValidSocksHost(host) {
  if (typeof host !== "string") return false;
  const value = host;
  return value === "localhost" ||
    !!parseStrictIpv4Address(value) ||
    isValidIpv6Literal(value) ||
    isValidSocksDnsName(value);
}

function normalizeSocksHost(host) {
  if (typeof host !== "string") {
    throw new Error("invalid SOCKS host: <invalid>");
  }
  const value = host.trim();
  if (!isValidSocksHost(value)) {
    throw new Error(`invalid SOCKS host: ${value || "<empty>"}`);
  }
  return value;
}

function socksHostCompareKey(host) {
  return String(host || "").trim().toLowerCase();
}

function isIpv4LoopbackAddress(host) {
  const nums = parseStrictIpv4Address(host);
  return !!nums && nums[0] === 127;
}

function isLoopbackSocksHost(host) {
  // See the matching comment in experiments/onionbird/implementation.js
  // for the `localhost` safety argument (Mozilla Bug 1220810 hard-codes
  // localhost resolution to 127.0.0.1 / ::1 ahead of the system resolver).
  if (typeof host !== "string") return false;
  const value = socksHostCompareKey(host);
  return value === "localhost" ||
    value === "::1" ||
    isIpv4LoopbackAddress(value);
}

function isIpLiteralSocksHost(host) {
  if (typeof host !== "string") return false;
  const value = socksHostCompareKey(host);
  return !!parseStrictIpv4Address(value) || isValidIpv6Literal(value);
}

function isSafeConfiguredSocksHost(host) {
  return isLoopbackSocksHost(host) || isIpLiteralSocksHost(host);
}

function safeConfiguredSocksHostOrDefault(host) {
  return isSafeConfiguredSocksHost(host) ? normalizeSocksHost(host) : DEFAULT_SOCKS_HOST;
}

function isValidDnsHost(host) {
  if (
    typeof host !== "string" ||
    host.length === 0 ||
    host.length > MAX_DNS_HOST_LENGTH ||
    ALL_NUMERIC_IPV4_SHAPE.test(host)
  ) {
    return false;
  }
  const labels = host.split(".");
  if (labels.length < 2) return false;
  if (labels.some(label => label.length === 0 || label.length > MAX_DNS_LABEL_LENGTH)) {
    return false;
  }
  return typeof host === "string" &&
    /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(host);
}

function normalizeProbeHost(host, fallback) {
  const raw = host === undefined || host === null || host === ""
    ? fallback
    : host;
  if (typeof raw !== "string") {
    throw new Error("invalid probe host (must be a DNS-shaped name)");
  }
  const value = raw.trim().toLowerCase().replace(/\.$/, "");
  if (!isValidDnsHost(value)) {
    throw new Error("invalid probe host (must be a DNS-shaped name)");
  }
  return value;
}

function isValidMessageIdFqdn(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_DNS_HOST_LENGTH ||
    ALL_NUMERIC_IPV4_SHAPE.test(value)
  ) {
    return false;
  }
  const labels = value.split(".");
  return labels.length >= 2 &&
    labels.every(label =>
      label.length > 0 &&
      label.length <= MAX_DNS_LABEL_LENGTH &&
      MESSAGE_ID_FQDN_LABEL_SHAPE.test(label)
    );
}

function safeRuntimeCommand(cmd) {
  const value = typeof cmd === "string" ? cmd : "<invalid>";
  return value.replace(/[^\w:-]/g, "_").slice(0, 64);
}

function isAccountReassertReason(reason) {
  return String(reason || "").startsWith("account-");
}

function setPrefValue(prefs, name, value) {
  const idx = prefs.findIndex((p) => p.name === name);
  if (idx < 0) {
    // F-096: throw on missing instead of silently no-op. All six
    // callers depend on specific prefs being in HARDENING_PREFS;
    // a future rename / removal that drops one would silently
    // skip the write under the old behaviour, routing users
    // through whatever pref value was previously in place
    // (potentially clearnet for the SOCKS prefs). A loud throw
    // surfaces the bug at the call-site instead of years later
    // in production.
    throw new Error(
      `setPrefValue: ${String(name)} not present in HARDENING_PREFS — ` +
      `a caller is referencing a pref that the canonical list does ` +
      `not include. Add the entry to HARDENING_PREFS (and ` +
      `ALLOWED_PREF_NAMES) or remove the caller.`
    );
  }
  prefs[idx] = { name, value };
}

function uniqueSocksCandidates(candidates) {
  const seen = new Set();
  const out = [];
  for (const c of candidates) {
    if (!c || !c.host || !c.port) continue;
    const key = `${c.host}:${c.port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(c);
  }
  return out;
}

async function isHardeningActive() {
  const snapshotState = await readSnapshotState();
  return !!snapshotState.snapshot;
}

async function detectSocksConfig({ socksHost, socksPort, probeHost } = {}) {
  const targetHost = normalizeProbeHost(probeHost, TOR_TEST_HOST);
  const candidates = [];
  const requestedPort = normalizeSocksPort(socksPort);
  if (requestedPort) {
    const requestedHost = socksHost ? normalizeSocksHost(socksHost) : DEFAULT_SOCKS_HOST;
    if (isSafeConfiguredSocksHost(requestedHost)) {
      candidates.push({
        host: requestedHost,
        port: requestedPort,
        source: "requested",
      });
    } else {
      console.warn(
        "[onionbird] requested SOCKS endpoint skipped: hostnames can leak DNS"
      );
    }
  }

  // F-168: user-configured SOCKS override has priority over existing
  // TB prefs and the fallback ladder, but not over caller-supplied
  // socksHost/socksPort (the latter is the explicit "use these now"
  // path — e.g. options.html "Test Tor now" with manually-entered
  // values — and must win). getSocksOverride returns null if either
  // half is missing or invalid, so the existing-pref candidate below
  // still fires for users who haven't touched the override at all.
  try {
    const override = await browser.onionbird.getSocksOverride();
    if (override && override.host && override.port) {
      candidates.push({
        host: override.host,
        port: override.port,
        source: "user-override",
      });
    }
  } catch (e) {
    console.warn("[onionbird] SOCKS override read failed:", e);
  }

  try {
    const prefHost = await browser.onionbird.getPref("network.proxy.socks");
    const prefPort = normalizeSocksPort(
      await browser.onionbird.getPref("network.proxy.socks_port")
    );
    if (prefHost && prefPort) {
      const normalizedPrefHost = normalizeSocksHost(prefHost);
      if (isSafeConfiguredSocksHost(normalizedPrefHost)) {
        candidates.push({
          host: normalizedPrefHost,
          port: prefPort,
          source: "existing-pref",
        });
      } else {
        console.warn(
          "[onionbird] existing SOCKS endpoint skipped: hostnames can leak DNS"
        );
      }
    }
  } catch (e) {
    console.warn("[onionbird] existing SOCKS pref inspection failed:", e);
  }

  candidates.push(
    { host: DEFAULT_SOCKS_HOST, port: DEFAULT_SOCKS_PORT, source: "system-tor" },
    { host: DEFAULT_SOCKS_HOST, port: TOR_BROWSER_SOCKS_PORT, source: "tor-browser" }
  );

  const probes = [];
  const uniqueCandidates = uniqueSocksCandidates(candidates);
  for (const c of uniqueCandidates) {
    // F-180: the user-override candidate carries the user's explicit
    // consent for this endpoint (they saved it via the Options page).
    // The gate's `currentSocksEndpointMatches` requirement was designed
    // to stop the addon from probing arbitrary remote IPs without user
    // consent — but saving an override IS the user consent. Without
    // this bypass the ladder rejects the user-override whenever TB's
    // existing `network.proxy.socks` differs (e.g. a fresh override
    // before the first enableHardening), and falls through to the
    // existing-pref / fallback candidates — silently ignoring the
    // user's configured endpoint. F-168 I-1 already established this
    // bypass for the Options-page "Test endpoint" button; the
    // run-tor-test / enableHardening ladder must honour the same logic.
    const probeOptions = c.source === "user-override"
      ? { userProbe: true }
      : undefined;
    const probe = await browser.onionbird.probeSocks(
      c.host, c.port, targetHost, probeOptions
    );
    probes.push({ ...probe, source: c.source });
    if (probe.ok) {
      console.log("[onionbird] SOCKS probe OK:", summarizeSocksProbeForLog({
        ...probe,
        source: c.source,
      }));
      return { ok: true, host: c.host, port: c.port, source: c.source, probes };
    }
  }

  const fallback = uniqueCandidates[0] || {
    host: DEFAULT_SOCKS_HOST,
    port: DEFAULT_SOCKS_PORT,
    source: "fallback",
  };
  console.warn("[onionbird] no reachable SOCKS proxy found; fail-closed prefs will apply", {
    probes: probes.map(summarizeSocksProbeForLog),
    fallback: summarizeSocksForLog(fallback),
  });
  return {
    ok: false,
    host: fallback.host,
    port: fallback.port,
    source: fallback.source,
    probes,
    error: "no reachable SOCKS proxy found",
  };
}

function publicSocksProbe(probe) {
  const socksPort = probe && Number.isInteger(probe.socks_port)
    ? probe.socks_port
    : null;
  return {
    source: probe && typeof probe.source === "string" && probe.source
      ? probe.source
      : null,
    socks_host: probe && typeof probe.socks_host === "string" && probe.socks_host
      ? probe.socks_host
      : null,
    socks_port: socksPort,
    host: probe && typeof probe.host === "string" && probe.host ? probe.host : null,
    ok: !!(probe && probe.ok),
    error: probe && typeof probe.error === "string" && probe.error ? probe.error : null,
  };
}

async function runTorReadinessTest({ socksHost, socksPort, host } = {}) {
  const probeHost = normalizeProbeHost(host, TOR_TEST_HOST);
  const socks = await detectSocksConfig({ socksHost, socksPort, probeHost });
  const probes = Array.isArray(socks.probes)
    ? socks.probes.map(publicSocksProbe)
    : [];
  return {
    ok: !!socks.ok,
    mode: "tor-readiness",
    anonymous: true,
    changedPrefs: false,
    host: probeHost,
    socks: socks.ok
      ? { host: socks.host, port: socks.port, source: socks.source }
      : null,
    probes,
    error: socks.ok ? null : (socks.error || "no reachable Tor SOCKS proxy found"),
  };
}

async function readCurrentSocksConfig() {
  try {
    const host = normalizeSocksHost(
      await browser.onionbird.getPref("network.proxy.socks")
    );
    const port = normalizeSocksPort(
      await browser.onionbird.getPref("network.proxy.socks_port")
    );
    if (host && port && isSafeConfiguredSocksHost(host)) {
      return { ok: true, verified: false, host, port, source: "current-pref" };
    }
    if (host && port) {
      console.warn(
        "[onionbird] current SOCKS endpoint ignored: hostnames can leak DNS"
      );
    }
  } catch (e) {
    console.warn("[onionbird] current SOCKS pref inspection failed:", e);
  }
  return null;
}

async function hardeningPrefsWithDetectedSocks(options = {}) {
  const prefs = [...HARDENING_PREFS];
  const socks = await detectSocksConfig({ probeHost: SELF_TEST_HOST, ...options });
  setPrefValue(prefs, "network.proxy.socks", socks.host);
  setPrefValue(prefs, "network.proxy.socks_port", socks.port);
  return { prefs, socks };
}

async function hardeningPrefsWithCurrentSocks() {
  const prefs = [...HARDENING_PREFS];
  const socks = await readCurrentSocksConfig() || await detectSocksConfig();
  setPrefValue(prefs, "network.proxy.socks", socks.host);
  setPrefValue(prefs, "network.proxy.socks_port", socks.port);
  return { prefs, socks };
}

function coreFailClosedPrefs(socks = {}) {
  const host = socks && socks.host
    ? safeConfiguredSocksHostOrDefault(socks.host)
    : DEFAULT_SOCKS_HOST;
  let port = DEFAULT_SOCKS_PORT;
  try {
    port = normalizeSocksPort(socks && socks.port) || DEFAULT_SOCKS_PORT;
  } catch (e) {
    console.warn("[onionbird] invalid fail-closed SOCKS port; using default");
  }
  const prefs = HARDENING_PREFS.filter((p) => CORE_FAIL_CLOSED_PREF_NAMES.has(p.name));
  setPrefValue(prefs, "network.proxy.socks", host);
  setPrefValue(prefs, "network.proxy.socks_port", port);
  return prefs;
}

async function applyFailClosedPrefs(reason, socks) {
  const prefs = coreFailClosedPrefs(socks);
  const result = await browser.onionbird.applyPrefs(prefs);
  if (hasFailures(result)) {
    console.error(`[onionbird] ${reason}: fail-closed pref apply failed`, {
      failed: countItems(result.failed),
    });
  } else {
    console.warn(`[onionbird] ${reason}: core fail-closed prefs applied`, {
      applied: countItems(result.applied),
      socks: summarizeSocksForLog(socks),
    });
  }
  return result;
}

async function getMessageIdFqdnPrefs() {
  const mode = await browser.onionbird.getPref("onionbird.messageid.fqdn_mode");
  const custom = await browser.onionbird.getPref("onionbird.messageid.fqdn_custom");
  return {
    mode: MESSAGE_ID_FQDN_MODES.has(mode) ? mode : "from_domain",
    custom: typeof custom === "string" ? custom : "",
  };
}

async function saveMessageIdFqdnPrefs({ mode, custom } = {}) {
  return enqueueHardeningMutation("message-id-fqdn", async () => {
    const normalizedMode = MESSAGE_ID_FQDN_MODES.has(mode) ? mode : "from_domain";
    const normalizedCustom = typeof custom === "string" ? custom.trim() : "";
    if (normalizedMode === "custom" && !isValidMessageIdFqdn(normalizedCustom)) {
      return { ok: false, error: "invalid Message-ID FQDN" };
    }
    const modeOk = await browser.onionbird.setPref(
      "onionbird.messageid.fqdn_mode",
      normalizedMode
    );
    let customOk = true;
    if (normalizedMode === "custom") {
      customOk = await browser.onionbird.setPref(
        "onionbird.messageid.fqdn_custom",
        normalizedCustom
      );
    }
    if (!modeOk || !customOk) {
      return { ok: false, error: "could not store Message-ID prefs" };
    }
    const hardeningActive = !!(await getStoredSnapshot());
    const identities = hardeningActive
      ? await browser.onionbird.applyHardeningToAllIdentities()
      : { applied: [], failed: [], mode: normalizedMode, inactive: true };
    return {
      ok: !hasFailures(identities),
      hardeningActive,
      mode: normalizedMode,
      custom: normalizedMode === "custom" ? normalizedCustom : "",
      identities,
    };
  });
}

async function getStoredSnapshot() {
  return (await readSnapshotState()).snapshot;
}

async function readSnapshotState() {
  // F-072: catch storage backend errors here, do NOT let them
  // propagate through isHardeningActive into the compose.onBeforeSend
  // listener — a rejected Promise from an async webExt listener
  // resolves to `undefined`, which TB treats as "no objection" and
  // proceeds with the send (fail-OPEN). Returning a corrupt-marker
  // with a distinct `storage-error` reason lets the listener
  // fail-CLOSED while preserving triage signal.
  let stored;
  try {
    stored = await browser.storage.local.get(STORAGE_KEY);
  } catch (e) {
    console.error("[onionbird] readSnapshotState storage error:", e);
    return { snapshot: null, corrupt: true, reason: "storage-error" };
  }
  if (!(STORAGE_KEY in stored) || stored[STORAGE_KEY] === null) {
    return { snapshot: null, corrupt: false, reason: null };
  }
  const snapshot = stored[STORAGE_KEY];
  const invalid = snapshotValidationError(snapshot);
  if (invalid) {
    console.error(
      `[onionbird] invalid hardening snapshot ignored: ${invalid}; ` +
      "staying fail-closed"
    );
    return { snapshot: null, corrupt: true, reason: invalid };
  }
  return { snapshot, corrupt: false, reason: null };
}

async function storeSnapshot(snapshot) {
  const invalid = snapshotValidationError(snapshot);
  if (invalid) {
    throw new Error(`refusing to store invalid hardening snapshot: ${invalid}`);
  }
  await browser.storage.local.set({ [STORAGE_KEY]: snapshot });
}

async function snapshotMissingPrefs(snapshot, names, label) {
  const uniqueNames = [...new Set((names || []).filter((n) => typeof n === "string"))];
  const missing = uniqueNames.filter((n) => !(n in snapshot));
  if (missing.length === 0) return snapshot;

  console.log(`[onionbird] expanding snapshot with ${missing.length} ${label} pref(s)`);
  const additionalSnap = await browser.onionbird.snapshotPrefs(missing);
  const merged = { ...snapshot, ...additionalSnap };
  await storeSnapshot(merged);
  return merged;
}

async function expandSnapshotForCurrentAccounts(snapshot) {
  let merged = snapshot;
  try {
    const smtp = await browser.onionbird.getSmtpHardeningPrefNames(true);
    if (hasFailures(smtp)) {
      console.warn("[onionbird] SMTP pref-name discovery failures:", {
        failed: countItems(smtp.failed),
      });
    }
    merged = await snapshotMissingPrefs(merged, smtp.names || [], "SMTP");
  } catch (e) {
    console.error("[onionbird] SMTP snapshot expansion failed:", e);
  }

  try {
    const identities = await browser.onionbird.getIdentityHardeningPrefNames();
    if (hasFailures(identities)) {
      console.warn("[onionbird] identity pref-name discovery failures:", {
        failed: countItems(identities.failed),
      });
    }
    merged = await snapshotMissingPrefs(merged, identities.names || [], "identity");
  } catch (e) {
    console.error("[onionbird] identity snapshot expansion failed:", e);
  }
  return merged;
}

async function ensureHardeningSnapshot() {
  // F-077: distinguish "no snapshot" (fresh install) from
  // "corrupt snapshot" (storage value present but unparseable /
  // wrong shape / storage-error). In the no-snapshot case it's
  // fine to capture the live pref state — they're the user's
  // genuine pre-hardening values. In the corrupt-snapshot case
  // the live state may already be HARDENED (we hardened in a
  // previous session, then storage corrupted) — capturing that
  // would silently make `disableHardening` restore to the
  // hardened state forever (disable becomes a permanent no-op).
  // Pull from default-branch values (the underlying TB defaults)
  // when we know the snapshot was corrupt rather than absent.
  const snapshotState = await readSnapshotState();
  let snapshot = snapshotState.snapshot;
  if (!snapshot) {
    if (snapshotState.corrupt) {
      console.warn(
        "[onionbird] ensureHardeningSnapshot: previous snapshot was " +
        "corrupt (reason=" + snapshotState.reason + "); refusing to " +
        "capture the live pref state, which may already be hardened. " +
        "Snapshotting from default-branch values instead so disable " +
        "can later restore to a sane baseline."
      );
      snapshot = await browser.onionbird.snapshotPrefs(
        HARDENING_PREF_NAMES,
        { source: "default" }
      );
    } else {
      // Genuine fresh install: live values ARE the user's pre-
      // hardening preferences.
      snapshot = await browser.onionbird.snapshotPrefs(HARDENING_PREF_NAMES);
    }
    await storeSnapshot(snapshot);
  }
  snapshot = await snapshotMissingPrefs(snapshot, HARDENING_PREF_NAMES, "global");
  return expandSnapshotForCurrentAccounts(snapshot);
}

async function enableHardening({ socksHost, socksPort } = {}) {
  return enqueueHardeningMutation(
    "enable",
    () => _enableHardeningImpl({ socksHost, socksPort })
  );
}

async function _enableHardeningImpl({ socksHost, socksPort } = {}) {
  console.log("[onionbird] enableHardening: starting");
  // F-080: write a transition-phase verdict immediately so the
  // compose.onBeforeSend listener fails closed for any send fired
  // while enable is still running. The listener treats anything
  // other than `state==="clean"` as block, so an
  // `enable-in-progress` value (or any inconclusive shape) blocks
  // until the success-path `clean` write below replaces it. This
  // closes the race window between startHardeningMonitors (which
  // can fire the periodic canary callback immediately) and the
  // final recordLeakVerdict on the success path.
  await recordLeakVerdict({
    state: "enable-in-progress",
    ts: Date.now(),
    source: "enable-start",
  });
  const { prefs, socks } = await hardeningPrefsWithDetectedSocks({ socksHost, socksPort });

  // Snapshot first so we can revert. If a snapshot already exists from a
  // previous enable (re-enable case after a partial restart), keep it —
  // re-snapshotting from already-hardened state would lose the original.
  await ensureHardeningSnapshot();

  // Apply with structured reporting.
  const prefResult = await browser.onionbird.applyPrefs(prefs);
  let failClosedResult = null;
  if (hasFailures(prefResult)) {
    failClosedResult = await applyFailClosedPrefs("enable-pref-failure", socks);
  }

  // Per-server / per-identity. B-003: harden ONLY onion (and loopback)
  // servers by default. Forcing STARTTLS + HELO=[127.0.0.1] on the user's
  // existing clearnet accounts (e.g. corporate Exchange, gmail) breaks
  // those sends. Opt-in to "harden every server" lands later as a UI toggle.
  const smtpResult = await browser.onionbird.applyHardeningToAllSmtpServers(true);
  const idResult = await browser.onionbird.applyHardeningToAllIdentities({ onlyOnionIdentities: true });
  const selfTest = await browser.onionbird.runSelfTest(
    SELF_TEST_HOST,
    { tries: 3, socksHost: socks.host, socksPort: socks.port }
  );
  const selfTestOk = !selfTest.error && !selfTest.leak_detected;
  if (!socks.ok || !selfTestOk) {
    failClosedResult = await applyFailClosedPrefs("enable-self-test-failure", socks);
  }

  if (
    !socks.ok ||
    !selfTestOk ||
    hasFailures(prefResult) ||
    hasFailures(smtpResult) ||
    hasFailures(idResult)
  ) {
    console.warn("[onionbird] enableHardening completed with failures:", {
      socks: summarizeSocksForLog(socks),
      selfTest: summarizeSelfTestForLog(selfTest),
      prefs: countItems(prefResult.failed),
      failClosed: failClosedResult ? countItems(failClosedResult.failed) : null,
      smtp: countItems(smtpResult.failed),
      identities: countItems(idResult.failed),
    });
  } else {
    console.log("[onionbird] enableHardening applied:", {
      prefs: summarizeResult(prefResult, "applied", "failed").applied,
      smtp: summarizeResult(smtpResult, "applied", "failed").applied,
      identities: summarizeResult(idResult, "applied", "failed").applied,
      skippedSmtp: Array.isArray(smtpResult.skipped) ? smtpResult.skipped.length : 0,
      socks: summarizeSocksForLog(socks),
    });
  }

  // Flush DNS + cached SMTP connections so stale clearnet IPs from a
  // pre-enable resolve don't survive into Tor mode. P1-1 (threat-model
  // review): without this, a TB session that ran clearnet for 30s before
  // enable would carry the cached IPs through the transition.
  try {
    await browser.onionbird.clearDnsCache();
  } catch (e) {
    console.error("[onionbird] clearDnsCache after enable failed:", e);
  }

  const ok = !hasFailures(prefResult) &&
    !hasFailures(smtpResult) &&
    !hasFailures(idResult) &&
    socks.ok &&
    selfTestOk;
  // F-042 + F-080: on success, replace the transition-phase
  // `enable-in-progress` marker with `clean`. On failure paths,
  // applyFailClosedPrefs above plus the listener's fail-closed
  // default (F-043) handle the safety net — the listener treats
  // the still-present `enable-in-progress` marker as non-clean
  // and blocks every send until the next canary either confirms
  // clean or replaces the marker. The verdict write happens
  // BEFORE startHardeningMonitors fires so the periodic-canary
  // callback can't race with a send that arrives at the same
  // moment.
  if (ok) {
    await recordLeakVerdict({ state: "clean", ts: Date.now(), source: "enable" });
  }
  startHardeningMonitors();
  return {
    ok,
    socks,
    selfTest,
    prefs: prefResult,
    failClosed: failClosedResult,
    smtp: smtpResult,
    identities: idResult,
  };
}

async function disableHardening({ scrubLogins } = {}) {
  return enqueueHardeningMutation(
    "disable",
    () => _disableHardeningImpl({ scrubLogins })
  );
}

async function _disableHardeningImpl({ scrubLogins } = {}) {
  console.log("[onionbird] disableHardening: restoring");
  const snapshotState = await readSnapshotState();
  const snapshot = snapshotState.snapshot;
  // P1-T3-8: surface "no snapshot" distinctly so the UI doesn't claim
  // success when nothing was changed. Silent no-op = user thinks they're
  // off Tor when they may still be on it (e.g. snapshot was wiped by a
  // storage.local.clear() but prefs persist).
  if (!snapshot) {
    const reason = snapshotState.corrupt
      ? "invalid snapshot — keeping current fail-closed prefs in place"
      : "no snapshot — hardening was never enabled in this profile";
    return {
      ok: false,
      reason,
      prefs: { restored: [], failed: [] },
      smtp: { cleared: [], failed: [] },
      identities: { cleared: [], failed: [] },
    };
  }

  // Clear per-server / per-identity hardening
  const smtpClear = await browser.onionbird.clearHardeningFromAllSmtpServers();
  const idClear = await browser.onionbird.clearHardeningFromAllIdentities();

  // Restore global prefs from snapshot. If snapshot has null (pref was unset),
  // clearUserPref. Otherwise restore the saved value.
  const restoreResult = await browser.onionbird.restorePrefs(snapshot);
  const loginResult = scrubLogins
    ? await browser.onionbird.removeSavedLoginsForTorServers()
    : await browser.onionbird.auditSavedLoginsForTorServers();

  if (scrubLogins) {
    if (hasFailures(loginResult)) {
      console.warn("[onionbird] saved-login cleanup completed with failures:", {
        failed: countItems(loginResult.failed),
      });
    } else {
      console.log("[onionbird] saved-login cleanup OK:", {
        removed: Array.isArray(loginResult.removed) ? loginResult.removed.length : 0,
      });
    }
  } else if (loginResult.count > 0) {
    console.warn(
      "[onionbird] saved login(s) for Tor mail servers remain after disable; " +
      "disable with scrubLogins=true to remove them",
      { count: loginResult.count }
    );
  }

  // Symmetric to enableHardening: flush DNS + cached SMTP connections so
  // Tor-routed IPs cached during the hardening period don't survive into
  // clearnet mode (and accidentally route the user via a now-rotated exit).
  try {
    await browser.onionbird.clearDnsCache();
  } catch (e) {
    console.error("[onionbird] clearDnsCache after disable failed:", e);
  }

  const ok = !hasFailures(restoreResult) &&
    !hasFailures(smtpClear) &&
    !hasFailures(idClear) &&
    !(scrubLogins && hasFailures(loginResult));

  // F-169: forensic-marker scrub MUST run regardless of restore-ok.
  // A single failed pref restore (one of 110+) previously left
  //   - storage.local snapshot + leak verdict in place (re-enable
  //     would re-snapshot from a hardened state, breaking the F-042
  //     fail-closed window)
  //   - addon-owned prefs in place — most acutely
  //     `onionbird.socks.host` if the user had configured a Whonix
  //     gateway override, which then persists in about:config as a
  //     "this user runs Whonix" forensic fingerprint surviving the
  //     explicit disable gesture (and surviving uninstall).
  // Each scrub is now in its own try/catch so a failure in one
  // doesn't cascade to the others. Final summary log still
  // distinguishes overall-ok from partial-failure.
  try {
    // F-042: clear BOTH the snapshot and the leak verdict. Leaving the
    // verdict behind means a stale `leak_detected` blocks every send
    // for up to 10 min after re-enable, while a stale `clean` lets the
    // gate be bypassed before the first canary fires post-re-enable.
    await browser.storage.local.remove([STORAGE_KEY, LEAK_VERDICT_KEY]);
  } catch (e) {
    console.error("[onionbird] storage.local scrub on disable failed:", e);
  }
  try {
    // F-076 + F-168 + F-169: clear the addon's own per-install prefs
    // (onionbird.messageid.fqdn_*, onionbird.socks.host/port) so neither
    // the per-install random `m<10hex>.invalid` fallback nor the user's
    // chosen SOCKS override survives disable as a forensic fingerprint.
    await browser.onionbird.clearAddonOwnedPrefs();
  } catch (e) {
    console.error("[onionbird] clearAddonOwnedPrefs on disable failed:", e);
  }

  if (ok) {
    stopHardeningMonitors();
    console.log("[onionbird] disableHardening restore OK");
  } else {
    console.warn("[onionbird] disableHardening completed with failures:",
      summarizeHardeningResultForLog({
        ok,
        prefs: restoreResult,
        smtp: smtpClear,
        identities: idClear,
        logins: loginResult,
      })
    );
  }
  return {
    ok,
    prefs: restoreResult,
    smtp: smtpClear,
    identities: idClear,
    logins: loginResult,
  };
}

browser.runtime.onMessage.addListener(async (msg, sender) => {
  if (!msg || typeof msg !== "object") return undefined;
  const senderId = sender && sender.id;
  if (senderId !== browser.runtime.id) {
    console.warn("[onionbird] rejected runtime message from unexpected sender");
    return { ok: false, error: "untrusted sender" };
  }
  if (typeof msg.cmd !== "string") {
    return { ok: false, error: "invalid command" };
  }
  const cmd = safeRuntimeCommand(msg.cmd);
  try {
    switch (msg.cmd) {
      case "enable-hardening":
        return await enableHardening();
      case "disable-hardening":
        return await disableHardening({ scrubLogins: !!msg.scrubLogins });
      case "get-status":
        return {
          version: VERSION,
          apiVersion: await browser.onionbird.getApiVersion(),
          hardeningActive: await isHardeningActive(),
        };
      case "run-self-test":
        return await browser.onionbird.runSelfTest(
          normalizeProbeHost(msg.host, SELF_TEST_HOST),
          { tries: 3 }
        );
      case "run-tor-test":
        return await runTorReadinessTest({
          host: msg.host,
        });
      case "get-message-id-fqdn":
        return await getMessageIdFqdnPrefs();
      case "save-message-id-fqdn":
        return await saveMessageIdFqdnPrefs({
          mode: msg.mode,
          custom: msg.custom,
        });
      // F-168 S-4: route the SOCKS-override surface through the same
      // runtime-message dispatch every other Options handler uses. The
      // Options page used to call browser.onionbird.* directly, but
      // that's a second pattern coexisting with the established
      // sendMessage indirection — future maintainers had to learn both.
      // Now all UI handlers route through background.js, which is the
      // sole experiment-API caller.
      case "get-socks-override":
        return await browser.onionbird.getSocksOverride();
      case "save-socks-override":
        return await browser.onionbird.setSocksOverridePair({
          host: msg.host,
          port: msg.port,
        });
      case "clear-socks-override":
        await browser.onionbird.setSocksOverride("host", "");
        await browser.onionbird.setSocksOverride("port", 0);
        return { ok: true };
      case "probe-socks-override":
        return await browser.onionbird.probeSocks(
          msg.host,
          msg.port,
          msg.target || SELF_TEST_HOST,
          { userProbe: true },
        );
      default:
        console.warn(`[onionbird] unknown runtime message: ${cmd}`);
        return undefined;
    }
  } catch (e) {
    console.error(`[onionbird] runtime message failed: ${cmd}`, e);
    return { ok: false, error: e.message || String(e) };
  }
});

function scheduleInconclusiveRetry() {
  // F-078: kick a short-window canary retry. Capped by
  // INCONCLUSIVE_RETRY_LIMIT so a permanently-broken environment
  // (Tor really gone) falls through to the normal 10-min interval
  // instead of busy-retrying forever. Reset to 0 on any
  // non-inconclusive verdict.
  if (_inconclusiveRetryTimer) return; // already scheduled
  if (_inconclusiveRetries >= INCONCLUSIVE_RETRY_LIMIT) return;
  _inconclusiveRetries += 1;
  _inconclusiveRetryTimer = setTimeout(() => {
    _inconclusiveRetryTimer = null;
    (async () => {
      const snapshot = await getStoredSnapshot();
      if (!snapshot) return; // disabled in the meantime
      await announceSelfTest();
    })().catch((e) =>
      console.error("[onionbird] F-078 inconclusive retry failed:", e)
    );
  }, INCONCLUSIVE_RETRY_MS);
}

async function announceSelfTest() {
  // 3 stream-isolated Tor lookups → union of plausibly-Tor IPs. Compares
  // the OS resolver's answer against that set. A "leak" verdict means
  // the OS path returned a non-private IP that no Tor circuit saw —
  // strong evidence the OS resolver is not Tor-routed.
  //
  // F-087: rotate the target host per-probe so a passive observer can't
  // fingerprint "this user runs OnionBird" from the periodic check.
  // torproject.org cadence. pickCanaryAnchorHost returns one of the
  // CANARY_ANCHOR_HOSTS pool (still includes check.torproject.org so
  // the canary's verdict semantics are unchanged for that anchor).
  try {
    const target = pickCanaryAnchorHost();
    const r = await browser.onionbird.runSelfTest(target, { tries: 3 });
    const summary = summarizeSelfTestForLog(r);
    if (r.error) {
      console.log("[onionbird] self-test inconclusive:", summary);
      // F-043: inconclusive verdicts now block sends (any non-clean
      // state fails closed in the compose.onBeforeSend listener).
      // Mozilla's failover_direct=false is the transport-layer
      // safety net but the user-visible action is the compose block.
      // F-078: schedule a fast retry up to INCONCLUSIVE_RETRY_LIMIT
      // times with short backoff, so a transient hiccup (laptop
      // wakeup, short circuit reset) doesn't block every send for
      // the full SELF_TEST_INTERVAL_MS (10 min) before the next
      // periodic canary fires.
      await recordLeakVerdict({
        state: "inconclusive",
        error: r.error,
        ts: Date.now(),
      });
      scheduleInconclusiveRetry();
      return;
    }
    if (r.leak_detected) {
      console.warn(
        "[onionbird] DNS LEAK SUSPECTED:",
        {
          ...summary,
          guidance: "Your OS resolver is likely not routed through Tor. " +
            "Route system DNS through a Tor DNSPort, or run Thunderbird inside Whonix / Tails.",
        }
      );
      // Application-layer block: persist the verdict and the compose
      // onBeforeSend hook will refuse outgoing sends until a re-test
      // clears the verdict. Without this the only fail-closed is
      // Mozilla's transport-layer failover_direct — which protects the
      // bytes but does not surface a clear refusal to the user.
      // F-078: any non-inconclusive verdict ends the fast-retry
      // chain. leak_detected is a different (worse) failure mode
      // that needs the normal periodic-canary cadence, not a
      // tight loop.
      _inconclusiveRetries = 0;
      await recordLeakVerdict({
        state: "leak_detected",
        ts: Date.now(),
        summary,
      });
      await reassertHardening("self-test-leak");
    } else {
      // Clean verdict — clear any stale block.
      // F-078: reset the fast-retry counter so a future
      // inconclusive starts the retry window fresh.
      _inconclusiveRetries = 0;
      await recordLeakVerdict({ state: "clean", ts: Date.now() });
      console.log("[onionbird] self-test OK:", summary);
    }
  } catch (e) {
    console.error("[onionbird] self-test failed:", e);
  }
}

// F-083: verdict-state allowlist. recordLeakVerdict accepted any object
// and persisted it verbatim — a typo at a writer (e.g. {state: "clena"})
// would silently start blocking every send forever because the read-side
// in compose.onBeforeSend treats anything other than `state === "clean"`
// as fail-closed. The allowlist gates the WRITE side; a stray typo now
// throws-or-drops instead of poisoning storage.local. The set is
// closed-by-design: any new state must be added here AND wired into the
// onBeforeSend listener's branch logic.
const VALID_VERDICT_STATES = new Set([
  "clean",
  "leak_detected",
  "inconclusive",
  "enable-in-progress",
]);

// Allowed keys on the persisted verdict object. Anything else is dropped
// at the normalize step to keep storage.local tidy (and to prevent a
// future canary bug from accidentally persisting PII / unbounded payloads).
const VERDICT_ALLOWED_KEYS = new Set(["state", "ts", "source", "error"]);

function normalizeLeakVerdict(input) {
  if (!input || typeof input !== "object") return null;
  if (!VALID_VERDICT_STATES.has(input.state)) {
    console.warn(
      `[onionbird] recordLeakVerdict rejected: unknown state ${String(input.state)}`
    );
    return null;
  }
  const out = {};
  for (const k of Object.keys(input)) {
    if (VERDICT_ALLOWED_KEYS.has(k)) out[k] = input[k];
  }
  if (typeof out.ts !== "number" || !Number.isFinite(out.ts)) {
    out.ts = Date.now();
  }
  return out;
}

async function recordLeakVerdict(verdict) {
  const normalized = normalizeLeakVerdict(verdict);
  if (!normalized) {
    // Don't poison storage with a malformed verdict. The read-side
    // treats null/missing as fail-closed when hardening is active, so
    // silently dropping is the safest behaviour — no consumer expects
    // recordLeakVerdict to succeed for an invalid input.
    return;
  }
  try {
    await browser.storage.local.set({ [LEAK_VERDICT_KEY]: normalized });
  } catch (e) {
    console.error("[onionbird] could not persist leak verdict:", e);
  }
}

async function readLeakVerdict() {
  try {
    const got = await browser.storage.local.get(LEAK_VERDICT_KEY);
    return got[LEAK_VERDICT_KEY] || null;
  } catch (e) {
    // F-043: never swallow storage errors silently — incident triage
    // depends on these surfacing in the browser console. The caller
    // (compose.onBeforeSend) treats `null` as fail-closed when
    // hardening is active.
    console.error("[onionbird] readLeakVerdict storage error:", e);
    return null;
  }
}

// Application-layer send-gate. compose.onBeforeSend fires for every
// outgoing message; we return {cancel: true} when the canary's last
// verdict was leak_detected. README's "the addon NEVER silently
// downgrades to clearnet" depends on this gate when the transport
// layer's failover_direct safety net hasn't fired yet (e.g. on a
// slow-developing DNS poisoning).
//
// `compose` API may be unavailable in stripped-down test environments;
// guard the registration so background.js still loads in such cases.
if (
  typeof browser.compose !== "undefined" &&
  browser.compose &&
  browser.compose.onBeforeSend &&
  typeof browser.compose.onBeforeSend.addListener === "function"
) {
  browser.compose.onBeforeSend.addListener(async (tab, _details) => {
    // F-043 + F-072: gate fail-closed decision on whether hardening
    // is active. When the addon is genuinely disabled the user opted
    // out of Tor routing; cancelling their sends would be a UX trap.
    // When the addon is active, ANY non-`clean` verdict — including
    // null from a storage error, a missing key on a fresh install
    // before the first canary, an `inconclusive` result, or an
    // unrecognised state string — must block. The 100%-Tor mandate
    // rules out "proceed because we don't know yet".
    //
    // F-072: we consult readSnapshotState() directly (not the slim
    // isHardeningActive wrapper) so we can distinguish "addon truly
    // disabled" from "storage error, unknown state". The latter has
    // to fail-CLOSED — otherwise a transient storage hiccup at the
    // exact moment the user clicks Send re-opens the gate F-043 was
    // meant to close.
    const [verdict, snapshotState] = await Promise.all([
      readLeakVerdict(),
      readSnapshotState(),
    ]);
    const storageError =
      snapshotState.corrupt && snapshotState.reason === "storage-error";
    if (storageError) {
      console.warn(
        "[onionbird] compose.onBeforeSend: BLOCKING send (storage-error)",
        { snapshotReason: snapshotState.reason, tab: tab && tab.id }
      );
      return {
        cancel: true,
        // U-072 / U-074: localised cancel reason routed through
        // browser.i18n.getMessage so a Persian / Tibetan / Arabic /
        // ... user sees their language during the privacy-critical
        // block. The message wording explicitly points at the
        // "Run self-test now" button on the DNS leak status section
        // of Options (NOT the "Test Tor now" button, which only
        // probes SOCKS reachability and never updates the verdict).
        cancelMessage: browser.i18n.getMessage("sendBlockedCancelStorageError"),
      };
    }
    const active = !!snapshotState.snapshot;
    if (!active) {
      return; // addon truly disabled — pass through
    }
    if (verdict && verdict.state === "clean") {
      return; // explicit clean verdict — proceed
    }
    const reason = !verdict
      ? "no verdict (storage error or canary not yet run)"
      : verdict.state === "leak_detected"
      ? "canary reported leak_detected"
      : `non-clean verdict: ${String(verdict.state)}`;
    console.warn(
      "[onionbird] compose.onBeforeSend: BLOCKING send (fail-closed)",
      { reason, verdict_ts: verdict && verdict.ts, tab: tab && tab.id }
    );
    // Pick the right localised cancel string based on which branch
    // fired. State substring goes through the $STATE$ placeholder
    // mechanism so the localised string never has to be concatenated
    // by hand on the locale side (which would break in RTL languages
    // and lose the explicit-substitution audit trail).
    let cancelMessage;
    if (verdict && verdict.state === "leak_detected") {
      cancelMessage = browser.i18n.getMessage("sendBlockedCancelLeakDetected");
    } else if (!verdict) {
      cancelMessage = browser.i18n.getMessage("sendBlockedCancelNoVerdict");
    } else {
      cancelMessage = browser.i18n.getMessage(
        "sendBlockedCancelOther",
        [String(verdict.state)]
      );
    }
    return {
      cancel: true,
      cancelMessage,
    };
  });
} else {
  console.warn(
    "[onionbird] browser.compose.onBeforeSend not available; " +
    "application-layer send-block disabled"
  );
  // U-079: persist a sentinel verdict so the Options page can
  // render a banner explaining that the addon-layer send-block
  // is silently disabled. Without this, a future TB that drops
  // the compose API leaves the user thinking the gate is
  // active when only Mozilla's failover_direct safety net is
  // protecting them.
  recordLeakVerdict({
    state: "compose_api_unavailable",
    ts: Date.now(),
    source: "manifest-load",
  }).catch((e) =>
    console.error("[onionbird] U-079 sentinel write failed:", e)
  );
}

async function reassertHardening(reason) {
  if (_reassertInflight) return _reassertInflight;
  _reassertInflight = enqueueHardeningMutation(
    `reassert:${reason}`,
    () => _reassertHardeningImpl(reason)
  )
    .finally(() => { _reassertInflight = null; });
  return _reassertInflight;
}

async function _reassertHardeningImpl(reason) {
  let snapshot = await getStoredSnapshot();
  if (!snapshot) {
    return { active: false };
  }

  try {
    snapshot = await snapshotMissingPrefs(snapshot, HARDENING_PREF_NAMES, "global");
    await expandSnapshotForCurrentAccounts(snapshot);
  } catch (e) {
    console.error(`[onionbird] ${reason} snapshot expansion failed:`, e);
  }

  const accountOnly = isAccountReassertReason(reason);
  let socks = null;
  let prefResult = { applied: [], failed: [], skipped: "account-event" };
  let failClosedResult = null;
  if (accountOnly) {
    // Account create/update events can fire while TB is still constructing
    // the account and before proxy prefs are stable. Only re-harden the new
    // account/identity surfaces here; startup/periodic reassert owns globals.
    socks = await readCurrentSocksConfig() || {
      ok: true,
      verified: false,
      host: null,
      port: null,
      source: "account-event-no-global-prefs",
    };
  } else {
    const detected = reason === "periodic"
      ? await hardeningPrefsWithCurrentSocks()
      : await hardeningPrefsWithDetectedSocks();
    socks = detected.socks;
    prefResult = await browser.onionbird.applyPrefs(detected.prefs);
    if (hasFailures(prefResult) || !socks.ok) {
      failClosedResult = await applyFailClosedPrefs(`${reason}-reassert-failure`, socks);
    }
  }
  const smtpResult = await browser.onionbird.applyHardeningToAllSmtpServers(true);
  const idResult = await browser.onionbird.applyHardeningToAllIdentities({ onlyOnionIdentities: true });
  const ok = !hasFailures(prefResult) &&
    !hasFailures(smtpResult) &&
    !hasFailures(idResult) &&
    (accountOnly || socks.ok);

  if (!ok) {
    console.warn(`[onionbird] ${reason} re-assert failures:`, {
      socks: summarizeSocksForLog(socks),
      prefs: countItems(prefResult.failed),
      failClosed: failClosedResult ? countItems(failClosedResult.failed) : null,
      smtp: countItems(smtpResult.failed),
      identities: countItems(idResult.failed),
    });
  } else if (reason !== "periodic") {
    console.log(`[onionbird] ${reason} re-assert OK`, {
      socks: summarizeSocksForLog(socks),
    });
  }
  return {
    active: true,
    ok,
    socks,
    prefs: prefResult,
    failClosed: failClosedResult,
    smtp: smtpResult,
    identities: idResult,
  };
}

function startHardeningMonitors() {
  if (!_accountReassertTimer) {
    _accountReassertTimer = setInterval(() => {
      reassertHardening("periodic")
        .catch((e) => console.error("[onionbird] periodic re-assert failed:", e));
    }, ACCOUNT_REASSERT_MS);
  }
  if (!_selfTestTimer) {
    _selfTestTimer = setInterval(() => {
      (async () => {
        const snapshot = await getStoredSnapshot();
        if (!snapshot) return;
        await announceSelfTest();
      })().catch((e) => console.error("[onionbird] periodic self-test failed:", e));
    }, SELF_TEST_INTERVAL_MS);
  }
  startAccountReassertListeners();
}

function stopHardeningMonitors() {
  if (_accountReassertTimer) {
    clearInterval(_accountReassertTimer);
    _accountReassertTimer = null;
  }
  if (_selfTestTimer) {
    clearInterval(_selfTestTimer);
    _selfTestTimer = null;
  }
  stopAccountReassertListeners();
}

function startAccountReassertListeners() {
  if (_accountReassertListenersStarted) return;
  const accounts = browser.accounts;
  if (!accounts) return;
  const watchedEvents = [
    ["onCreated", "account-created"],
    ["onUpdated", "account-updated"],
    ["onDeleted", "account-deleted"],
  ];
  for (const [eventName, reason] of watchedEvents) {
    const event = accounts[eventName];
    if (!event || !event.addListener) continue;
    const handler = () => {
      reassertHardening(reason)
        .catch((e) => console.error(`[onionbird] ${reason} re-assert failed:`, e));
    };
    event.addListener(handler);
    _accountReassertHandlers.push([event, handler]);
  }
  _accountReassertListenersStarted = _accountReassertHandlers.length > 0;
}

function stopAccountReassertListeners() {
  for (const [event, handler] of _accountReassertHandlers) {
    try {
      if (event.removeListener) event.removeListener(handler);
    } catch (e) {
      console.warn("[onionbird] account listener removal failed:", e);
    }
  }
  _accountReassertHandlers = [];
  _accountReassertListenersStarted = false;
}

// B-004 fix: auto-enable on install so users aren't silently exposed.
// P0-T3-4: also handle reason="update" — a user upgrading from an
// older version that never had hardening (or whose snapshot was lost)
// would otherwise silently regress to clearnet. We only enable if no
// snapshot exists; if one does, main()'s re-assert path covers it.
//
// Ordering: snapshot is written BEFORE applyPrefs (see enableHardening
// body). If we crash mid-applyPrefs, the snapshot still exists on disk,
// so the next launch's re-assert picks up the partial state and finishes
// it. Do not reorder this.
browser.runtime.onInstalled.addListener(async (details) => {
  if (details.reason !== "install" && details.reason !== "update") return;
  try {
    const stored = await browser.storage.local.get(STORAGE_KEY);
    if (stored[STORAGE_KEY]) {
      console.log(
        `[onionbird] onInstalled reason=${details.reason}; snapshot exists, ` +
        "main()'s re-assert will run"
      );
      return;
    }
    console.log(
      `[onionbird] onInstalled reason=${details.reason}; no snapshot — auto-enabling`
    );
    const r = await enableHardening();
    if (!r.ok) {
      console.warn(
        "[onionbird] auto-enable did not verify cleanly:",
        summarizeHardeningResultForLog(r)
      );
      // F-081: surface the failure to the user with an actionable
      // notification. Without this the new compose.onBeforeSend
      // send-block silently cancels every send and the user has
      // no way to know "Tor isn't running" without opening
      // Options. The notification points them at the right
      // remediation surface. Requires `notifications` permission
      // (added in both manifests for this finding).
      try {
        // F-175: route the notification text through browser.i18n.
        // getMessage instead of hardcoded English literals. A Farsi /
        // Burmese / Bengali user (the F-168 cited repression-hotspot
        // locales) previously saw English when their sends started
        // failing — exactly the population the localised cancelMessage
        // work (U-072) was meant to serve. Both branches (Tor
        // unreachable / canary self-test fail) get their own (title,
        // message) key pair so translators can phrase the action
        // sentence naturally per language.
        const socksUnreachable = r.socks && !r.socks.ok;
        const titleKey = socksUnreachable
          ? "autoEnableNotificationTitleSocksUnreachable"
          : "autoEnableNotificationTitleCanaryFail";
        const messageKey = socksUnreachable
          ? "autoEnableNotificationMessageSocksUnreachable"
          : "autoEnableNotificationMessageCanaryFail";
        if (browser.notifications && browser.notifications.create) {
          await browser.notifications.create("onionbird-autoenable-failure", {
            type: "basic",
            iconUrl: browser.runtime.getURL("icons/onionbird.svg"),
            title: browser.i18n.getMessage(titleKey),
            message: browser.i18n.getMessage(messageKey),
          });
        }
      } catch (notifyErr) {
        console.warn("[onionbird] notification on auto-enable failure failed:", notifyErr);
      }
    }
  } catch (e) {
    console.error("[onionbird] auto-enable on onInstalled failed:", e);
  }
});

async function main() {
  console.log(`[onionbird] background loaded v${VERSION}`);
  if (!browser.onionbird) {
    console.error("[onionbird] FATAL: experiment API not available");
    return;
  }
  const apiVer = await browser.onionbird.getApiVersion();
  console.log(`[onionbird] experiment API ${apiVer} reachable`);
  // Durable signal "user opted into hardening" is the snapshot in
  // storage — NOT the live pref state. If a third party flipped a
  // hardened pref between launches, the snapshot still lets startup
  // re-apply protection instead of mistaking the profile for inactive.
  try {
    const snapshotState = await readSnapshotState();
    if (!snapshotState.snapshot) {
      if (snapshotState.corrupt) {
        console.error(
          "[onionbird] corrupt hardening snapshot found; re-enabling fail-closed"
        );
        const r = await enableHardening();
        if (!r.ok) {
          console.warn(
            "[onionbird] corrupt-snapshot re-enable did not verify cleanly:",
            summarizeHardeningResultForLog(r)
          );
        }
        announceSelfTest().catch((e) => console.error("[onionbird] self-test:", e));
        return;
      }
      console.log("[onionbird] no hardening snapshot — self-test skipped");
      return;
    }
    // Re-assert HARDENING_PREFS every startup. Between launches, prefs.js
    // may have been edited (local attacker, TB migration that resets
    // network.trr.mode, buggy companion addon) and the snapshot/restore
    // primitive only triggers on explicit toggle.
    await reassertHardening("startup");
    startHardeningMonitors();
    announceSelfTest().catch((e) => console.error("[onionbird] self-test:", e));
  } catch (e) {
    console.error("[onionbird] self-test gate failed:", e);
  }
}

main().catch((e) => console.error("[onionbird] startup error:", e));
