// SPDX-License-Identifier: MPL-2.0
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
"use strict";

var { ExtensionCommon } = ChromeUtils.importESModule(
  "resource://gre/modules/ExtensionCommon.sys.mjs"
);
var { Services } = globalThis;
// F-037: hoist Ci to top so applyHardeningToAllSmtpServers's
// QueryInterface call doesn't depend on a file-bottom `var`.
// Works in chrome context (real ExtensionAPI parent script) and in the
// fuzz harness (which injects a fake `Components` with an `interfaces`
// property — see test/integration/test_fuzz_inputs.py).
var Ci = (typeof Components !== "undefined" && Components.interfaces) ||
  (globalThis.Components && globalThis.Components.interfaces) || null;
var Cc = (typeof Components !== "undefined" && Components.classes) ||
  (globalThis.Components && globalThis.Components.classes) || null;
var MailServices;
try {
  ({ MailServices } = ChromeUtils.importESModule(
    "resource:///modules/MailServices.sys.mjs"
  ));
} catch (e) {
  console.error("[onionbird] MailServices import failed:", e);
  MailServices = null;
}

const API_VERSION = "0.1.4";
const MAX_PREF_NAME_LENGTH = 256;
const MAX_PREF_STRING_LENGTH = 65536;
const MAX_PREF_BATCH_SIZE = 256;
const MAX_PREF_SNAPSHOT_SIZE = 4096;
const MAX_DNS_HOST_LENGTH = 253;
const MAX_DNS_LABEL_LENGTH = 63;
const MAX_PTR_CONFIRMATIONS = 8;
const PREF_INT_MIN = -2147483648;
const PREF_INT_MAX = 2147483647;

const SMTP_HARDENING_PREF_SUFFIXES = ["hello_argument", "try_ssl"];
const IDENTITY_HARDENING_PREF_SUFFIXES = [
  "FQDN",
  "compose_html",
  "reply_to",
  "organization",
  "attach_vcard",
  "attach_signature",
  "htmlSigText",
  "htmlSigFormat",
];
const ADDON_OWNED_PREF_NAMES = new Set([
  "onionbird.messageid.fqdn_mode",
  "onionbird.messageid.fqdn_custom",
  "onionbird.messageid.fqdn_fallback",
  // F-168: user-configurable SOCKS endpoint override. Empty/unset =
  // fall back to the auto-detect+ladder path; non-empty host = use
  // this on every enable. Host validated via isValidSocksHost on
  // write (rejects DNS-resolvable names other than `localhost`).
  "onionbird.socks.host",
  "onionbird.socks.port",
]);
const MAIL_LOGIN_ORIGIN_SCHEMES = new Set(["smtp", "imap", "pop3", "nntp"]);

function readPref(name) {
  const branch = Services.prefs;
  const type = branch.getPrefType(name);
  if (type === branch.PREF_INVALID) return null;
  if (type === branch.PREF_STRING) {
    try { return branch.getCharPref(name); } catch (e) { return null; }
  }
  if (type === branch.PREF_INT) return branch.getIntPref(name);
  if (type === branch.PREF_BOOL) return branch.getBoolPref(name);
  return null;
}

function safePrefName(name) {
  const value = typeof name === "string" ? name : "<invalid>";
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, "_");
  return cleaned.length > MAX_PREF_NAME_LENGTH
    ? `${cleaned.slice(0, MAX_PREF_NAME_LENGTH)}...`
    : cleaned;
}

// P0-T3-3 / security round 2026-05-22: pref-write allowlist. The experiment
// API runs in the parent process with full Services.prefs power, so broad
// prefixes are too much authority. Allow exact global hardening prefs and
// only the per-account suffixes this addon owns.
const ALLOWED_PREF_NAMES = new Set([
  "app.support.baseURL",
  "app.update.auto",
  "app.update.background.scheduling.enabled",
  "app.update.enabled",
  "app.update.url",
  "breakpad.reportURL",
  "browser.safebrowsing.malware.enabled",
  "calendar.useragent.extra",
  "browser.safebrowsing.phishing.enabled",
  "captivedetect.canonicalURL",
  "datareporting.healthreport.uploadEnabled",
  "datareporting.policy.dataSubmissionEnabled",
  "dom.battery.enabled",
  "dom.gamepad.enabled",
  "dom.indexedDB.enabled",
  "dom.push.enabled",
  "dom.push.serverURL",
  "dom.serviceWorkers.enabled",
  "dom.storageManager.enabled",
  "dom.vr.enabled",
  "dom.webnotifications.enabled",
  "extensions.blocklist.enabled",
  "extensions.systemAddon.update.enabled",
  "extensions.update.enabled",
  "extensions.update.url",
  "geo.enabled",
  "identity.fxaccounts.enabled",
  "intl.accept_languages",
  "ldap_2.autoComplete.useDirectory",
  "mail.biff.show_alert",
  "mail.biff.show_tray_icon",
  "mail.biff.use_system_alert",
  "mail.collect_email_address_outgoing",
  "mail.imap.use_client_info",
  "mail.server.default.send_client_info",
  "mail.update.url",
  "mailnews.auto_config.fetchFromISP.v2",
  "mailnews.auto_config.guess.enabled",
  "mailnews.auto_config_url",
  "mailnews.display.disable_format_flowed_support",
  "mailnews.display.disallow_mime_handlers",
  "mailnews.display.html_as",
  "mailnews.display.prefer_plaintext",
  "mailnews.headers.sendUserAgent",
  "mailnews.message_display.disable_remote_image",
  "mailnews.mx_service_url",
  "mailnews.notifications.enabled",
  "mailnews.reply_header_authorwrote",
  "mailnews.reply_header_type",
  "mailnews.scam_detection.url_indicators",
  "mailnews.send_default_charset",
  "mailnews.send_format",
  "mailnews.send_plaintext_flowed",
  "mailnews.view_default_charset",
  "media.autoplay.default",
  "media.eme.enabled",
  "media.gmp-manager.url",
  "media.gmp-widevinecdm.enabled",
  "media.navigator.enabled",
  "media.peerconnection.enabled",
  "media.peerconnection.ice.default_address_only",
  "media.peerconnection.ice.no_host",
  "media.peerconnection.ice.proxy_only_if_behind_proxy",
  "media.webspeech.recognition.enable",
  "media.webspeech.synth.enabled",
  "network.IDN_show_punycode",
  "network.captive-portal-service.enabled",
  "network.connectivity-service.IPv4.url",
  "network.connectivity-service.IPv6.url",
  "network.connectivity-service.enabled",
  "network.cookie.cookieBehavior",
  "network.cookie.lifetimePolicy",
  "network.dns.disableIPv6",
  "network.dns.disablePrefetch",
  "network.dns.echconfig.enabled",
  "network.dns.use_https_rr_as_altsvc",
  "network.http.speculative-parallel-limit",
  "network.predictor.enable-prefetch",
  "network.predictor.enabled",
  "network.prefetch-next",
  "network.proxy.failover_direct",
  "network.proxy.no_proxies_on",
  "network.proxy.socks",
  "network.proxy.socks_port",
  "network.proxy.socks_remote_dns",
  "network.proxy.socks_version",
  "network.proxy.type",
  "network.trr.bootstrapAddress",
  "network.trr.confirmationNS",
  "network.trr.custom_uri",
  "network.trr.mode",
  "network.trr.uri",
  "privacy.resistFingerprinting",
  "security.OCSP.enabled",
  "security.OCSP.require",
  "security.ssl.require_safe_negotiation",
  "security.tls.enable_0rtt_data",
  "security.tls.version.enable-deprecated",
  "security.tls.version.min",
  "services.settings.server",
  "services.sync.enabled",
  "services.sync.serverURL",
  "toolkit.crashreporter.include_extensions",
  "toolkit.crashreporter.submitURL",
  "toolkit.telemetry.archive.enabled",
  "toolkit.telemetry.bhrPing.enabled",
  "toolkit.telemetry.enabled",
  "toolkit.telemetry.firstShutdownPing.enabled",
  "toolkit.telemetry.newProfilePing.enabled",
  "toolkit.telemetry.shutdownPingSender.enabled",
  "toolkit.telemetry.updatePing.enabled",
]);

const SMTP_HARDENING_PREF_RE =
  /^mail\.smtpserver\.[A-Za-z0-9_]+\.(hello_argument|try_ssl)$/;
const IDENTITY_HARDENING_PREF_RE =
  /^mail\.identity\.[A-Za-z0-9_]+\.(FQDN|compose_html|reply_to|organization|attach_vcard|attach_signature|htmlSigText|htmlSigFormat)$/;

function isAllowedPref(name) {
  if (
    typeof name !== "string" ||
    name.length === 0 ||
    name.length > MAX_PREF_NAME_LENGTH
  ) {
    return false;
  }
  return ALLOWED_PREF_NAMES.has(name) ||
    ADDON_OWNED_PREF_NAMES.has(name) ||
    SMTP_HARDENING_PREF_RE.test(name) ||
    IDENTITY_HARDENING_PREF_RE.test(name);
}

function isAddonOwnedPref(name) {
  return ADDON_OWNED_PREF_NAMES.has(name);
}

function isValidPrefValue(value, allowNull = false) {
  return (allowNull && value === null) ||
    (typeof value === "string" &&
      value.length <= MAX_PREF_STRING_LENGTH &&
      value.indexOf("\0") === -1) ||
    typeof value === "boolean" ||
    (
      typeof value === "number" &&
      Number.isInteger(value) &&
      value >= PREF_INT_MIN &&
      value <= PREF_INT_MAX
    );
}

function normalizeAddonOwnedPrefValue(name, value) {
  if (!isValidPrefValue(value)) {
    throw new Error(`invalid pref value for ${safePrefName(name)}`);
  }
  if (name === "onionbird.socks.host") {
    const host = typeof value === "string" ? value.trim() : "";
    if (!host || !(isLoopbackSocksHost(host) || isIpLiteralSocksHost(host))) {
      throw new Error(
        "invalid SOCKS override host (must be loopback or IP literal)"
      );
    }
    return host;
  }
  if (name === "onionbird.socks.port") {
    if (typeof value !== "number" || !Number.isInteger(value)) {
      throw new Error("invalid SOCKS override port");
    }
    return normalizeSocksPortValue(value);
  }
  return value;
}

function normalizePrefValueForWrite(name, value) {
  if (isAddonOwnedPref(name)) {
    return normalizeAddonOwnedPrefValue(name, value);
  }
  if (!isValidPrefValue(value)) {
    throw new Error(`invalid pref value for ${safePrefName(name)}`);
  }
  return value;
}

function writePref(name, value) {
  if (!isAllowedPref(name)) {
    throw new Error(`pref not in allowlist: ${name}`);
  }
  const normalizedValue = normalizePrefValueForWrite(name, value);
  const branch = Services.prefs;
  if (typeof normalizedValue === "boolean") {
    branch.setBoolPref(name, normalizedValue);
  } else if (
    typeof normalizedValue === "number" &&
    Number.isInteger(normalizedValue)
  ) {
    branch.setIntPref(name, normalizedValue);
  } else {
    branch.setCharPref(name, String(normalizedValue));
  }
}

function isValidDnsHost(host) {
  if (
    typeof host !== "string" ||
    host.length === 0 ||
    host.length > MAX_DNS_HOST_LENGTH ||
    /^\d{1,3}(\.\d{1,3}){1,3}$/.test(host)
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

function normalizeSocksPortValue(port) {
  let value;
  if (typeof port === "number") {
    value = port;
  } else if (typeof port === "string" && /^[1-9]\d{0,4}$/.test(port.trim())) {
    value = Number(port.trim());
  } else {
    throw new Error(`invalid SOCKS port: ${port}`);
  }
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error(`invalid SOCKS port: ${port}`);
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
  // Note on `localhost`: Gecko's nsIDNSService has a hard-coded
  // short-circuit that resolves `localhost` to 127.0.0.1 / ::1
  // *before* consulting the system resolver or /etc/hosts (Mozilla
  // Bug 1220810, landed ~2016). So accepting `localhost` here does
  // NOT create a pre-Tor DNS leak even if /etc/hosts has been
  // tampered to point `localhost` at a public IP — TB will refuse
  // to look up the system answer and bind to loopback. Without
  // this guarantee we would have to reject `localhost` and only
  // accept IP literals.
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

function currentSocksEndpointMatches(host, port) {
  try {
    const prefHost = normalizeSocksHost(
      Services.prefs.getCharPref("network.proxy.socks")
    );
    const prefPort = normalizeSocksPortValue(
      Services.prefs.getIntPref("network.proxy.socks_port")
    );
    return socksHostCompareKey(prefHost) === socksHostCompareKey(host) &&
      prefPort === port;
  } catch (e) {
    return false;
  }
}

function assertAllowedSocksEndpoint(host, port, options) {
  // F-168 I-1: userProbe is the "user explicitly entered this in the
  // Options page Test field" opt-out. The strict isLoopback || isIpLiteral
  // gate still applies (IP literals never trigger a system-resolver
  // lookup — the leak class B-001 closed) but we skip the
  // currentSocksEndpointMatches requirement that exists to stop
  // arbitrary background callers from probing far-network hosts via
  // the addon. For the Options-page Test button the user IS the source
  // of truth: requiring the IP to already be in TB's proxy pref before
  // probing creates a chicken-and-egg trap (you can only test what you
  // already saved), which broke the Whonix/Tails workflow this feature
  // was designed for.
  const userProbe = !!(options && options.userProbe);
  if (isLoopbackSocksHost(host)) return;
  if (isIpLiteralSocksHost(host)) {
    if (userProbe || currentSocksEndpointMatches(host, port)) return;
  }
  throw new Error(
    "SOCKS endpoint not allowed (must be loopback or current Thunderbird proxy IP)"
  );
}

function summarizeSocksEndpointForLog(host, port) {
  return {
    host: isLoopbackSocksHost(host) ? socksHostCompareKey(host) : "<configured>",
    port: Number.isInteger(port) ? port : null,
  };
}

function summarizeErrorForLog(error) {
  if (typeof error !== "string" || !error) return null;
  const text = error;
  if (/refused/i.test(text)) return "refused";
  if (/timeout/i.test(text)) return "timeout";
  if (/network unreachable|ENETUNREACH/i.test(text)) return "network-unreachable";
  if (/dns/i.test(text)) return "dns-error";
  if (/invalid|unsafe|not allowed/i.test(text)) return "invalid-input";
  return "error";
}

function clearPrefValue(name) {
  if (!isAllowedPref(name)) {
    throw new Error(`pref not in allowlist: ${name}`);
  }
  if (Services.prefs.prefHasUserValue(name)) {
    Services.prefs.clearUserPref(name);
  }
}

function isSafeAccountKey(key) {
  return typeof key === "string" && /^[A-Za-z0-9_]+$/.test(key);
}

function safeAccountKeyForReport(key) {
  return isSafeAccountKey(key) ? key : "<invalid>";
}

function smtpHardeningPrefNames(key) {
  return SMTP_HARDENING_PREF_SUFFIXES.map(
    (suffix) => `mail.smtpserver.${key}.${suffix}`
  );
}

function identityHardeningPrefNames(key) {
  return IDENTITY_HARDENING_PREF_SUFFIXES.map(
    (suffix) => `mail.identity.${key}.${suffix}`
  );
}

function normalizeHost(hostname) {
  if (typeof hostname !== "string") return "";
  let host = hostname.trim().toLowerCase();
  const bracketed = host.match(/^\[([^\]]+)\](?::\d+)?\.?$/);
  if (bracketed) {
    const inner = bracketed[1].toLowerCase();
    return isValidIpv6Literal(inner) ? inner : host.replace(/\.$/, "");
  }
  host = host.replace(/\.$/, "");
  const colon = host.lastIndexOf(":");
  if (colon > -1 && host.indexOf(":") === colon) {
    const maybePort = host.slice(colon + 1);
    if (/^\d+$/.test(maybePort)) {
      host = host.slice(0, colon);
    }
  }
  return host;
}

function isOnionHost(hostname) {
  const host = normalizeHost(hostname);
  const label = host.endsWith(".onion") ? host.slice(0, -".onion".length) : "";
  // Tor v2 onion names are obsolete; only classify valid v3 names as onion.
  return /^[a-z2-7]{56}$/.test(label);
}

function isLoopbackHost(hostname) {
  const host = normalizeHost(hostname);
  return host === "localhost" ||
         isIpv4LoopbackAddress(host) ||
         host === "::1";
}

function classifyMailHostForReport(hostname) {
  if (isOnionHost(hostname)) return "onion";
  if (isLoopbackHost(hostname)) return "loopback";
  if (!normalizeHost(hostname)) return "empty";
  return "other";
}

/**
 * Classify a string IP as a non-actionable address — private RFC1918,
 * loopback, link-local, CG-NAT, multicast, or sentinel "no answer".
 * These can't be a real leak target so the canary must NOT flag them.
 *
 * Returns true for any address class we should treat as inconclusive.
 */
function isInconclusiveIp(ip) {
  if (!ip) return true;
  // Sentinels frequently returned by misconfigured resolvers / failures.
  if (ip === "0.0.0.0" || ip === "::" || ip === "0:0:0:0:0:0:0:0") return true;
  // Malformed IPv6 (more than one "::" run). canonicalizeIp passes these
  // through unchanged; without this check, downstream socks5ResolvePtr
  // throws on the .split(".") and the canary mis-attributes that as a leak.
  if (ip.indexOf("::") !== ip.lastIndexOf("::")) return true;
  // IPv4 private + reserved.
  if (/^10\./.test(ip)) return true;
  if (/^127\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip)) return true;
  if (/^169\.254\./.test(ip)) return true;         // link-local
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) return true; // CG-NAT 100.64/10
  if (/^198\.(1[89])\./.test(ip)) return true;     // RFC 2544 benchmarking
  if (/^22[4-9]\.|^23\d\./.test(ip)) return true;  // multicast 224/4
  // IPv6 private + loopback + link-local.
  // The ULA regex anchors on `:` to avoid matching non-IPv6 strings that
  // happen to start with "fc" or "fd" (e.g. "fc.example.com" if some
  // future code path pushed a domain string in by mistake).
  if (ip === "::1") return true;
  if (/^f[cd][0-9a-f]{2}:/i.test(ip)) return true;  // fc00::/7 (unique-local)
  if (/^fe80:/i.test(ip)) return true;              // fe80::/10 (link-local)
  return false;
}

/**
 * Normalize an IPv6 address to its canonical form (lowercase, compressed
 * runs of zero groups). Matches the output of Necko's `getNextAddrAsString`
 * so two strings produced by different code paths compare equal.
 *
 * IPv4 is returned unchanged.
 */
function canonicalizeIp(ip) {
  if (!ip) return ip;
  const value = String(ip);
  if (value.indexOf(":") === -1) return value;  // IPv4
  if (!isValidIpv6Literal(value)) return value;
  // Expand any "::" to its full form, normalize each group to short hex,
  // then re-compress the longest run of zero groups (>=2).
  let parts;
  if (value.indexOf("::") !== -1) {
    // RFC 4291 §2.2: only ONE "::" is permitted. Reject strings with
    // multiple "::" runs rather than silently normalize a malformed
    // address into a valid-looking one (which could mask leaks).
    const segments = value.split("::");
    if (segments.length !== 2) {
      return value;  // malformed — pass through; caller decides what to do
    }
    const [head, tail] = segments;
    const headG = head ? head.split(":") : [];
    const tailG = tail ? tail.split(":") : [];
    const missing = 8 - headG.length - tailG.length;
    if (missing < 0) return value;  // overlong, also malformed
    parts = headG.concat(Array(missing).fill("0"), tailG);
  } else {
    parts = value.split(":");
  }
  parts = parts.map(g => parseInt(g, 16).toString(16));
  // Compress longest run of consecutive "0" groups (length >= 2).
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === "0") {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else {
      curStart = -1; curLen = 0;
    }
  }
  if (bestLen >= 2) {
    const left = parts.slice(0, bestStart).join(":");
    const right = parts.slice(bestStart + bestLen).join(":");
    return `${left}::${right}`;
  }
  return parts.join(":");
}

// F-178: encode a SOCKS5 length-prefixed string field to bytes.
// The chrome-script context of some Thunderbird builds does NOT expose
// the global `TextEncoder` constructor — a user reported the Test
// endpoint button failing with "TextEncoder is not defined" because
// the SOCKS5 helpers used `new TextEncoder().encode(s)`. Use a
// charCode-based encoder instead; it's context-agnostic.
//
// Inputs are ASCII by upstream validation:
//   - hostnames: `isValidDnsHost` / loopback / IP literal
//   - isolation tokens: hex (from randomIsolationToken)
// We assert ASCII here as a defense-in-depth check; a non-ASCII byte
// would silently truncate to 8 bits otherwise and break the protocol.
function encodeSocksStringField(s) {
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0x7f) {
      throw new Error("SOCKS5 string field contains non-ASCII byte");
    }
    bytes[i] = c;
  }
  return bytes;
}

/**
 * Resolve `host` via SOCKS5 RESOLVE (Tor extension 0xF0).
 *
 * If `isolationToken` is non-empty, the SOCKS5 connection authenticates
 * with username=isolationToken / password=isolationToken — Tor uses the
 * (username, password) tuple as a stream-isolation key, so different
 * tokens get different circuits and thus different exits. This lets the
 * canary build a set of independent Tor views of the same hostname.
 *
 * Returns an IP/domain response string, or throws.
 */
async function socks5Resolve(socksHost, socksPort, host, isolationToken) {
  const Cc = Components.classes;
  const Ci = Components.interfaces;
  const sts = Cc["@mozilla.org/network/socket-transport-service;1"]
    .getService(Ci.nsISocketTransportService);
  const transport = sts.createTransport([], socksHost, socksPort, null, null);
  transport.setTimeout(Ci.nsISocketTransport.TIMEOUT_CONNECT, 10);
  transport.setTimeout(Ci.nsISocketTransport.TIMEOUT_READ_WRITE, 10);

  const outStream = transport.openOutputStream(0, 0, 0);
  const inStream  = transport.openInputStream(0, 0, 0);
  const binOut = Cc["@mozilla.org/binaryoutputstream;1"]
    .createInstance(Ci.nsIBinaryOutputStream);
  binOut.setOutputStream(outStream);
  const binIn = Cc["@mozilla.org/binaryinputstream;1"]
    .createInstance(Ci.nsIBinaryInputStream);
  binIn.setInputStream(inStream);

  const waitForBytes = (n) => new Promise((resolve, reject) => {
    const deadline = Date.now() + 12000;
    const Cc2 = Components.classes;
    const Ci2 = Components.interfaces;
    const tm = Cc2["@mozilla.org/thread-manager;1"].getService(Ci2.nsIThreadManager);
    const tick = () => {
      try {
        if (binIn.available() >= n) { resolve(binIn.readByteArray(n)); return; }
      } catch (e) { reject(e); return; }
      if (Date.now() > deadline) { reject(new Error("socks5 read timeout")); return; }
      // P1-T3-4: dispatchToMainThread can throw if the thread manager is
      // shutting down (TB quit mid-canary). Without wrapping, the throw
      // propagates to the nsIRunnable bridge and the awaiting Promise
      // hangs until deadline with a misleading "timeout" reject.
      try { tm.dispatchToMainThread({ run: tick }); }
      catch (e) { reject(e); }
    };
    try { tm.dispatchToMainThread({ run: tick }); }
    catch (e) { reject(e); }
  });

  try {
    const useAuth = !!isolationToken;
    if (useAuth) {
      // Offer ONLY username/password (0x02) so Tor MUST use auth and thus
      // bind the stream isolation key.
      binOut.writeByteArray([0x05, 0x01, 0x02]);
      const greet = await waitForBytes(2);
      if (greet[0] !== 0x05) throw new Error("socks5 bad greeting ver");
      if (greet[1] !== 0x02) {
        throw new Error(`socks5 server refused user/pass auth: ${greet[1]}`);
      }
      const u = encodeSocksStringField(isolationToken);
      const p = encodeSocksStringField(isolationToken);
      if (u.length > 255 || p.length > 255) {
        throw new Error("isolation token too long");
      }
      const subReq = [0x01, u.length];
      for (const b of u) subReq.push(b);
      subReq.push(p.length);
      for (const b of p) subReq.push(b);
      binOut.writeByteArray(subReq);
      const subResp = await waitForBytes(2);
      if (subResp[0] !== 0x01 || subResp[1] !== 0x00) {
        throw new Error(`socks5 user/pass sub-negotiation failed: ${subResp}`);
      }
    } else {
      // Greeting: VER=5 NMETHODS=1 METHODS=[0x00 (no auth)]
      binOut.writeByteArray([0x05, 0x01, 0x00]);
      const greet = await waitForBytes(2);
      if (greet[0] !== 0x05 || greet[1] !== 0x00) {
        throw new Error(`socks5 greeting failed: ${greet}`);
      }
    }

    // RESOLVE request: VER=5 CMD=0xF0 RSV=0 ATYP=3 (domain)
    const dom = encodeSocksStringField(host);
    if (dom.length > 255) throw new Error("hostname too long");
    const req = [0x05, 0xF0, 0x00, 0x03, dom.length];
    for (const b of dom) req.push(b);
    req.push(0x00, 0x00);
    binOut.writeByteArray(req);

    const hdr = await waitForBytes(4);
    if (hdr[0] !== 0x05) throw new Error("socks5 bad version in response");
    if (hdr[1] !== 0x00) throw new Error(`socks5 resolve failed rep=${hdr[1]}`);
    const atyp = hdr[3];
    let addr;
    if (atyp === 0x01) {
      const v4 = await waitForBytes(4);
      addr = `${v4[0]}.${v4[1]}.${v4[2]}.${v4[3]}`;
    } else if (atyp === 0x04) {
      const v6 = await waitForBytes(16);
      const groups = [];
      for (let i = 0; i < 16; i += 2) {
        groups.push(((v6[i] << 8) | v6[i + 1]).toString(16));
      }
      // Canonicalize so the output matches what Necko produces — otherwise
      // the canary's string-equality check produces false positives on IPv6.
      addr = canonicalizeIp(groups.join(":"));
    } else if (atyp === 0x03) {
      const len = (await waitForBytes(1))[0];
      const name = await waitForBytes(len);
      addr = String.fromCharCode(...name);
    } else {
      throw new Error(`socks5 unknown atyp=${atyp}`);
    }
    await waitForBytes(2);
    return addr;
  } finally {
    try { transport.close(0); } catch (e) {}
  }
}

/**
 * SOCKS5 RESOLVE_PTR (Tor extension 0xF1) — reverse-resolves an IPv4
 * address to a domain via Tor. Used to verify that the system-resolved IP
 * is a legitimate host of the target domain (the IP-set comparison alone
 * has false-positives when a service has many A records across ASNs).
 *
 * Returns the PTR domain string, or null if no PTR record exists.
 * Throws on protocol error or transport failure.
 */
async function socks5ResolvePtr(socksHost, socksPort, ipv4, isolationToken) {
  const Cc = Components.classes;
  const Ci = Components.interfaces;
  const sts = Cc["@mozilla.org/network/socket-transport-service;1"]
    .getService(Ci.nsISocketTransportService);
  const transport = sts.createTransport([], socksHost, socksPort, null, null);
  transport.setTimeout(Ci.nsISocketTransport.TIMEOUT_CONNECT, 10);
  transport.setTimeout(Ci.nsISocketTransport.TIMEOUT_READ_WRITE, 10);
  const outStream = transport.openOutputStream(0, 0, 0);
  const inStream  = transport.openInputStream(0, 0, 0);
  const binOut = Cc["@mozilla.org/binaryoutputstream;1"]
    .createInstance(Ci.nsIBinaryOutputStream);
  binOut.setOutputStream(outStream);
  const binIn = Cc["@mozilla.org/binaryinputstream;1"]
    .createInstance(Ci.nsIBinaryInputStream);
  binIn.setInputStream(inStream);

  const waitForBytes = (n) => new Promise((resolve, reject) => {
    const deadline = Date.now() + 12000;
    const tm = Cc["@mozilla.org/thread-manager;1"].getService(Ci.nsIThreadManager);
    const tick = () => {
      try {
        if (binIn.available() >= n) { resolve(binIn.readByteArray(n)); return; }
      } catch (e) { reject(e); return; }
      if (Date.now() > deadline) { reject(new Error("socks5 ptr read timeout")); return; }
      try { tm.dispatchToMainThread({ run: tick }); }
      catch (e) { reject(e); }
    };
    try { tm.dispatchToMainThread({ run: tick }); }
    catch (e) { reject(e); }
  });

  // Parse the IPv4 into 4 octets, validating each.
  const parts = ipv4.split(".");
  if (parts.length !== 4) throw new Error(`bad ipv4: ${ipv4}`);
  const octets = parts.map((p) => {
    const n = parseInt(p, 10);
    if (!(n >= 0 && n <= 255) || String(n) !== p) {
      throw new Error(`bad ipv4 octet: ${p}`);
    }
    return n;
  });

  try {
    // Same auth dance as socks5Resolve so caller can isolate circuits.
    if (isolationToken) {
      binOut.writeByteArray([0x05, 0x01, 0x02]);
      const greet = await waitForBytes(2);
      if (greet[0] !== 0x05 || greet[1] !== 0x02) {
        throw new Error(`socks5 ptr auth refused: ${greet[1]}`);
      }
      const u = encodeSocksStringField(isolationToken);
      const p = encodeSocksStringField(isolationToken);
      if (u.length > 255 || p.length > 255) {
        throw new Error("isolation token too long");
      }
      const sr = [0x01, u.length];
      for (const b of u) sr.push(b);
      sr.push(p.length);
      for (const b of p) sr.push(b);
      binOut.writeByteArray(sr);
      const sresp = await waitForBytes(2);
      if (sresp[0] !== 0x01 || sresp[1] !== 0x00) {
        throw new Error(`socks5 ptr sub-neg failed: ${sresp}`);
      }
    } else {
      binOut.writeByteArray([0x05, 0x01, 0x00]);
      const greet = await waitForBytes(2);
      if (greet[0] !== 0x05 || greet[1] !== 0x00) {
        throw new Error(`socks5 ptr greeting failed: ${greet}`);
      }
    }
    // RESOLVE_PTR: VER=5 CMD=0xF1 RSV=0 ATYP=1 (IPv4) + 4 octets + 2 byte port=0
    const req = [0x05, 0xF1, 0x00, 0x01, ...octets, 0x00, 0x00];
    binOut.writeByteArray(req);

    const hdr = await waitForBytes(4);
    if (hdr[0] !== 0x05) throw new Error("socks5 ptr bad ver");
    if (hdr[1] !== 0x00) {
      // rep=0x04 = host unreachable / no PTR; treat as "no answer", not error.
      if (hdr[1] === 0x04) return null;
      throw new Error(`socks5 ptr rep=${hdr[1]}`);
    }
    if (hdr[3] !== 0x03) {
      throw new Error(`socks5 ptr expected atyp=3 (domain), got ${hdr[3]}`);
    }
    const len = (await waitForBytes(1))[0];
    if (len === 0) return null;
    const name = await waitForBytes(len);
    await waitForBytes(2); // port
    return String.fromCharCode(...name);
  } finally {
    try { transport.close(0); } catch (e) {}
  }
}

function normalizeDnsComparisonHost(host) {
  if (typeof host !== "string") return "";
  const value = host.trim().toLowerCase().replace(/\.$/, "");
  return isValidDnsHost(value) ? value : "";
}

function ptrConfirmsTargetHost(ptrHost, targetHost) {
  const ptr = normalizeDnsComparisonHost(ptrHost);
  const target = normalizeDnsComparisonHost(targetHost);
  if (!ptr || !target) return false;
  return ptr === target || ptr.endsWith(`.${target}`);
}

/**
 * Opaque random isolation token for SOCKS5 user/pass auth. Used to
 * force Tor to bind each lookup to a distinct circuit. The token is a
 * hex blob — NO "t0r-canary-" prefix — so a local observer with shell
 * on the box can't fingerprint onionbird from the Tor control-port
 * stream-status output (P1-T3-1, T3-2).
 */
function randomHex(byteCount) {
  // The Experiments-API parent-process sandbox does not expose
  // `globalThis.crypto`, so an unconditional `crypto.getRandomValues`
  // call throws TypeError and silently kills the entire identity-
  // hardening chain (no per-identity FQDN write for ANY identity,
  // fallback FQDN never persisted, every Tor canary probe loses its
  // isolation token). Prefer WebCrypto if it happens to be present
  // (some sandbox/fuzz contexts inject it), fall back to the XPCOM
  // RNG which is always available in parent-process. See follow-up.md
  // F-166 for the full incident write-up.
  let bytes;
  if (typeof globalThis.crypto !== "undefined" &&
      typeof globalThis.crypto.getRandomValues === "function") {
    const buf = new Uint8Array(byteCount);
    globalThis.crypto.getRandomValues(buf);
    bytes = buf;
  } else if (Cc && Ci && Ci.nsIRandomGenerator) {
    const rg = Cc["@mozilla.org/security/random-generator;1"]
      .createInstance(Ci.nsIRandomGenerator);
    bytes = rg.generateRandomBytes(byteCount);
  } else {
    throw new Error("randomHex: no RNG available (no WebCrypto, no nsIRandomGenerator)");
  }
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

function randomIsolationToken() {
  return randomHex(16);
}

// Message-ID FQDN validation shared by custom mode and the per-install
// fallback for identities that do not yet have a usable From domain.
const MESSAGE_ID_FQDN_LABEL_SHAPE =
  /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
const ALL_NUMERIC_IPV4_SHAPE = /^\d{1,3}(\.\d{1,3}){1,3}$/;

function isValidMessageIdFqdn(s) {
  if (
    typeof s !== "string" ||
    s.length === 0 ||
    s.length > MAX_DNS_HOST_LENGTH ||
    ALL_NUMERIC_IPV4_SHAPE.test(s)
  ) {
    return false;
  }
  const labels = s.split(".");
  return typeof s === "string" &&
    labels.length >= 2 &&
    labels.every(label =>
      label.length > 0 &&
      label.length <= MAX_DNS_LABEL_LENGTH &&
      MESSAGE_ID_FQDN_LABEL_SHAPE.test(label)
    );
}

function getMessageIdFallbackFqdn() {
  try {
    const existing = Services.prefs.getCharPref("onionbird.messageid.fqdn_fallback");
    if (isValidMessageIdFqdn(existing)) return existing;
  } catch (e) {}
  const generated = `m${randomHex(10)}.invalid`;
  try {
    writePref("onionbird.messageid.fqdn_fallback", generated);
  } catch (e) {
    console.warn("[onionbird] could not persist Message-ID fallback FQDN:", e);
  }
  return generated;
}

function loginOriginHost(hostname) {
  const host = normalizeHost(hostname);
  if (!host) return "";
  if (host.indexOf(":") !== -1 && !host.startsWith("[")) {
    return `[${host}]`;
  }
  return host;
}

function normalizeLoginOriginScheme(scheme) {
  if (typeof scheme !== "string") return "";
  const value = scheme.trim().toLowerCase();
  return MAIL_LOGIN_ORIGIN_SCHEMES.has(value) ? value : "";
}

function normalizeLoginOriginPort(port) {
  if (port === undefined || port === null || port === "") return null;
  let value;
  if (typeof port === "number") {
    value = port;
  } else if (typeof port === "string" && /^[1-9]\d{0,4}$/.test(port.trim())) {
    value = Number(port.trim());
  } else {
    return null;
  }
  return Number.isInteger(value) && value > 0 && value <= 65535 ? value : null;
}

function addLoginOriginsForServer(origins, scheme, hostname, port) {
  const originScheme = normalizeLoginOriginScheme(scheme);
  if (!originScheme || !hostname) return;
  const host = normalizeHost(hostname);
  if (!isOnionHost(host) && !isLoopbackHost(host)) return;
  const originHost = loginOriginHost(host);
  if (!originHost) return;
  origins.add(`${originScheme}://${originHost}`);
  const nPort = normalizeLoginOriginPort(port);
  if (nPort !== null) {
    origins.add(`${originScheme}://${originHost}:${nPort}`);
  }
}

function publicLoginOriginInfo(origin) {
  if (typeof origin !== "string") {
    return { scheme: "unknown", host_type: "unknown", port_present: false };
  }
  const match = origin.match(
    /^([a-z0-9+.-]+):\/\/(\[[^\]]+\]|[^/:]+)(?::(\d+))?$/i
  );
  if (!match) {
    return { scheme: "unknown", host_type: "unknown", port_present: false };
  }
  const rawHost = match[2];
  const bracketed = rawHost.startsWith("[") && rawHost.endsWith("]");
  const innerHost = bracketed ? rawHost.slice(1, -1) : rawHost;
  const reportHost = bracketed && !isValidIpv6Literal(innerHost)
    ? rawHost
    : innerHost;
  return {
    scheme: match[1].toLowerCase(),
    host_type: classifyMailHostForReport(reportHost),
    port_present: !!match[3],
  };
}

function torMailLoginOrigins() {
  const origins = new Set();
  if (!MailServices) return [];

  try {
    const outgoing = MailServices.outgoingServer || MailServices.smtp;
    if (outgoing && outgoing.servers) {
      for (const s of outgoing.servers) {
        try {
          const ss = s.QueryInterface ? s.QueryInterface(Ci.nsISmtpServer) : s;
          addLoginOriginsForServer(origins, "smtp", ss.hostname || "", ss.port);
        } catch (e) {
          console.warn("[onionbird] SMTP login-origin inspection failed:", e);
        }
      }
    }
  } catch (e) {
    console.error("[onionbird] SMTP login-origin discovery failed:", e);
  }

  try {
    const accounts = MailServices.accounts;
    const incomingServers = accounts.allServers || [];
    const seen = new Set();
    const addIncoming = (server) => {
      if (!server) return;
      const key = server.key || `${server.type}:${server.hostName}`;
      if (seen.has(key)) return;
      seen.add(key);
      const type = typeof server.type === "string"
        ? server.type.toLowerCase()
        : "";
      if (!type || type === "none") return;
      addLoginOriginsForServer(
        origins,
        type,
        server.hostName || server.hostname || "",
        server.port
      );
    };

    if (incomingServers && typeof incomingServers[Symbol.iterator] === "function") {
      for (const server of incomingServers) addIncoming(server);
    } else if (accounts.accounts) {
      for (const account of accounts.accounts) addIncoming(account.incomingServer);
    }
  } catch (e) {
    console.error("[onionbird] incoming login-origin discovery failed:", e);
  }

  return [...origins].sort();
}

async function findSavedLoginsForOrigins(origins) {
  const found = [];
  const failed = [];
  const seen = new Set();
  if (!Services.logins) {
    return {
      logins: [],
      failed: [{ origin_type: "login-manager", error: "unavailable" }],
    };
  }
  for (const origin of origins) {
    try {
      const logins = Services.logins.searchLoginsAsync
        ? await Services.logins.searchLoginsAsync({ origin })
        : Services.logins.searchLogins({ origin });
      for (const login of logins) {
        const key = login.guid ||
          `${login.origin}\0${login.formActionOrigin}\0${login.httpRealm}\0${login.username}`;
        if (seen.has(key)) continue;
        seen.add(key);
        found.push(login);
      }
    } catch (e) {
      console.error("[onionbird] login search failed for Tor mail origin:", e);
      failed.push({
        ...publicLoginOriginInfo(origin),
        error: summarizeErrorForLog(e.message || String(e)),
      });
    }
  }
  return { logins: found, failed };
}

function publicLoginInfo(login) {
  return {
    ...publicLoginOriginInfo(login.origin),
    form_action_origin_present: !!login.formActionOrigin,
    httpRealm_present: !!login.httpRealm,
    username_present: !!login.username,
  };
}

/**
 * Resolve `host` via the system / browser resolver (nsIDNSService).
 * This is what TB would do if it called gethostbyname-equivalent. With
 * TRR=5 the answer comes from the OS resolver. Returns first IP or throws.
 */
async function systemResolve(host) {
  const Cc = Components.classes;
  const Ci = Components.interfaces;
  const dns = Cc["@mozilla.org/network/dns-service;1"]
    .getService(Ci.nsIDNSService);
  // Walk all A records — getNextAddrAsString returns one record per call
  // and throws NS_ERROR_NOT_AVAILABLE when exhausted. For multi-A services
  // (CDN-fronted) one call gives a single rotation; we need the SET so
  // the canary's tor_ips membership check is fair.
  return await new Promise((resolve, reject) => {
    // P1-T3-3: in some Necko versions the listener can be invoked more
    // than once for the same resolution. Guard so the second call doesn't
    // overwrite our first verdict (which is the one that already settled
    // the Promise — Promise spec ignores the second resolve/reject, but
    // we want to avoid even the wasted iteration over an exhausted record).
    let settled = false;
    const listener = {
      QueryInterface: ChromeUtils.generateQI(["nsIDNSListener"]),
      onLookupComplete(_req, record, status) {
        if (settled) return;
        settled = true;
        if (!Components.isSuccessCode(status)) {
          reject(new Error(`dns status 0x${status.toString(16)}`));
          return;
        }
        try {
          record.QueryInterface(Ci.nsIDNSAddrRecord);
          const ips = [];
          // Hard cap: any DNS answer with >64 A records is pathological.
          // Without this, a buggy Necko iterator that fails to advance
          // would freeze the main thread (canary runs on options page +
          // at startup — UI hang).
          for (let i = 0; i < 64; i++) {
            try { ips.push(record.getNextAddrAsString()); }
            catch (e) { break; }
          }
          resolve(ips);
        } catch (e) { reject(e); }
      },
    };
    const tm = Cc["@mozilla.org/thread-manager;1"]
      .getService(Ci.nsIThreadManager);
    try {
      dns.asyncResolve(
        host,
        Ci.nsIDNSService.RESOLVE_TYPE_DEFAULT,
        0, null, listener, tm.mainThread, {}
      );
    } catch (e) {
      reject(e);
    }
  });
}

this.onionbird = class extends ExtensionCommon.ExtensionAPI {
  getAPI(context) {
    return {
      onionbird: {
        getApiVersion: async () => API_VERSION,

        setPref: async (name, value) => {
          try {
            if (!isAddonOwnedPref(name)) {
              console.warn(
                `[onionbird] setPref(${safePrefName(name)}) denied: addon-owned prefs only`
              );
              return false;
            }
            if (!isValidPrefValue(value)) {
              console.warn(
                `[onionbird] setPref(${safePrefName(name)}) denied: invalid value type`
              );
              return false;
            }
            writePref(name, value);
            return true;
          } catch (e) {
            console.error(`[onionbird] setPref(${safePrefName(name)}) failed:`, e);
            return false;
          }
        },

        getPref: async (name) => {
          if (!isAllowedPref(name)) {
            console.warn(`[onionbird] getPref(${safePrefName(name)}) denied by allowlist`);
            return null;
          }
          return readPref(name);
        },

        // F-168: user-configurable SOCKS endpoint override.
        // setSocksOverride validates BEFORE persisting so the Options-page
        // Save handler gets immediate ok/false instead of silent success.
        // The host gate is `isValidSocksHost` — same gate as `probeSocks`
        // and `applyHardeningToAllSmtpServers`, which already rejects
        // DNS-resolvable names other than `localhost` (those would leak
        // a pre-Tor lookup of the SOCKS host itself).
        setSocksOverride: async (field, value) => {
          try {
            if (field === "host") {
              if (typeof value === "string" && value === "") {
                // empty string = clear override; fall back to ladder.
                clearPrefValue("onionbird.socks.host");
                return true;
              }
              // Strict gate: loopback (localhost / 127.x / ::1) or IP
              // literal only. DNS names — including the container-DNS
              // name `tor` used in the test pod — would trigger a
              // pre-Tor system-resolver lookup of the SOCKS host
              // itself before the connection. That's an out-of-band
              // leak the F-005/F-014/B-001 line of work spent effort
              // closing on the auto-detect path; the user-override
              // path must honour the same constraint. Users on
              // Whonix etc. enter the gateway IP literal, not the
              // hostname.
              const candidate = typeof value === "string" ? value.trim() : "";
              if (!candidate || !(isLoopbackSocksHost(candidate) || isIpLiteralSocksHost(candidate))) {
                console.warn(
                  `[onionbird] setSocksOverride(host) rejected: ${safePrefName(candidate || "<empty>")} not loopback or IP literal`
                );
                return false;
              }
              writePref("onionbird.socks.host", candidate);
              return true;
            }
            if (field === "port") {
              // S-9: accept all the obvious "clear" shapes —
              // `0` (number), `"0"` / `""` / whitespace (string),
              // null, undefined. Without this a caller passing the
              // string "0" (e.g. an Options-page input read as text)
              // would hit `normalizeSocksPortValue` and fail validation
              // instead of cleanly clearing.
              const isClearSentinel =
                value === 0 || value === null || value === undefined ||
                (typeof value === "string" && /^\s*0*\s*$/.test(value));
              if (isClearSentinel) {
                clearPrefValue("onionbird.socks.port");
                return true;
              }
              let port;
              try { port = normalizeSocksPortValue(value); }
              catch (e) {
                console.warn(`[onionbird] setSocksOverride(port) rejected: ${e.message || e}`);
                return false;
              }
              writePref("onionbird.socks.port", port);
              return true;
            }
            console.warn(`[onionbird] setSocksOverride: unknown field ${safePrefName(String(field))}`);
            return false;
          } catch (e) {
            console.error(`[onionbird] setSocksOverride(${field}) failed:`, e);
            return false;
          }
        },

        // F-170: atomic host+port write. Without this the Options-page
        // Save handler had to call setSocksOverride("host", …) then
        // setSocksOverride("port", …) sequentially — a half-set state
        // (host persisted, port cleared) silently dead-states the
        // override (getSocksOverride returns null for half-set pairs).
        // This validates both inputs first; on any rejection, writes
        // NEITHER pref. On full success, writes both in the same
        // parent-process tick (no race against an enableHardening run
        // that could otherwise observe the half-state mid-write).
        setSocksOverridePair: async (pair) => {
          try {
            const host = pair && typeof pair.host === "string" ? pair.host.trim() : "";
            const portIn = pair && pair.port;
            if (!host || !(isLoopbackSocksHost(host) || isIpLiteralSocksHost(host))) {
              console.warn(
                `[onionbird] setSocksOverridePair rejected: host ${safePrefName(host || "<empty>")} not loopback or IP literal`
              );
              return { ok: false, reason: "invalid-host" };
            }
            let port;
            try { port = normalizeSocksPortValue(portIn); }
            catch (e) {
              console.warn(`[onionbird] setSocksOverridePair rejected: ${e.message || e}`);
              return { ok: false, reason: "invalid-port" };
            }
            writePref("onionbird.socks.host", host);
            writePref("onionbird.socks.port", port);
            return { ok: true };
          } catch (e) {
            console.error("[onionbird] setSocksOverridePair failed:", e);
            return { ok: false, reason: "internal-error" };
          }
        },

        // F-168: getSocksOverride returns the stored override pair iff
        // BOTH host and port are present AND both pass validation. A
        // half-set pair (host only / port only) returns null so the
        // resolution path falls through to the next candidate cleanly
        // instead of mixing an override host with a fallback port.
        // Read-time validation: even if `setSocksOverride` is the only
        // write path the addon offers, the prefs themselves can be
        // edited via about:config or by another addon — we must NOT
        // trust the stored value blindly.
        getSocksOverride: async () => {
          const rawHost = readPref("onionbird.socks.host");
          const rawPort = readPref("onionbird.socks.port");
          if (typeof rawHost !== "string" || rawHost === "") return null;
          if (typeof rawPort !== "number" || rawPort === 0) return null;
          // Mirror setSocksOverride's strict gate at READ time too, so a
          // pref left over from an older install (or set via about:config)
          // that would now be rejected as a non-IP-literal cannot sneak
          // into the candidate list. isValidSocksHost would also accept a
          // bare DNS name like `tor` — that's the wrong validator here.
          const trimmed = rawHost.trim();
          if (!(isLoopbackSocksHost(trimmed) || isIpLiteralSocksHost(trimmed))) {
            console.warn(
              "[onionbird] stored SOCKS override host failed validation (isValidSocksHost passes but isLoopback||isIpLiteral does not); ignoring"
            );
            return null;
          }
          let port;
          try { port = normalizeSocksPortValue(rawPort); }
          catch (e) {
            console.warn("[onionbird] stored SOCKS override port failed validation; ignoring");
            return null;
          }
          // S-8: pass the host through normalizeSocksHost too for
          // IPv6-literal canonicalization (callers like the candidate
          // ladder compare via socksHostCompareKey which lowercases —
          // returning a normalized value here keeps comparisons stable
          // even if a future caller does a strict-equal check).
          let host = trimmed;
          try { host = normalizeSocksHost(trimmed); }
          catch (e) { /* already passed the strict gate above; defensive */ }
          return { host, port };
        },

        clearPref: async (name) => {
          if (!isAddonOwnedPref(name)) {
            console.warn(
              `[onionbird] clearPref(${safePrefName(name)}) denied: addon-owned prefs only`
            );
            return false;
          }
          try {
            clearPrefValue(name);
            return true;
          } catch (e) {
            console.error(`[onionbird] clearPref(${safePrefName(name)}) failed:`, e);
            return false;
          }
        },

        clearAddonOwnedPrefs: async () => {
          // F-076: clear the addon's own per-install prefs
          // (`onionbird.messageid.fqdn_mode/custom/fallback`) on
          // disable. Otherwise the per-install random
          // `m<10hex>.invalid` fallback value persists across
          // disable AND uninstall — a forensic fingerprint that
          // survives the user's explicit "remove this addon"
          // gesture. Returns {cleared:[...], failed:[...]}.
          const cleared = [];
          const failed = [];
          for (const name of ADDON_OWNED_PREF_NAMES) {
            try {
              if (Services.prefs.prefHasUserValue(name)) {
                clearPrefValue(name);
                cleared.push(name);
              }
            } catch (e) {
              console.error(
                `[onionbird] clearAddonOwnedPrefs(${name}) failed:`,
                e
              );
              failed.push({ name, error: String(e) });
            }
          }
          return { cleared, failed };
        },

        clearDnsCache: async () => {
          // Flush nsIDNSService cache + all cached mail connections.
          // Must be called across enable/disable transitions or stale
          // clearnet IPs from a previous mode could survive into Tor mode
          // (or vice-versa). Returns {dns, smtp_servers_closed}.
          let dnsCleared = false;
          let smtpClosed = 0;
          try {
            const dns = Components.classes["@mozilla.org/network/dns-service;1"]
              .getService(Components.interfaces.nsIDNSService);
            dns.clearCache(true);
            dnsCleared = true;
          } catch (e) {
            console.error("[onionbird] dns.clearCache failed:", e);
          }
          if (MailServices) {
            try {
              const outgoing = MailServices.outgoingServer || MailServices.smtp;
              if (outgoing && outgoing.servers) {
                for (const s of outgoing.servers) {
                  try {
                    s.QueryInterface(Ci.nsISmtpServer).closeCachedConnections();
                    smtpClosed++;
                  } catch (e) {
                    console.warn("[onionbird] closeCachedConnections failed:", e);
                  }
                }
              }
            } catch (e) {
              console.error("[onionbird] SMTP cache flush failed:", e);
            }
          }
          return { dns: dnsCleared, smtp_servers_closed: smtpClosed };
        },

        // F-044: per-pref validate-and-write. The previous all-or-
        // nothing upfront-validation behaviour was a fail-OPEN
        // regression at 110-entry HARDENING_PREFS scale: a single bad
        // pref (failed SOCKS probe → null value, a future refactor
        // that adds a pref not in ALLOWED_PREF_NAMES, etc.) silently
        // dropped the entire fail-closed batch and returned the user
        // to clearnet while the caller saw "applyPrefs failed". The
        // batch-rollback loop was deleted for the same reason. Once a
        // fail-closed pref is applied it persists; restoration happens
        // through the snapshot path in disableHardening rather than
        // through batch rollback.
        applyPrefs: async (prefs) => {
          const applied = [];
          const failed = [];
          if (!Array.isArray(prefs)) {
            const error = "prefs must be an array";
            console.error(`[onionbird] applyPrefs failed: ${error}`);
            return { applied, failed: [{ name: "<prefs>", error }] };
          }
          if (prefs.length > MAX_PREF_BATCH_SIZE) {
            const error = `prefs batch too large (max ${MAX_PREF_BATCH_SIZE})`;
            console.error(`[onionbird] applyPrefs failed: ${error}`);
            return { applied, failed: [{ name: "<prefs>", error }] };
          }

          for (const pref of prefs) {
            if (!pref || typeof pref.name !== "string") {
              failed.push({ name: "<invalid>", error: "invalid pref object" });
              continue;
            }
            const name = pref.name;
            if (!isAllowedPref(name)) {
              failed.push({ name: safePrefName(name), error: "not in allowlist" });
              continue;
            }
            if (!isValidPrefValue(pref.value)) {
              failed.push({ name, error: "invalid pref value type" });
              continue;
            }
            try {
              writePref(name, pref.value);
              applied.push(name);
            } catch (e) {
              console.error(`[onionbird] applyPrefs(${name}) failed:`, e);
              failed.push({ name, error: String(e) });
            }
          }
          if (failed.length > 0) {
            console.warn("[onionbird] applyPrefs partial failures:", {
              applied_count: applied.length,
              failed,
            });
          }
          return { applied, failed };
        },

        snapshotPrefs: async (names, options) => {
          // F-077: `options.source === "default"` snapshots from the
          // default branch instead of the user branch. Used by the
          // corrupt-snapshot recovery path in background.js so the
          // recovered baseline cannot be the live (possibly-already-
          // hardened) state. Default: snapshot from user-branch
          // values (the normal first-install case).
          const snap = {};
          const useDefaultBranch =
            options && options.source === "default";
          if (!Array.isArray(names)) {
            console.error("[onionbird] snapshotPrefs failed: names must be an array");
            return snap;
          }
          if (names.length > MAX_PREF_SNAPSHOT_SIZE) {
            console.error(
              `[onionbird] snapshotPrefs failed: too many names (max ${MAX_PREF_SNAPSHOT_SIZE})`
            );
            return snap;
          }
          const branch = useDefaultBranch
            ? Services.prefs.getDefaultBranch("")
            : Services.prefs;
          for (const name of names) {
            if (!isAllowedPref(name)) {
              console.warn(
                `[onionbird] snapshotPrefs(${safePrefName(name)}) denied by allowlist`
              );
              continue;
            }
            try {
              const type = branch.getPrefType(name);
              if (type === branch.PREF_INVALID) {
                snap[name] = null;
                continue;
              }
              if (useDefaultBranch) {
                if (type === branch.PREF_STRING) snap[name] = branch.getStringPref(name);
                else if (type === branch.PREF_INT) snap[name] = branch.getIntPref(name);
                else if (type === branch.PREF_BOOL) snap[name] = branch.getBoolPref(name);
                else snap[name] = null;
              } else {
                snap[name] = Services.prefs.prefHasUserValue(name)
                  ? readPref(name)
                  : null;
              }
            } catch (e) {
              console.warn(
                `[onionbird] snapshotPrefs(${safePrefName(name)}) read failed:`,
                e
              );
              snap[name] = null;
            }
          }
          return snap;
        },

        restorePrefs: async (snapshot) => {
          const restored = [];
          const failed = [];
          if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
            const error = "snapshot must be an object";
            console.error(`[onionbird] restorePrefs failed: ${error}`);
            return { restored, failed: [{ name: "<snapshot>", error }] };
          }
          const entries = Object.entries(snapshot);
          if (entries.length > MAX_PREF_SNAPSHOT_SIZE) {
            const error = `snapshot too large (max ${MAX_PREF_SNAPSHOT_SIZE})`;
            console.error(`[onionbird] restorePrefs failed: ${error}`);
            return { restored, failed: [{ name: "<snapshot>", error }] };
          }
          for (const [name, value] of entries) {
            try {
              // Round-4 I-6: even clearUserPref must go through the
              // allowlist gate. Otherwise a hostile snapshot value could
              // clear xpinstall.signatures.required or other security
              // prefs that aren't ours to touch.
              if (!isAllowedPref(name)) {
                console.warn(
                  `[onionbird] restorePrefs(${safePrefName(name)}) denied by allowlist`
                );
                failed.push({ name: safePrefName(name), error: "not in allowlist" });
                continue;
              }
              if (!isValidPrefValue(value, true)) {
                console.warn(
                  `[onionbird] restorePrefs(${safePrefName(name)}) denied: invalid value type`
                );
                failed.push({ name, error: "invalid pref value type" });
                continue;
              }
              if (value === null) {
                clearPrefValue(name);
              } else {
                writePref(name, value);
              }
              restored.push(name);
            } catch (e) {
              console.error(`[onionbird] restorePrefs(${safePrefName(name)}) failed:`, e);
              failed.push({ name: safePrefName(name), error: String(e) });
            }
          }
          return { restored, failed };
        },

        getSmtpHardeningPrefNames: async (onlyOnionHosts) => {
          if (!MailServices) {
            return { names: [], skipped: [], failed: [{ error: "MailServices unavailable" }] };
          }
          const outgoing = MailServices.outgoingServer || MailServices.smtp;
          if (!outgoing || !outgoing.servers) {
            return { names: [], skipped: [], failed: [{ error: "SMTP service unavailable" }] };
          }
          const names = [];
          const skipped = [];
          const failed = [];
          for (const s of outgoing.servers) {
            let key = "<unknown>";
            let hostname = "";
            try {
              key = s.key;
              if (!isSafeAccountKey(key)) {
                throw new Error("unsafe SMTP server key");
              }
              const ss = s.QueryInterface
                ? s.QueryInterface(Ci.nsISmtpServer)
                : s;
              hostname = ss.hostname || "";
            } catch (e) {
              console.warn("[onionbird] SMTP pref-name discovery failed:", e);
              failed.push({
                key: safeAccountKeyForReport(key),
                host_type: classifyMailHostForReport(hostname),
                error: String(e),
              });
              continue;
            }
            if (onlyOnionHosts && !isOnionHost(hostname) && !isLoopbackHost(hostname)) {
              skipped.push({ key, host_type: classifyMailHostForReport(hostname) });
              continue;
            }
            names.push(...smtpHardeningPrefNames(key));
          }
          return { names, skipped, failed };
        },

        getIdentityHardeningPrefNames: async () => {
          if (!MailServices) {
            return { names: [], failed: [{ error: "MailServices unavailable" }] };
          }
          const names = [];
          const failed = [];
          for (const identity of MailServices.accounts.allIdentities) {
            let key = "<unknown>";
            try {
              key = identity.key;
              if (!isSafeAccountKey(key)) {
                throw new Error("unsafe identity key");
              }
              names.push(...identityHardeningPrefNames(key));
            } catch (e) {
              console.warn("[onionbird] identity pref-name discovery failed:", e);
              failed.push({ key: safeAccountKeyForReport(key), error: String(e) });
            }
          }
          names.push(...identityHardeningPrefNames("default"));
          return { names, failed };
        },

        // F-097 / F-017: `onlyOnionHosts` is deliberately retained
        // even though the only production caller passes `true`. The
        // `false` code path is reserved for the planned F-017 UI
        // toggle (Options → "Harden every SMTP server, not just
        // onion/loopback") so users with mixed-mode profiles can opt
        // in to addon-wide hardening. The parameter is exposed via
        // the experiment API and sender-checked to browser.runtime.id
        // so no untrusted caller can flip it from outside the addon.
        // Drop the parameter only after F-017 either lands or is
        // formally cancelled.
        applyHardeningToAllSmtpServers: async (onlyOnionHosts) => {
          if (!MailServices) return { applied: [], failed: [], skipped: [] };
          const outgoing = MailServices.outgoingServer || MailServices.smtp;
          if (!outgoing || !outgoing.servers) {
            return { applied: [], failed: [], skipped: [] };
          }
          const applied = [];
          const failed = [];
          const skipped = [];
          for (const s of outgoing.servers) {
            let key = "<unknown>";
            let hostname = "";
            try {
              key = s.key;
              if (!isSafeAccountKey(key)) {
                throw new Error("unsafe SMTP server key");
              }
              const ss = s.QueryInterface
                ? s.QueryInterface(Ci.nsISmtpServer)
                : s;
              hostname = ss.hostname || "";
            } catch (e) {
              console.warn("[onionbird] SMTP server inspection failed:", e);
              failed.push({
                key: safeAccountKeyForReport(key),
                host_type: classifyMailHostForReport(hostname),
                error: String(e),
              });
              continue;
            }
            // B-003: Only harden onion or loopback servers (or all if !onlyOnionHosts)
            if (onlyOnionHosts && !isOnionHost(hostname) && !isLoopbackHost(hostname)) {
              skipped.push({ key, host_type: classifyMailHostForReport(hostname) });
              continue;
            }
            try {
              // Round-4 P1-9: route through writePref so the allowlist
              // is the only write gate. Direct Services.prefs.set*Pref
              // bypassed the allowlist and was a future-RCE footgun.
              writePref(
                `mail.smtpserver.${key}.hello_argument`,
                "[127.0.0.1]"
              );
              writePref(
                `mail.smtpserver.${key}.try_ssl`,
                isOnionHost(hostname) ? 0 : 3
              );
              applied.push({ key, host_type: classifyMailHostForReport(hostname) });
            } catch (e) {
              console.error(`[onionbird] SMTP hardening failed for ${key}:`, e);
              failed.push({
                key: safeAccountKeyForReport(key),
                host_type: classifyMailHostForReport(hostname),
                error: String(e),
              });
            }
          }
          return { applied, failed, skipped };
        },

        applyHardeningToAllIdentities: async (options) => {
          // F-075: `options.onlyOnionIdentities = true` skips identities
          // whose bound SMTP server is neither onion nor loopback. This
          // mirrors the SMTP-side gating (applyHardeningToAllSmtpServers
          // accepts the same boolean) and honours the README + Options-
          // page disableHelp promise that clearnet accounts kept outside
          // Tor mode keep working normally. Default (no option) keeps
          // the historic harden-everything behaviour for callers that
          // explicitly want it.
          const onlyOnionIdentities =
            !!(options && options.onlyOnionIdentities);
          if (!MailServices) return { applied: [], failed: [], skipped: [] };
          const applied = [];
          const failed = [];
          const skipped = [];

          // Precompute the set of SMTP-server keys whose hostname is
          // onion or loopback. Cheap (max few dozen servers) and avoids
          // re-walking outgoing.servers per identity.
          let onionLikeSmtpKeys = null;
          if (onlyOnionIdentities) {
            onionLikeSmtpKeys = new Set();
            try {
              const outgoing = MailServices.outgoingServer || MailServices.smtp;
              if (outgoing && outgoing.servers) {
                for (const s of outgoing.servers) {
                  try {
                    const ss = s.QueryInterface
                      ? s.QueryInterface(Ci.nsISmtpServer)
                      : s;
                    const host = ss.hostname || "";
                    if (isOnionHost(host) || isLoopbackHost(host)) {
                      onionLikeSmtpKeys.add(ss.key);
                    }
                  } catch (e) { /* per-server error, keep going */ }
                }
              }
            } catch (e) {
              console.warn("[onionbird] identity gating SMTP-walk failed:", e);
            }
          }
          // Reallife-audit reconsideration (2026-05-22): default to the
          // From-address's domain when available. That makes the Message-ID
          // look like a normal user at the provider (e.g.
          // `<uuid@undisclose.de>` instead of `<uuid@localhost.localdomain>`).
          // If an identity has no usable From domain yet, use a per-install
          // random `.invalid` fallback rather than a global localhost
          // supercluster.
          //
          // Mode controlled by `onionbird.messageid.fqdn_mode`:
          //   "from_domain" (default)  — use identity.email's domain
          //   "localhost"              — bare "localhost"
          //   "localhost.localdomain"  — legacy TorBirdy choice
          //   "custom"                 — uses onionbird.messageid.fqdn_custom
          let mode = "from_domain";
          try { mode = Services.prefs.getCharPref("onionbird.messageid.fqdn_mode"); }
          catch (e) {}
          let custom = "";
          try { custom = Services.prefs.getCharPref("onionbird.messageid.fqdn_custom"); }
          catch (e) {}
          const fallbackFqdn = getMessageIdFallbackFqdn();

          function pickFqdn(identityEmail) {
            // "localhost" / "localhost.localdomain" are explicit user choices.
            if (mode === "localhost") return "localhost";
            if (mode === "localhost.localdomain") return "localhost.localdomain";
            if (mode === "custom" && isValidMessageIdFqdn(custom)) return custom;
            if (identityEmail && identityEmail.indexOf("@") !== -1) {
              const dom = identityEmail.split("@").pop();
              // F-073: never emit the user's onion address as the
              // Message-ID FQDN, even if from_domain mode is on. The
              // onion mailbox IS the identifying secret — printing it
              // in every outbound header discloses the onion identity
              // to every recipient and to anyone scraping Received
              // chains. Fall through to the per-install random
              // `m<hex>.invalid` fallback instead. The bytes go via
              // Tor; the application-layer header must not leak the
              // origin.
              if (isValidMessageIdFqdn(dom) && !isOnionHost(dom)) return dom;
            }
            return fallbackFqdn;
          }

          for (const identity of MailServices.accounts.allIdentities) {
            let id = "<unknown>";
            try {
              id = identity.key;
              if (!isSafeAccountKey(id)) {
                throw new Error("unsafe identity key");
              }
              // F-075: in onion-only mode, skip identities whose bound
              // SMTP server is not onion/loopback. We DO process
              // identities with NO bound server (smtpServerKey empty)
              // because they inherit the default identity branch we
              // harden unconditionally below.
              if (onlyOnionIdentities) {
                const smtpKey = identity.smtpServerKey || "";
                if (smtpKey && !onionLikeSmtpKeys.has(smtpKey)) {
                  skipped.push({ key: id, reason: "clearnet-bound-smtp" });
                  continue;
                }
              }
              const fqdn = pickFqdn(identity.email);
              // Route through writePref so allowlist is the only gate
              // (Round-4 P1-9 / I-1: previously bypassed via direct
              // Services.prefs.set*Pref calls).
              writePref(`mail.identity.${id}.FQDN`, fqdn);
              writePref(`mail.identity.${id}.compose_html`, false);
              // Round-4 P0-A: strip identity-bound disclosure surfaces.
              // Reply-To: real@employer.com on an anon identity = full
              // deanonymization. Organization: corp_name = corporate
              // fingerprint. vCard + signature attach = embed-anything.
              writePref(`mail.identity.${id}.reply_to`, "");
              writePref(`mail.identity.${id}.organization`, "");
              writePref(`mail.identity.${id}.attach_vcard`, false);
              writePref(`mail.identity.${id}.attach_signature`, false);
              writePref(`mail.identity.${id}.htmlSigText`, "");
              writePref(`mail.identity.${id}.htmlSigFormat`, false);
              applied.push({ key: id, fqdn_mode: mode });
            } catch (e) {
              console.error(
                `[onionbird] identity hardening failed for ${safeAccountKeyForReport(id)}:`,
                e
              );
              failed.push({ key: safeAccountKeyForReport(id), error: String(e) });
            }
          }
          // Round-4 P0-C: write the DEFAULT identity branch too, so
          // pref-inheritance can't re-inject Reply-To / Organization /
          // hostname from underneath us when a new identity is created
          // before our account-observer (deferred) catches up.
          try {
            writePref("mail.identity.default.FQDN", fallbackFqdn);
            writePref("mail.identity.default.compose_html", false);
            writePref("mail.identity.default.reply_to", "");
            writePref("mail.identity.default.organization", "");
            writePref("mail.identity.default.attach_vcard", false);
            writePref("mail.identity.default.attach_signature", false);
            writePref("mail.identity.default.htmlSigText", "");
            writePref("mail.identity.default.htmlSigFormat", false);
          } catch (e) {
            console.error("[onionbird] default identity hardening failed:", e);
            failed.push({ key: "default", error: String(e) });
          }
          return { applied, failed, skipped, mode };
        },

        clearHardeningFromAllSmtpServers: async () => {
          if (!MailServices) return { cleared: [], failed: [] };
          const outgoing = MailServices.outgoingServer || MailServices.smtp;
          if (!outgoing || !outgoing.servers) return { cleared: [], failed: [] };
          const cleared = [];
          const failed = [];
          const skipped = [];
          for (const s of outgoing.servers) {
            let key = "<unknown>";
            let hostname = "";
            try {
              key = s.key;
              if (!isSafeAccountKey(key)) {
                throw new Error("unsafe SMTP server key");
              }
              const ss = s.QueryInterface
                ? s.QueryInterface(Ci.nsISmtpServer)
                : s;
              hostname = ss.hostname || "";
              if (!isOnionHost(hostname) && !isLoopbackHost(hostname)) {
                skipped.push({ key, host_type: classifyMailHostForReport(hostname) });
                continue;
              }
              for (const name of smtpHardeningPrefNames(key)) {
                clearPrefValue(name);
              }
              cleared.push(key);
            } catch (e) {
              console.error(
                `[onionbird] SMTP hardening clear failed for ${safeAccountKeyForReport(key)}:`,
                e
              );
              failed.push({ key: safeAccountKeyForReport(key), error: String(e) });
            }
          }
          return { cleared, failed, skipped };
        },

        auditSavedLoginsForTorServers: async () => {
          const origins = torMailLoginOrigins();
          const { logins, failed } = await findSavedLoginsForOrigins(origins);
          return {
            origins: origins.map(publicLoginOriginInfo),
            count: logins.length,
            logins: logins.map(publicLoginInfo),
            failed,
          };
        },

        removeSavedLoginsForTorServers: async () => {
          const origins = torMailLoginOrigins();
          const { logins, failed } = await findSavedLoginsForOrigins(origins);
          const removed = [];
          for (const login of logins) {
            const info = publicLoginInfo(login);
            try {
              Services.logins.removeLogin(login);
              removed.push(info);
            } catch (e) {
              console.error("[onionbird] removeLogin for Tor mail origin failed:", e);
              failed.push({
                ...info,
                error: summarizeErrorForLog(e.message || String(e)),
              });
            }
          }
          if (removed.length > 0) {
            console.warn(
              `[onionbird] removed ${removed.length} saved login(s) for Tor mail servers`
            );
          }
          return { origins: origins.map(publicLoginOriginInfo), removed, failed };
        },

        probeSocks: async (socksHost, socksPort, host, options) => {
          const target = host === undefined || host === null || host === ""
            ? "check.torproject.org"
            : host;
          const result = {
            ok: false,
            socks_host: typeof socksHost === "string" ? socksHost : "",
            socks_port: Number.isInteger(socksPort) ? socksPort : null,
            host: typeof target === "string" ? target : null,
            ip: null,
            error: null,
          };
          try {
            if (typeof target !== "string" || !isValidDnsHost(target)) {
              throw new Error("invalid probe host (must be a DNS-shaped name)");
            }
            const normalizedHost = normalizeSocksHost(socksHost);
            const normalizedPort = normalizeSocksPortValue(socksPort);
            // F-168 I-1: thread the userProbe flag so Options-page
            // Test bypasses the currentSocksEndpointMatches requirement.
            assertAllowedSocksEndpoint(normalizedHost, normalizedPort, options);
            result.socks_host = normalizedHost;
            result.socks_port = normalizedPort;
            result.ip = await socks5Resolve(
              normalizedHost,
              normalizedPort,
              target,
              randomIsolationToken()
            );
            result.ok = !!result.ip;
          } catch (e) {
            result.error = e.message || String(e);
            console.warn(
              "[onionbird] SOCKS probe failed:",
              {
                ...summarizeSocksEndpointForLog(result.socks_host, result.socks_port),
                error: summarizeErrorForLog(result.error),
              }
            );
          }
          return result;
        },

        runSelfTest: async (host, options) => {
          // P0-T3-2: validate caller input. host travels into a raw SOCKS5
          // packet and into UI text — both want strict shape.
          if (!isValidDnsHost(host)) {
            return {
              host: null, tor_ips: [], system_ip: null, system_ips: [],
              error: "invalid host (must be a DNS-shaped name)",
              errors: [], leak_detected: false,
            };
          }
          // Cap tries at 10 — runaway caller can't make us hammer Tor.
          const cfg = options && typeof options === "object" && !Array.isArray(options)
            ? options
            : {};
          const tries = Number.isInteger(cfg.tries)
            ? Math.min(10, Math.max(1, cfg.tries))
            : 3;
          let socksHost = null;
          let socksPort = null;
          try {
            // F-182: the WebExtension schema validator normalizes
            // *missing* optional fields to `null` (not `undefined`). A
            // background caller passing `{tries:3}` arrives here as
            // `{tries:3, socksHost:null, socksPort:null}`. The
            // previous `!== undefined` check let null through and
            // normalizeSocksHost(null) threw "invalid SOCKS host:
            // <invalid>" — surfacing in the UI as the user-visible
            // canary error. Treat both null AND undefined as "not
            // supplied" and fall through to the pref read.
            socksHost = (() => {
              if (cfg.socksHost !== undefined && cfg.socksHost !== null) {
                return normalizeSocksHost(cfg.socksHost);
              }
              try { return Services.prefs.getCharPref("network.proxy.socks"); }
              catch (e) { return "127.0.0.1"; }
            })();
            socksPort = (() => {
              if (cfg.socksPort !== undefined && cfg.socksPort !== null) {
                return normalizeSocksPortValue(cfg.socksPort);
              }
              try { return Services.prefs.getIntPref("network.proxy.socks_port"); }
              catch (e) { return 9050; }
            })();
            // F-172: thread cfg (which carries `userProbe` when the
            // caller is a UI-initiated run-self-test) so the gate can
            // bypass the currentSocksEndpointMatches requirement —
            // same fix as F-168 I-1 for probeSocks. Without this, a
            // self-test invoked before the override has been applied
            // to network.proxy.socks rejects the IP-literal endpoint
            // with the misleading "SOCKS endpoint not allowed".
            assertAllowedSocksEndpoint(socksHost, socksPort, cfg);
          } catch (e) {
            return {
              host, tor_ips: [], system_ip: null, system_ips: [],
              socks_host: socksHost || null, socks_port: socksPort || null,
              error: e.message || String(e), errors: [], leak_detected: false,
            };
          }
          const result = {
            host,
            socks_host: socksHost,
            socks_port: socksPort,
            tor_ips: [],
            system_ip: null,
            system_ips: [],
            system_ptr: null,
            system_ptrs: [],
            leak_detected: false,
            error: null,
            errors: [],
          };
          // Issue N isolated SOCKS5 RESOLVE queries. Each call gets a
          // fresh opaque hex token so Tor binds a distinct circuit AND
          // no observer of the local SOCKS auth can correlate "this is
          // a onionbird canary" — the token has no project marker.
          for (let i = 0; i < tries; i++) {
            const token = randomIsolationToken();
            try {
              const ip = await socks5Resolve(socksHost, socksPort, host, token);
              if (ip && result.tor_ips.indexOf(ip) === -1) {
                result.tor_ips.push(ip);
              }
            } catch (e) {
              result.errors.push(`socks5#${i}: ${e.message || e}`);
            }
          }
          if (result.tor_ips.length === 0) {
            result.error = result.errors.join("; ") || "all socks5 resolves failed";
            return result;
          }
          // System / Necko resolve — returns the FULL A-record set, not
          // just the first rotation. Asymmetry between "tor: 3 isolated
          // circuits gave us a small set" and "system: just one IP"
          // produces false-positive leaks on multi-A services.
          let systemIps = [];
          try {
            systemIps = await systemResolve(host);
          } catch (e) {
            result.error = `system: ${e.message || e}`;
            return result;
          }
          // Canonicalize for clean comparison + populate fields.
          result.tor_ips = result.tor_ips.map(canonicalizeIp);
          result.system_ips = systemIps.map(canonicalizeIp);
          // Keep system_ip for back-compat with options UI / older callers
          // — the first record (resolver's preferred rotation).
          result.system_ip = result.system_ips[0] || null;

          if (result.system_ips.length === 0) {
            result.error = "system resolve returned no records";
            return result;
          }
          const actionableSystemIps = result.system_ips.filter(
            ip => !isInconclusiveIp(ip)
          );
          // Treat only inconclusive IPs (private / sentinel / link-local /
          // multicast) as non-leak.
          if (actionableSystemIps.length === 0) {
            return result;
          }
          // Every actionable system answer must be explainable. Accept IPs
          // seen through Tor directly; every other public answer needs PTR
          // confirmation. Otherwise a poisoned resolver can return one real
          // target IP plus one attacker IP and pass an "any intersection"
          // test while Thunderbird might use the attacker-controlled answer.
          const divergentIps = actionableSystemIps.filter(
            ip => result.tor_ips.indexOf(ip) === -1
          );
          if (divergentIps.length === 0) {
            return result;
          }
          if (divergentIps.length > MAX_PTR_CONFIRMATIONS) {
            result.errors.push(
              `ptr: too many divergent system IPs (${divergentIps.length})`
            );
            result.leak_detected = true;
            return result;
          }

          let allDivergentIpsConfirmed = true;
          for (const probe of divergentIps) {
            try {
              // Opaque random PTR token — no project marker, fresh per
              // call. Crypto-RNG, not Math.random (P1-T3-1).
              const ptr = await socks5ResolvePtr(
                socksHost, socksPort, probe, randomIsolationToken()
              );
              if (!result.system_ptr && ptr) result.system_ptr = ptr;
              result.system_ptrs.push(ptr || null);
              if (!ptrConfirmsTargetHost(ptr, host)) {
                allDivergentIpsConfirmed = false;
              }
            } catch (e) {
              allDivergentIpsConfirmed = false;
              result.errors.push(`ptr: ${e.message || e}`);
            }
          }
          if (allDivergentIpsConfirmed) return result;
          // No confirmation from set-membership or PTR — flag as leak.
          result.leak_detected = true;
          return result;
        },

        clearHardeningFromAllIdentities: async () => {
          if (!MailServices) return { cleared: [], failed: [] };
          const cleared = [];
          const failed = [];
          for (const identity of MailServices.accounts.allIdentities) {
            let id = "<unknown>";
            try {
              id = identity.key;
              if (!isSafeAccountKey(id)) {
                throw new Error("unsafe identity key");
              }
              for (const name of identityHardeningPrefNames(id)) {
                clearPrefValue(name);
              }
              cleared.push(id);
            } catch (e) {
              console.error(
                `[onionbird] identity hardening clear failed for ${safeAccountKeyForReport(id)}:`,
                e
              );
              failed.push({ key: safeAccountKeyForReport(id), error: String(e) });
            }
          }
          try {
            for (const name of identityHardeningPrefNames("default")) {
              clearPrefValue(name);
            }
            cleared.push("default");
          } catch (e) {
            console.error("[onionbird] default identity hardening clear failed:", e);
            failed.push({ key: "default", error: String(e) });
          }
          return { cleared, failed };
        },
      },
    };
  }
};
