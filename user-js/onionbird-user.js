// SPDX-License-Identifier: MPL-2.0
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// onionbird companion user.js
//
// Pre-startup hardening: applied before the addon loads, mitigates the
// window between Thunderbird launch and addon initialization where DNS
// probes, autoconfig fetches, update checks, etc. fire.
//
// Install via scripts/install-user-js.sh into your active TB profile.
//
// This file is conservative: it only sets prefs that are safe regardless
// of network configuration. SOCKS routing and Tor-specific prefs are set
// by the addon at runtime (so a user with mixed Tor + clearnet accounts
// can toggle hardening without losing connectivity globally).
//
// Restart Thunderbird after installing for changes to take effect.

// === Anti-fingerprinting headers ===
user_pref("mailnews.headers.sendUserAgent", false);

// === Auto-config disabled (DNS-leak vector that fires BEFORE addon load) ===
user_pref("mailnews.auto_config.fetchFromISP.v2", false);
user_pref("mailnews.auto_config_url", "");
user_pref("mailnews.mx_service_url", "");
user_pref("mailnews.auto_config.guess.enabled", false);

// === Reply-header minimization ===
user_pref("mailnews.reply_header_type", 1);
user_pref("mailnews.reply_header_authorwrote", "%s");

// === Remote content / images blocked IN MAIL ONLY ===
// Note: `permissions.default.image=2` was removed — it blocks ALL images
// (calendar invites, in-app UI, account wizard) without need; the mail-
// specific pref below is enough.
user_pref("mailnews.message_display.disable_remote_image", true);

// === HTML mail render hardening (Round-4 P0-1, 2026-05-22) ===
// Force text-only render of HTML mail. Without this, a message with
// <video src=...>, <link rel=prefetch>, CSS url(), @font-face, @import
// or <iframe> resolves those URLs on first render — defeats the
// remote-image block. TorBirdy historically forced this.
user_pref("mailnews.display.html_as", 3);
user_pref("mailnews.display.prefer_plaintext", true);
user_pref("mailnews.display.disallow_mime_handlers", 100);

// === Telemetry / health-report / submission off ===
// Kept here as a belt-and-braces defense (effective even before TB
// finishes loading the addon, and survives an addon disable). The
// addon itself now re-asserts the same prefs at every enable/start
// (see HARDENING_PREFS in addon/background.js), so the addon-only
// install path no longer leaks telemetry either.
user_pref("toolkit.telemetry.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);

// === Safebrowsing / blocklist / push pings off ===
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("extensions.blocklist.enabled", false);
user_pref("dom.push.serverURL", "");
user_pref("media.gmp-manager.url", "");
user_pref("services.settings.server", "");

// === Crash reporter off (Round-4 P0-2) ===
// Crash reporter is a separate process that does NOT honor
// network.proxy.* — minidumps + addon list + locale go to
// crash-reports.mozilla.com over clearnet.
user_pref("breakpad.reportURL", "");
user_pref("toolkit.crashreporter.include_extensions", false);
user_pref("toolkit.crashreporter.submitURL", "");

// === Mozilla Sync / Firefox Accounts off (Round-4 P0-3) ===
// Locks off the FxA flow that would replicate creds + address book
// to accounts.firefox.com if accidentally activated.
user_pref("services.sync.enabled", false);
user_pref("services.sync.serverURL", "");
user_pref("identity.fxaccounts.enabled", false);

// === Desktop notifications off (Round-4 P0-4) ===
// Notifications expose sender + subject of arriving mail to libnotify
// / dbus / Windows Action Center — every process on the session bus.
user_pref("mail.biff.show_alert", false);
user_pref("mail.biff.show_tray_icon", false);
user_pref("mail.biff.use_system_alert", false);
user_pref("mailnews.notifications.enabled", false);

// === Connectivity / captive-portal probes off ===
user_pref("network.connectivity-service.enabled", false);
user_pref("network.captive-portal-service.enabled", false);

// === No first-run prompts (cosmetic but reduces user error) ===
// B-012 fix: previous version set `mail.rights.override` which is not a real
// pref. The correct ones are mail.rights.version + mail.rights.acceptedEULA.
user_pref("mail.shell.checkDefaultClient", false);
user_pref("mail.rights.version", 1);
user_pref("mail.rights.acceptedEULA", true);

// === Calendar user-agent normalization (display TZ left alone) ===
// B-017 fix: previous version forced `calendar.timezone.local=UTC`, which
// mangles every event display for users who actually use the calendar.
// Date-header normalization belongs at compose time (handled by the addon
// via privacy.resistFingerprinting), not by mangling the calendar display.
user_pref("calendar.useragent.extra", "");

// === No JavaScript in mail (historical pref; ignored on modern TB but
// harmless to assert in case Mozilla re-introduces JS in mail) ===
user_pref("javascript.allow.mailnews", false);

// === Defense-in-depth: WebRTC / geo / prefetch / TRR ===
user_pref("media.peerconnection.enabled", false);
user_pref("geo.enabled", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.predictor.enabled", false);
user_pref("network.prefetch-next", false);
// Disable Trusted Recursive Resolver (DNS-over-HTTPS). TRR's DoH endpoint
// is a clearnet HTTPS host that — even routed through SOCKS — adds an
// independent path with its own cache & bootstrap. Safer to keep DNS on
// the single SOCKS5-remote-resolve path the addon controls.
user_pref("network.trr.mode", 5);

// === IMAP / NNTP client-info disclosure off ===
// Same belt-and-braces story as the telemetry block above: the addon
// also re-asserts these at runtime via HARDENING_PREFS, but keeping
// them here means a user who locks down via user.js but never enables
// the addon still gets covered.
user_pref("mail.imap.use_client_info", false);
user_pref("mail.server.default.send_client_info", false);

// NOTE: network.dns.disableIPv6 was REMOVED from this user.js. It is global
// and affects every account in the profile. The addon sets it at runtime as
// part of `enable-hardening`, scoped to the user's choice to enable Tor mode.
