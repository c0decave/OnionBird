// Test profile prefs — Marionette enabled, no first-run noise

// Marionette binds to 127.0.0.1 only. socat forwards external 2828 -> 127.0.0.1:2829.
user_pref("marionette.port", 2829);
user_pref("marionette.enabled", true);

// Suppress first-run modals
user_pref("mail.shell.checkDefaultClient", false);
user_pref("mail.rights.override", true);
user_pref("mail.provider.suppress_dialog_on_startup", true);
user_pref("mailnews.start_page.override_url", "about:blank");
user_pref("mailnews.start_page.url", "about:blank");

// No update checks during tests
user_pref("app.update.enabled", false);
user_pref("app.update.auto", false);
user_pref("app.update.service.enabled", false);
user_pref("extensions.update.enabled", false);
user_pref("extensions.update.autoUpdateDefault", false);

// Allow unsigned addons for testing
user_pref("xpinstall.signatures.required", false);
user_pref("extensions.experiments.enabled", true);
user_pref("extensions.legacy.enabled", true);
user_pref("extensions.autoDisableScopes", 0);
user_pref("extensions.enabledScopes", 15);

// Disable telemetry during tests
user_pref("toolkit.telemetry.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);

// Skip account-setup wizard on startup
user_pref("mail.provider.enabled", false);

// Make TB headless-friendly
user_pref("browser.dom.window.dump.enabled", true);
user_pref("devtools.console.stdout.chrome", true);

// IPv6 disabled at test level: /etc/hosts has only IPv4 entries.
// Without this, AAAA queries for container names hit dns-trap (NXDOMAIN),
// adding latency and noise. The addon's hardening also sets this in production.
user_pref("network.dns.disableIPv6", true);
