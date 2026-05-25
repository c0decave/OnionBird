// SPDX-License-Identifier: MPL-2.0
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
"use strict";

const THEME_STORAGE_KEY = "onionbird.theme";
const HELP_MODE_STORAGE_KEY = "onionbird.helpMode";

function t(key, substitutions) {
  if (typeof browser !== "undefined" && browser.i18n && browser.i18n.getMessage) {
    try {
      const msg = browser.i18n.getMessage(key, substitutions);
      if (msg) return msg;
    } catch (e) {
      console.warn("[onionbird] i18n lookup failed:", key, e);
    }
  }
  return key;
}

function applyI18n() {
  const uiLanguage =
    typeof browser !== "undefined" && browser.i18n && browser.i18n.getUILanguage
      ? browser.i18n.getUILanguage()
      : "en";
  document.documentElement.lang = uiLanguage.split("-")[0] || "en";
  document.title = t("pageTitle");
  for (const el of document.querySelectorAll("[data-i18n]")) {
    el.textContent = t(el.dataset.i18n);
  }
}

function normalizeTheme(theme) {
  return ["system", "light", "dark"].includes(theme) ? theme : "system";
}

function applyTheme(theme) {
  const normalized = normalizeTheme(theme);
  if (normalized === "system") {
    delete document.documentElement.dataset.theme;
  } else {
    document.documentElement.dataset.theme = normalized;
  }
  for (const button of document.querySelectorAll("[data-theme-choice]")) {
    button.setAttribute(
      "aria-pressed",
      String(button.dataset.themeChoice === normalized)
    );
  }
  return normalized;
}

function loadStoredTheme() {
  try {
    return normalizeTheme(localStorage.getItem(THEME_STORAGE_KEY));
  } catch (e) {
    return "system";
  }
}

function storeTheme(theme) {
  const normalized = applyTheme(theme);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, normalized);
  } catch (e) {
    console.warn("[onionbird] could not store theme:", e);
  }
}

const HELP_SECTIONS = {
  tldr: [
    {
      title: "helpTldrDoesTitle",
      items: [
        "helpTldrDoes1",
        "helpTldrDoes2",
        "helpTldrDoes3",
        "helpTldrDoes4",
      ],
    },
    {
      title: "helpTldrDoesNotTitle",
      items: [
        "helpTldrDoesNot1",
        "helpTldrDoesNot2",
        "helpTldrDoesNot3",
        "helpTldrDoesNot4",
      ],
    },
    {
      title: "helpTldrTorbirdyTitle",
      items: ["helpTldrTorbirdy1", "helpTldrTorbirdy2"],
    },
    {
      title: "helpTldrExperimentsTitle",
      items: ["helpTldrExperiments1", "helpTldrExperiments2"],
    },
  ],
  nerd: [
    {
      title: "helpNerdDoesTitle",
      items: [
        "helpNerdDoes1",
        "helpNerdDoes2",
        "helpNerdDoes3",
        "helpNerdDoes4",
        "helpNerdDoes5",
      ],
    },
    {
      title: "helpNerdDoesNotTitle",
      items: [
        "helpNerdDoesNot1",
        "helpNerdDoesNot2",
        "helpNerdDoesNot3",
        "helpNerdDoesNot4",
        "helpNerdDoesNot5",
      ],
    },
    {
      title: "helpNerdTorbirdyTitle",
      items: [
        "helpNerdTorbirdy1",
        "helpNerdTorbirdy2",
        "helpNerdTorbirdy3",
      ],
    },
    {
      title: "helpNerdExperimentsTitle",
      items: [
        "helpNerdExperiments1",
        "helpNerdExperiments2",
        "helpNerdExperiments3",
      ],
    },
  ],
};

function normalizeHelpMode(mode) {
  return mode === "nerd" ? "nerd" : "tldr";
}

function renderHelp(mode) {
  const normalized = normalizeHelpMode(mode);
  const container = document.getElementById("help-content");
  if (!container) return normalized;
  container.textContent = "";
  for (const button of document.querySelectorAll("[data-help-mode]")) {
    button.setAttribute(
      "aria-pressed",
      String(button.dataset.helpMode === normalized)
    );
  }
  for (const section of HELP_SECTIONS[normalized]) {
    const title = document.createElement("h3");
    title.textContent = t(section.title);
    container.appendChild(title);

    const list = document.createElement("ul");
    list.className = "help-list";
    for (const item of section.items) {
      const li = document.createElement("li");
      li.textContent = t(item);
      list.appendChild(li);
    }
    container.appendChild(list);
  }
  try {
    localStorage.setItem(HELP_MODE_STORAGE_KEY, normalized);
  } catch (e) {
    console.warn("[onionbird] could not store help mode:", e);
  }
  return normalized;
}

/**
 * Map a runSelfTest result to a {level, label, verdict} triple used by the UI.
 *
 *  level "ok"      — both lookups succeeded, IPs match or are inconclusive-private
 *  level "warn"    — IPs differ, but heuristic says benign (e.g. CDN round-robin)
 *  level "leak"    — leak_detected=true per the experiment API
 *  level "error"   — could not complete (socks5 failed, dns failed)
 *  level "unknown" — no run yet
 */
/**
 * Map raw canary error strings to actionable user guidance.
 * Returns null if no specific guidance fits — caller falls back to raw string.
 */
function explainCanaryError(err) {
  if (typeof err !== "string" || !err) return null;
  const s = err;
  if (/refused/i.test(s) && /9050/.test(s)) {
    return t("canaryErrorTor9050");
  }
  if (/refused/i.test(s) && /9150/.test(s)) {
    return t("canaryErrorTor9150");
  }
  if (/refused/i.test(s)) {
    return t("canaryErrorSocksRefused");
  }
  if (/network unreachable|ENETUNREACH/i.test(s)) {
    return t("canaryErrorNetworkUnreachable");
  }
  if (/timeout/i.test(s)) {
    return t("canaryErrorTimeout");
  }
  if (/dns 0x|dns status/i.test(s)) {
    return t("canaryErrorDnsStatus");
  }
  return null;
}

function maskIp(ip) {
  if (!ip) return "—";
  if (typeof ip !== "string" && typeof ip !== "number") return "<non-ip>";
  const value = String(ip);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    const parts = value.split(".");
    return `${parts[0]}.x.x.${parts[3]}`;
  }
  if (value.indexOf(":") !== -1) {
    const parts = value.split(":").filter(Boolean);
    if (parts.length <= 2) return "<ipv6>";
    return `${parts[0]}:…:${parts[parts.length - 1]}`;
  }
  return "<non-ip>";
}

function renderIpList(ips, reveal) {
  if (!Array.isArray(ips) || ips.length === 0) return "—";
  return ips.map((ip) => {
    if (!reveal) return maskIp(ip);
    return (typeof ip === "string" || typeof ip === "number")
      ? String(ip)
      : "<non-ip>";
  }).join(", ");
}

function describeSocksSource(source) {
  const value = typeof source === "string" ? source : "";
  const key = {
    "requested": "torTestSourceRequested",
    "existing-pref": "torTestSourceExistingPref",
    "system-tor": "torTestSourceSystemTor",
    "tor-browser": "torTestSourceTorBrowser",
    "fallback": "torTestSourceFallback",
    "current-pref": "torTestSourceCurrentPref",
  }[value];
  return key ? t(key) : (value || t("canaryUnknown"));
}

function formatTorEndpoint(socks) {
  if (!socks || typeof socks !== "object") return "—";
  const host = typeof socks.host === "string" && socks.host ? socks.host : "";
  const port = Number.isInteger(socks.port) ? String(socks.port) : "";
  if (!host || !port) return "—";
  return `${host}:${port} (${describeSocksSource(socks.source)})`;
}

function formatTorTestProbes(probes) {
  if (!Array.isArray(probes) || probes.length === 0) return "—";
  return probes.map((probe) => {
    const endpointHost = probe && typeof probe.socks_host === "string" &&
      probe.socks_host ? probe.socks_host : "?";
    const endpointPort = probe && Number.isInteger(probe.socks_port)
      ? String(probe.socks_port)
      : "?";
    const endpoint = `${endpointHost}:${endpointPort}`;
    const source = describeSocksSource(probe && probe.source);
    const verdict = probe && probe.ok
      ? t("torTestAvailable")
      : (probe && typeof probe.error === "string" && probe.error
        ? probe.error
        : t("torTestUnavailable"));
    return `${endpoint} (${source}): ${verdict}`;
  }).join("\n");
}

function isValidMessageIdFqdn(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 253 ||
    /^\d{1,3}(\.\d{1,3}){1,3}$/.test(value)
  ) {
    return false;
  }
  const labels = value.split(".");
  return labels.length >= 2 &&
    labels.every(label =>
      label.length > 0 &&
      label.length <= 63 &&
      /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label)
    );
}

function classifyTorTest(result) {
  if (!result) {
    return {
      level: "unknown",
      labelKey: "torTestUnknown",
      statusKey: "torTestNotRun",
    };
  }
  if (result.ok) {
    const socks = result.socks && typeof result.socks === "object"
      ? result.socks
      : null;
    const socksHost = socks && typeof socks.host === "string" && socks.host
      ? socks.host
      : "?";
    const socksPort = socks && Number.isInteger(socks.port)
      ? String(socks.port)
      : "?";
    return {
      level: "ok",
      labelKey: "torTestAvailable",
      statusKey: "torTestOk",
      statusArgs: [
        socksHost,
        socksPort,
        socks ? describeSocksSource(socks.source) : "?",
      ],
    };
  }
  return {
    level: "error",
    labelKey: "torTestUnavailable",
    statusKey: "torTestNoTor",
    statusArgs: [formatTorTestProbes(result.probes)],
  };
}

function renderTorTest(result) {
  const { level, labelKey, statusKey, statusArgs } = classifyTorTest(result);
  const badge = document.getElementById("tor-test-badge");
  if (badge) {
    badge.className = `badge ${level}`;
    badge.textContent = t(labelKey);
  }

  const status = document.getElementById("tor-test-status");
  if (status) status.textContent = t(statusKey, statusArgs);

  const detail = document.getElementById("tor-test-detail");
  if (!detail) return;
  if (!result) {
    detail.hidden = true;
    return;
  }
  detail.hidden = false;
  document.getElementById("tor-test-result").textContent = result.ok
    ? t("torTestAvailable")
    : t("torTestUnavailable");
  document.getElementById("tor-test-endpoint").textContent =
    result.ok ? formatTorEndpoint(result.socks) : "—";
  document.getElementById("tor-test-host").textContent = result.host || "—";
  document.getElementById("tor-test-tried").textContent =
    formatTorTestProbes(result.probes);
  document.getElementById("tor-test-error").textContent = result.error || "—";
}

function classifyCanary(result) {
  if (!result) {
    return {
      level: "unknown",
      label: "unknown",
      verdict: "no data yet",
      labelKey: "canaryUnknown",
      verdictKey: "canaryVerdictNoData",
    };
  }
  const torIps = Array.isArray(result.tor_ips) ? result.tor_ips : [];
  const systemIps = Array.isArray(result.system_ips) && result.system_ips.length > 0
    ? result.system_ips
    : (result.system_ip ? [result.system_ip] : []);
  if (result.error && torIps.length === 0) {
    return {
      level: "error",
      label: "error",
      verdict: result.error,
      labelKey: "canaryError",
    };
  }
  if (result.leak_detected) {
    return {
      level: "leak",
      label: "leak suspected",
      verdict: "system resolver answer is not in any Tor circuit's view — verify system DNS routing",
      labelKey: "canaryLeakSuspected",
      verdictKey: "canaryVerdictLeak",
    };
  }
  if (systemIps.length > 0 && torIps.length > 0 &&
      systemIps.some((ip) => torIps.indexOf(ip) !== -1)) {
    return {
      level: "ok",
      label: "no leak",
      verdict: `system_ip in Tor set (${torIps.length} circuit(s) tried)`,
      labelKey: "canaryNoLeak",
      verdictKey: "canaryVerdictOk",
      verdictArgs: [String(torIps.length)],
    };
  }
  if (systemIps.length > 0 && torIps.length > 0) {
    // system_ip is private OR otherwise not in tor_ips but we didn't flag
    // a leak (e.g. RFC1918). Surface this as warn.
    return {
      level: "warn",
      label: "diverged",
      verdict: "system_ip not in Tor set but heuristic says benign (private range?) — inspect details",
      labelKey: "canaryDiverged",
      verdictKey: "canaryVerdictDiverged",
    };
  }
  return {
    level: "warn",
    label: "inconclusive",
    verdict: result.error || "one of the lookups did not return data",
    labelKey: "canaryInconclusive",
    verdictKey: result.error ? null : "canaryVerdictMissingData",
  };
}

function renderCanary(result) {
  const { level, label, labelKey, verdict, verdictKey, verdictArgs } =
    classifyCanary(result);
  // F-179: mirror renderTorTest — null-check every getElementById before
  // dereferencing. The pre-fix code threw if any element was missing
  // from the HTML, taking the whole Options page down.
  const badge = document.getElementById("canary-badge");
  if (badge) {
    badge.className = `badge ${level}`;
    badge.textContent = labelKey ? t(labelKey) : label;
  }

  const detail = document.getElementById("canary-detail");
  if (!detail) return;
  if (!result) { detail.hidden = true; return; }
  detail.hidden = false;
  const torIps = Array.isArray(result.tor_ips) ? result.tor_ips : [];
  const revealIps = document.getElementById("canary-reveal-ips");
  const reveal = !!(revealIps && revealIps.checked);
  const setText = (id, text) => {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  };
  setText("canary-host", result.host || "—");
  setText("canary-tor", renderIpList(torIps, reveal));
  setText(
    "canary-system",
    reveal ? (result.system_ip || "—") : maskIp(result.system_ip),
  );
  setText("canary-ptr", result.system_ptr || "—");
  setText(
    "canary-verdict",
    verdictKey ? t(verdictKey, verdictArgs) : verdict,
  );
  const rawError = result.error ||
    (result.errors && result.errors.length ? result.errors.join("; ") : "");
  const guidance = explainCanaryError(rawError);
  setText(
    "canary-error",
    guidance ? `${rawError}  ->  ${guidance}` : (rawError || "—"),
  );
}

function countItems(value) {
  return Array.isArray(value) ? value.length : 0;
}

function redactErrorForLog(error) {
  if (typeof error !== "string" || !error) return null;
  const text = error;
  if (/refused/i.test(text)) return "refused";
  if (/timeout/i.test(text)) return "timeout";
  if (/network unreachable|ENETUNREACH/i.test(text)) return "network-unreachable";
  if (/dns/i.test(text)) return "dns-error";
  if (/invalid/i.test(text)) return "invalid-input";
  return "error";
}

function redactSocksForLog(socks) {
  if (!socks || typeof socks !== "object") return null;
  return {
    ok: !!socks.ok,
    verified: !!socks.verified,
    source: typeof socks.source === "string" && socks.source ? socks.source : null,
    host: socks.host === "127.0.0.1" || socks.host === "localhost" || socks.host === "::1"
      ? socks.host
      : (typeof socks.host === "string" && socks.host ? "<configured>" : null),
    port: Number.isInteger(socks.port) ? socks.port : null,
    probes_count: countItems(socks.probes),
    error: redactErrorForLog(socks.error),
  };
}

function redactSelfTestForLog(selfTest) {
  if (!selfTest || typeof selfTest !== "object") return null;
  return {
    // F-184: redact canary anchor host. Even though the pool is public
    // (check.torproject.org, www.torproject.org, etc. — F-087), the
    // raw value in a screenshot/support-log gives an observer "this
    // user ran an addon-driven canary against the Tor checker", an
    // OnionBird-specific fingerprint. README claim 'logs redact IPs,
    // hostnames, and secrets' applies to all hostnames, not just
    // private ones — strict reading.
    host: typeof selfTest.host === "string" && selfTest.host
      ? "<canary-anchor>"
      : null,
    socks_host: selfTest.socks_host === "127.0.0.1" ||
        selfTest.socks_host === "localhost" ||
        selfTest.socks_host === "::1"
      ? selfTest.socks_host
      : (typeof selfTest.socks_host === "string" && selfTest.socks_host
        ? "<configured>"
        : null),
    socks_port: Number.isInteger(selfTest.socks_port) ? selfTest.socks_port : null,
    tor_ip_count: countItems(selfTest.tor_ips),
    system_ip: maskIp(selfTest.system_ip),
    system_ip_count: countItems(selfTest.system_ips),
    system_ptr_present: !!selfTest.system_ptr,
    leak_detected: !!selfTest.leak_detected,
    errors_count: countItems(selfTest.errors),
    error: redactErrorForLog(selfTest.error),
  };
}

function summarizeListForLog(result) {
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

function redactResultForLog(result) {
  if (!result || typeof result !== "object") return result;
  return {
    ok: !!result.ok,
    reason: typeof result.reason === "string" && result.reason ? result.reason : null,
    error: redactErrorForLog(result.error),
    socks: redactSocksForLog(result.socks),
    selfTest: redactSelfTestForLog(result.selfTest),
    prefs: summarizeListForLog(result.prefs),
    failClosed: summarizeListForLog(result.failClosed),
    smtp: summarizeListForLog(result.smtp),
    identities: summarizeListForLog(result.identities),
    logins: summarizeListForLog(result.logins),
  };
}

// Exposed for tests that re-implement the page in a Node-like env.
if (typeof module !== "undefined") {
  module.exports = {
    classifyCanary,
    classifyTorTest,
    describeSocksSource,
    explainCanaryError,
    formatTorEndpoint,
    formatTorTestProbes,
    isValidMessageIdFqdn,
    maskIp,
    redactErrorForLog,
    redactResultForLog,
    redactSocksForLog,
    redactSelfTestForLog,
    renderIpList,
    summarizeListForLog,
  };
}

if (typeof document !== "undefined") (async () => {
  applyI18n();
  applyTheme(loadStoredTheme());

  const status = document.getElementById("status");
  const log = document.getElementById("log");
  const enable = document.getElementById("enable");
  const disable = document.getElementById("disable");
  const scrubLogins = document.getElementById("scrub-logins");
  const torTestBtn = document.getElementById("run-tor-test");
  const torTestSpinner = document.getElementById("tor-test-spinner");
  const runBtn = document.getElementById("run-self-test");
  const spinner = document.getElementById("canary-spinner");
  const canaryHostInput = document.getElementById("canary-host-input");
  const revealIps = document.getElementById("canary-reveal-ips");
  const themeControls = document.getElementById("theme-controls");
  const helpModeControls = document.getElementById("help-mode-controls");
  let hardeningActive = false;
  let lastCanaryResult = null;

  async function refreshStatus() {
    const s = await browser.runtime.sendMessage({ cmd: "get-status" });
    if (s && s.error) throw new Error(s.error);
    hardeningActive = !!(s && s.hardeningActive);
    // U-080: read the leak verdict from storage and surface non-
    // clean states alongside the ACTIVE / inactive label. Without
    // this the user has no visual cue that sends are silently
    // being cancelled by the compose.onBeforeSend gate (F-043).
    let verdictSuffix = "";
    try {
      const got = await browser.storage.local.get("onionbird.leakVerdict");
      const leakVerdict = got["onionbird.leakVerdict"];
      if (hardeningActive && leakVerdict && leakVerdict.state) {
        const st = String(leakVerdict.state);
        if (st !== "clean") {
          // U-079 sentinel surfaces here too: the manifest-load-time
          // sentinel state "compose_api_unavailable" tells the user
          // the addon-layer block is silently disabled.
          verdictSuffix = " — verdict: " + st;
        }
      }
    } catch (e) {
      // Storage error reading verdict — don't fail the status
      // refresh; the listener (F-072) handles fail-closed on its
      // side.
    }
    status.textContent = t("statusText", [
      s && s.apiVersion ? s.apiVersion : "?",
      s && s.version ? s.version : "?",
      hardeningActive ? t("statusActive") : t("statusInactive"),
    ]) + verdictSuffix;
    return s;
  }

  try {
    await refreshStatus();
  } catch (e) {
    status.textContent = t("errorWithMessage", e.message);
  }

  enable.addEventListener("click", async () => {
    log.textContent = t("logApplyingHardening") + "\n";
    enable.disabled = true;
    disable.disabled = true;
    try {
      const r = await browser.runtime.sendMessage({ cmd: "enable-hardening" });
      // F-179: `r` can be undefined if no background listener responded
      // (e.g. the service worker was unloaded mid-dispatch). `r.ok` then
      // throws TypeError before the catch could surface the underlying
      // problem. Null-guard explicitly.
      log.textContent += `${r && r.ok ? t("logDone") : t("logWarnings")}: ` +
        `${JSON.stringify(redactResultForLog(r))}\n`;
      await refreshStatus();
    } catch (e) {
      log.textContent += `${t("errorLabel")}: ${e.message}\n`;
    } finally {
      enable.disabled = false;
      disable.disabled = false;
    }
  });

  disable.addEventListener("click", async () => {
    if (!confirm(t("disableConfirm"))) return;
    log.textContent = t("logRestoringPrefs") + "\n";
    enable.disabled = true;
    disable.disabled = true;
    try {
      const r = await browser.runtime.sendMessage({
        cmd: "disable-hardening",
        scrubLogins: !!(scrubLogins && scrubLogins.checked),
      });
      log.textContent += `${r && r.ok ? t("logDone") : t("logWarnings")}: ` +
        `${JSON.stringify(redactResultForLog(r))}\n`;
      await refreshStatus();
    } catch (e) {
      log.textContent += `${t("errorLabel")}: ${e.message}\n`;
    } finally {
      enable.disabled = false;
      disable.disabled = false;
    }
  });

  async function runTorTest() {
    torTestSpinner.hidden = false;
    torTestBtn.disabled = true;
    renderTorTest(null);
    try {
      const r = await browser.runtime.sendMessage({ cmd: "run-tor-test" });
      renderTorTest(r);
    } catch (e) {
      // F-179: on dispatch failure no probe was actually attempted, so
      // we must NOT fabricate a `host: "example.com"` in the rendered
      // result — the UI then shows "example.com" as the host that was
      // tested, which is a lie. Pass null/empty and let renderTorTest
      // surface "—" for the host field.
      renderTorTest({
        ok: false,
        host: null,
        socks: null,
        probes: [],
        error: t("torTestError", e.message),
      });
    } finally {
      torTestSpinner.hidden = true;
      torTestBtn.disabled = false;
    }
  }

  torTestBtn.addEventListener("click", runTorTest);

  async function runSelfTest() {
    spinner.hidden = false;
    runBtn.disabled = true;
    try {
      const r = await browser.runtime.sendMessage({
        cmd: "run-self-test",
        host: (canaryHostInput.value || "").trim() || "check.torproject.org",
      });
      lastCanaryResult = r && r.error && r.ok === false ? { error: r.error } : r;
      renderCanary(lastCanaryResult);
    } catch (e) {
      lastCanaryResult = { error: e.message };
      renderCanary(lastCanaryResult);
    } finally {
      spinner.hidden = true;
      runBtn.disabled = false;
    }
  }

  runBtn.addEventListener("click", runSelfTest);
  if (revealIps) {
    revealIps.addEventListener("change", () => {
      if (lastCanaryResult) renderCanary(lastCanaryResult);
    });
  }

  // Auto-run only once hardening is active; otherwise a fresh profile gets
  // a noisy Tor-port error before the user intentionally enables anything.
  if (hardeningActive) runSelfTest();

  // --- Message-ID FQDN strategy ---
  const fqdnMode = document.getElementById("fqdn-mode");
  const fqdnCustom = document.getElementById("fqdn-custom");
  const fqdnSave = document.getElementById("fqdn-save");
  const fqdnStatus = document.getElementById("fqdn-status");

  async function loadFqdnPrefs() {
    try {
      const r = await browser.runtime.sendMessage({ cmd: "get-message-id-fqdn" });
      if (r && r.mode) fqdnMode.value = r.mode;
      if (r && r.custom) fqdnCustom.value = r.custom;
      fqdnCustom.style.display = fqdnMode.value === "custom" ? "inline-block" : "none";
    } catch (e) {
      fqdnStatus.textContent = t("readPrefsFailed", e.message);
    }
  }

  fqdnMode.addEventListener("change", () => {
    fqdnCustom.style.display = fqdnMode.value === "custom" ? "inline-block" : "none";
  });

  fqdnSave.addEventListener("click", async () => {
    fqdnStatus.textContent = t("savingLabel");
    try {
      const v = (fqdnCustom.value || "").trim();
      if (fqdnMode.value === "custom") {
        if (!isValidMessageIdFqdn(v)) {
          fqdnStatus.textContent = t("fqdnInvalid");
          return;
        }
      }
      const r = await browser.runtime.sendMessage({
        cmd: "save-message-id-fqdn",
        mode: fqdnMode.value,
        custom: v,
      });
      if (!r || r.ok === false) {
        throw new Error((r && r.error) || "unknown");
      }
      const identities = r.identities || { mode: r.mode, applied: [] };
      fqdnStatus.textContent = t("fqdnSaved", [
        identities.mode || r.mode,
        String(Array.isArray(identities.applied) ? identities.applied.length : 0),
      ]);
    } catch (e) {
      fqdnStatus.textContent = t("saveFailed", e.message);
    }
  });

  // --- F-168: SOCKS endpoint override ---
  const socksHostInput = document.getElementById("socks-override-host");
  const socksPortInput = document.getElementById("socks-override-port");
  const socksSaveBtn = document.getElementById("socks-override-save");
  const socksResetBtn = document.getElementById("socks-override-reset");
  const socksTestBtn = document.getElementById("socks-override-test");
  const socksStatus = document.getElementById("socks-override-status");

  // F-177 v2: partial-edit UX. The HTML placeholders ("127.0.0.1" /
  // "9050") double as defaults: if the user types only one field, the
  // OTHER's placeholder is the implicit value they expect ("wenn ich
  // nur die ip anpasse sollte der port schon drin stehen und
  // andersherum"). Both fields empty stays an error — we MUST NOT
  // silently pin 127.0.0.1:9050 on a no-input Save, because that
  // would convert "fall back to the 9050→9150 auto-detect ladder"
  // into "pin port 9050", silently breaking users on Tor-Browser-
  // bundle (which lives on 9150). The previous F-177 v1 (pre-fill
  // .value in loadSocksOverride) regressed exactly this on the
  // Reset+Save gesture.
  function resolveSocksInputsWithPlaceholderFallback() {
    const rawHost = (socksHostInput.value || "").trim();
    const rawPortStr = (socksPortInput.value || "").trim();
    let host = rawHost;
    let portStr = rawPortStr;
    if (rawHost && !rawPortStr) {
      portStr = (socksPortInput.placeholder || "").trim();
    } else if (!rawHost && rawPortStr) {
      host = (socksHostInput.placeholder || "").trim();
    }
    const port = parseInt(portStr, 10);
    return { host, port };
  }

  async function loadSocksOverride() {
    try {
      // F-168 S-4: route through runtime.sendMessage instead of calling
      // browser.onionbird.* directly. Consistent with every other UI
      // handler in this file (Tor test, self-test, FQDN save, etc.).
      const ov = await browser.runtime.sendMessage({ cmd: "get-socks-override" });
      if (ov && ov.host) socksHostInput.value = ov.host;
      if (ov && ov.port) socksPortInput.value = String(ov.port);
      // User-Override + Warnung: if TB's existing network.proxy.socks
      // pref differs from what we have stored, surface a hint so the
      // user knows their saved override will replace it on next enable.
      // The two pref lookups stay on the experiment API surface via a
      // small helper command — they're read-only and there's no other
      // handler in the dispatch table that returns generic prefs.
      try {
        const status = await browser.runtime.sendMessage({ cmd: "get-status" });
        // get-status doesn't carry the proxy prefs; for now fall back
        // to a direct getPref via the existing browser.onionbird.getPref
        // path which is already in the schema. This is the one remaining
        // direct-call exception and is acceptable for a read-only
        // best-effort warning. Refactor candidate for a later S-4 v2.
        const tbHost = await browser.onionbird.getPref("network.proxy.socks");
        const tbPort = await browser.onionbird.getPref("network.proxy.socks_port");
        if (ov && ov.host && tbHost && (tbHost !== ov.host || tbPort !== ov.port)) {
          socksStatus.textContent = t("socksOverrideTbPrefWarning", [
            `${tbHost}:${tbPort}`,
            `${ov.host}:${ov.port}`,
          ]);
        }
      } catch (e) { /* warning is best-effort */ }
    } catch (e) {
      socksStatus.textContent = t("readPrefsFailed", e.message);
    }
  }

  async function saveSocksOverride() {
    const { host, port } = resolveSocksInputsWithPlaceholderFallback();
    socksStatus.textContent = t("savingLabel");
    if (!host) {
      socksStatus.textContent = t("socksOverrideStatusInvalidHost");
      return;
    }
    if (!Number.isFinite(port) || port < 1 || port > 65535) {
      socksStatus.textContent = t("socksOverrideStatusInvalidPort");
      return;
    }
    // Reflect the resolved (post-fallback) values back to the inputs so
    // the user sees exactly what got persisted — especially when a
    // placeholder fallback filled in a field they left blank.
    socksHostInput.value = host;
    socksPortInput.value = String(port);
    // F-170: atomic write of the (host, port) pair via the dedicated
    // pair API. The previous two-step `setSocksOverride("host", …)`
    // then `setSocksOverride("port", …)` flow could leave a half-set
    // state (host persisted, port cleared by the empty-sentinel path)
    // which `getSocksOverride` reads as null — the override would
    // silently dead-state and the user would see "OK" while the
    // addon ignored their settings. setSocksOverridePair validates
    // both first, writes both in the same parent-process tick, or
    // writes neither on rejection.
    // F-168 S-4: dispatched via runtime.sendMessage so the experiment
    // API stays concentrated in background.js.
    const r = await browser.runtime.sendMessage({
      cmd: "save-socks-override",
      host,
      port,
    });
    if (!r || !r.ok) {
      const key = r && r.reason === "invalid-port"
        ? "socksOverrideStatusInvalidPort"
        : "socksOverrideStatusInvalidHost";
      socksStatus.textContent = t(key);
      return;
    }
    socksStatus.textContent = t("socksOverrideStatusOk");
  }

  async function resetSocksOverride() {
    // F-168 S-4: clear via dispatched runtime message; background.js
    // owns the experiment API surface.
    await browser.runtime.sendMessage({ cmd: "clear-socks-override" });
    socksHostInput.value = "";
    socksPortInput.value = "";
    // F-171: distinct status for Reset (was reusing socksOverrideStatusOk
    // which reads as "saved" — contradictory after a clear gesture).
    socksStatus.textContent = t("socksOverrideStatusReset");
    // F-168 review S-5: re-run loadSocksOverride to refresh the
    // TB-pref-drift warning. Without this, a "TB has X configured,
    // your override Y will replace it" warning that was visible at
    // load time stays on screen even after Reset has cleared the
    // override — misleading the user into thinking the warning still
    // applies. loadSocksOverride sees no override now and either
    // surfaces a different state or stays clean.
    loadSocksOverride();
  }

  async function testSocksOverride() {
    // Probe whatever's currently in the inputs (NOT the saved value), so
    // the user can test a candidate before committing. Apply the same
    // placeholder fallback as Save so partial edits ("I typed only the
    // host, but the example port is shown") behave consistently.
    const { host, port } = resolveSocksInputsWithPlaceholderFallback();
    // F-176: mirror saveSocksOverride's per-field validation. Pre-fix
    // code combined `!host || !isFinite(port)` and routed both into
    // InvalidHost, so a valid-host-but-bad-port user saw the wrong
    // status message and assumed the Test button was non-functional.
    if (!host) {
      socksStatus.textContent = t("socksOverrideStatusInvalidHost");
      return;
    }
    if (!Number.isFinite(port) || port < 1 || port > 65535) {
      socksStatus.textContent = t("socksOverrideStatusInvalidPort");
      return;
    }
    // Reflect resolved values so the user sees what's about to be probed.
    socksHostInput.value = host;
    socksPortInput.value = String(port);
    socksStatus.textContent = t("torTestRunning");
    try {
      // F-168 I-1: userProbe=true tells the API this is an explicit
      // user-driven Test (not a background auto-detect), so it bypasses
      // the currentSocksEndpointMatches gate that would otherwise reject
      // any IP literal not already in network.proxy.socks. Without this,
      // testing a Whonix Gateway IP before Save was structurally impossible.
      // F-168 S-4: dispatched via runtime.sendMessage — background.js's
      // probe-socks-override case forwards { userProbe: true } onward.
      const probe = await browser.runtime.sendMessage({
        cmd: "probe-socks-override",
        host,
        port,
        target: "check.torproject.org",
      });
      socksStatus.textContent = probe && probe.ok
        ? t("socksOverrideStatusOk")
        : t("torTestError",probe && probe.error ? probe.error : "no reachable SOCKS proxy");
    } catch (e) {
      socksStatus.textContent = t("torTestError",e.message || String(e));
    }
  }

  if (socksSaveBtn) socksSaveBtn.addEventListener("click", saveSocksOverride);
  if (socksResetBtn) socksResetBtn.addEventListener("click", resetSocksOverride);
  if (socksTestBtn) socksTestBtn.addEventListener("click", testSocksOverride);
  loadSocksOverride();

  if (themeControls) {
    themeControls.addEventListener("click", (event) => {
      const button = event.target && event.target.closest
        ? event.target.closest("[data-theme-choice]")
        : null;
      if (!button) return;
      storeTheme(button.dataset.themeChoice);
    });
  }

  let helpMode = "tldr";
  try {
    helpMode = normalizeHelpMode(localStorage.getItem(HELP_MODE_STORAGE_KEY));
  } catch (e) {}
  renderHelp(helpMode);
  if (helpModeControls) {
    helpModeControls.addEventListener("click", (event) => {
      const button = event.target && event.target.closest
        ? event.target.closest("[data-help-mode]")
        : null;
      if (!button) return;
      renderHelp(button.dataset.helpMode);
    });
  }

  loadFqdnPrefs();
})();
