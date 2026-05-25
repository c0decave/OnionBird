"""Deterministic fuzz tests for app-facing input surfaces.

These are intentionally small, seed-stable fuzzers. They are not a replacement
for long-running coverage-guided fuzzing, but they keep the sharp edges we have
already found from drifting back in: UI redaction, Canary classification, and
the companion installer parsing attacker-influenced prefs.js values.
"""

from __future__ import annotations

import random
import re
import string
import subprocess
from pathlib import Path

import pytest
from helpers.tb_client import TBClient

SCRIPT = Path("/scripts/install-user-js.sh")


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


def _read(path: str) -> str:
    with open(path) as f:
        return f.read()


def test_options_js_fuzzes_redaction_and_canary_classification(tb: TBClient) -> None:
    """Run options.js itself inside Thunderbird's JS engine with random data."""
    options_js = _read("/addon/ui/options.js")
    result = tb.exec_chrome(
        r"""
        const [source] = arguments;
        const module = { exports: {} };
        const browser = {
          i18n: {
            getMessage(key) { return key; },
            getUILanguage() { return "en-US"; },
          },
        };
        const load = new Function(
          "module", "browser", "document", "localStorage", "confirm",
          `${source}\nreturn module.exports;`
        );
        const app = load(module, browser, undefined, undefined, undefined);

        let seed = 0x51f15e;
        function rnd() {
          seed = (seed * 1664525 + 1013904223) >>> 0;
          return seed / 4294967296;
        }
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" +
          "0123456789-_.:[]@/\\\\\\u0000\\u0001";
        function rstr(maxLen) {
          const len = Math.floor(rnd() * maxLen);
          let s = "";
          for (let i = 0; i < len; i++) {
            s += chars[Math.floor(rnd() * chars.length)];
          }
          return s;
        }
        function rval(depth = 0) {
          const pick = Math.floor(rnd() * 9);
          if (pick === 0) return null;
          if (pick === 1) return undefined;
          if (pick === 2) return rnd() < 0.5;
          if (pick === 3) return Math.floor(rnd() * 1000000) - 500000;
          if (pick === 4) return rstr(320);
          if (pick === 5 && depth < 2) {
            const a = [];
            for (let i = 0; i < Math.floor(rnd() * 8); i++) a.push(rval(depth + 1));
            return a;
          }
          if (depth < 2) {
            const o = {};
            for (let i = 0; i < Math.floor(rnd() * 8); i++) o[rstr(20)] = rval(depth + 1);
            return o;
          }
          return rstr(64);
        }

        const levels = new Set(["ok", "warn", "leak", "error", "unknown"]);
        const torLevels = new Set(["ok", "error", "unknown"]);
        function assertJsonish(value, path = "value") {
          if (value === undefined || typeof value === "function" ||
              typeof value === "symbol") {
            throw new Error(`${path} is not JSON-shaped`);
          }
          if (typeof value === "number" && !Number.isFinite(value)) {
            throw new Error(`${path} is not finite`);
          }
          if (!value || typeof value !== "object") return;
          if (Array.isArray(value)) {
            for (let i = 0; i < value.length; i++) {
              assertJsonish(value[i], `${path}[${i}]`);
            }
            return;
          }
          for (const [k, v] of Object.entries(value)) {
            assertJsonish(v, `${path}.${k}`);
          }
        }
        if (app.maskIp("smtp.secret.example") !== "<non-ip>") {
          throw new Error("non-IP values must not be displayed by default");
        }
        if (app.renderIpList(["smtp.secret.example"], false) !== "<non-ip>") {
          throw new Error("non-IP list entries must be redacted unless reveal=true");
        }
        if (app.renderIpList(["smtp.secret.example"], true) !== "smtp.secret.example") {
          throw new Error("explicit reveal should still reveal raw values");
        }

        for (let i = 0; i < 4000; i++) {
          const value = rval();
          const fqdn = app.isValidMessageIdFqdn(value);
          if (typeof fqdn !== "boolean") {
            throw new Error("FQDN validator returned non-boolean");
          }

          const masked = app.maskIp(rval());
          if (typeof masked !== "string") throw new Error("maskIp returned non-string");

          const rendered = app.renderIpList(rval(), rnd() < 0.5);
          if (typeof rendered !== "string") {
            throw new Error("renderIpList returned non-string");
          }

          const verdict = app.classifyCanary(rval());
          if (!verdict || !levels.has(verdict.level)) {
            throw new Error(`bad canary level: ${JSON.stringify(verdict)}`);
          }
          assertJsonish(verdict, "canary verdict");

          const torVerdict = app.classifyTorTest(value);
          if (!torVerdict || !torLevels.has(torVerdict.level)) {
            throw new Error(`bad Tor-test level: ${JSON.stringify(torVerdict)}`);
          }
          if (Array.isArray(torVerdict.statusArgs) &&
              torVerdict.statusArgs.some((arg) => typeof arg !== "string")) {
            throw new Error("Tor-test statusArgs leaked non-strings");
          }
          assertJsonish(torVerdict, "Tor-test verdict");

          for (const formatted of [
            app.describeSocksSource(value),
            app.explainCanaryError(value) || "",
            app.formatTorEndpoint(value),
            app.formatTorTestProbes(value),
            app.formatTorTestProbes([value, {
              socks_host: rval(),
              socks_port: rval(),
              source: rval(),
              ok: rval(),
              error: rval(),
            }]),
          ]) {
            if (typeof formatted !== "string") {
              throw new Error("formatter returned non-string output");
            }
          }

          const redacted = app.redactSelfTestForLog({
            host: rstr(128),
            socks_host: rstr(128),
            socks_port: Math.floor(rnd() * 70000),
            tor_ips: [rstr(128), "1.2.3.4"],
            system_ip: rstr(128),
            system_ips: [rstr(128)],
            system_ptr: rstr(128),
            errors: [rstr(128)],
            leak_detected: rnd() < 0.5,
            error: rstr(128),
          });
          if (redacted.system_ip === "smtp.secret.example") {
            throw new Error("redaction leaked system_ip");
          }
          if (typeof redacted.system_ptr_present !== "boolean") {
            throw new Error("PTR redaction should be presence-only");
          }
          assertJsonish(redacted, "redacted self-test");

          assertJsonish(app.redactSocksForLog({
            ok: value,
            verified: value,
            source: rval(),
            host: rval(),
            port: rval(),
            probes: value,
            error: rval(),
          }), "redacted socks");
          assertJsonish(app.redactResultForLog({
            ok: value,
            reason: rval(),
            error: rval(),
            socks: rval(),
            selfTest: rval(),
            prefs: rval(),
            failClosed: rval(),
            smtp: rval(),
            identities: rval(),
            logins: rval(),
          }), "redacted result");
        }
        return { ok: true, iterations: 4000 };
        """,
        args=[options_js],
    )
    assert result == {"ok": True, "iterations": 4000}


def test_background_js_fuzzes_runtime_helpers_and_fail_closed_defaults(
    tb: TBClient,
) -> None:
    """Fuzz background.js helpers that normalize runtime-facing input."""
    background_js = _read("/addon/background.js")
    result = tb.exec_chrome(
        r"""
        const [source] = arguments;
        const browser = {
          runtime: {
            id: "onionbird@undisclose.de",
            getManifest() { return { version: "0.1.0" }; },
            onMessage: { addListener() {} },
            onInstalled: { addListener() {} },
          },
          storage: {
            local: {
              async get() { return {}; },
              async set() {},
              async remove() {},
            },
          },
          onionbird: {
            async getApiVersion() { return "0.1.0"; },
            async setPref() { throw new Error("setPref should not be called"); },
          },
        };
        const load = new Function("browser", `${source}
          return {
            coreFailClosedPrefs,
            isAllowedSnapshotPrefName,
            isValidIpv6Literal,
            isValidSnapshotValue,
            isValidSocksHost,
            maskIpForLog,
            normalizeProbeHost,
            normalizeSocksHost,
            normalizeSocksPort,
            parseStrictIpv4Address,
            publicSocksProbe,
            safeConfiguredSocksHostOrDefault,
            safeRuntimeCommand,
            saveMessageIdFqdnPrefs,
            summarizeHardeningResultForLog,
            snapshotValidationError,
            summarizeSelfTestForLog,
            summarizeSocksForLog,
            summarizeSocksProbeForLog,
          };`);
        const app = load(browser);
        const throws = (fn) => {
          try { fn(); return false; } catch (e) { return true; }
        };
        function assertJsonish(value, path = "value") {
          if (value === undefined || typeof value === "function" ||
              typeof value === "symbol") {
            throw new Error(`${path} is not JSON-shaped`);
          }
          if (typeof value === "number" && !Number.isFinite(value)) {
            throw new Error(`${path} is not finite`);
          }
          if (!value || typeof value !== "object") return;
          if (Array.isArray(value)) {
            for (let i = 0; i < value.length; i++) {
              assertJsonish(value[i], `${path}[${i}]`);
            }
            return;
          }
          for (const [k, v] of Object.entries(value)) {
            assertJsonish(v, `${path}.${k}`);
          }
        }

        if (app.normalizeSocksPort(" 9050 ") !== 9050) {
          throw new Error("string SOCKS port should normalize");
        }
        if (app.normalizeProbeHost(undefined, "Check.Torproject.Org.") !==
            "check.torproject.org") {
          throw new Error("probe host fallback should normalize");
        }
        for (const bad of [["example.com"], { toString() { return "example.com"; } }]) {
          if (!throws(() => app.normalizeProbeHost(bad, "check.torproject.org"))) {
            throw new Error("non-string probe host was coerced");
          }
        }
        const customArray = await app.saveMessageIdFqdnPrefs({
          mode: "custom",
          custom: ["valid.example"],
        });
        if (!customArray || customArray.ok !== false) {
          throw new Error("non-string custom Message-ID FQDN was coerced");
        }
        for (const bad of [true, false, [9050], { toString() { return "9050"; } }]) {
          if (!throws(() => app.normalizeSocksPort(bad))) {
            throw new Error(`coerced invalid SOCKS port: ${String(bad)}`);
          }
        }
        if (app.normalizeSocksHost(" 127.0.0.1 ") !== "127.0.0.1") {
          throw new Error("string SOCKS host should normalize");
        }
        for (const bad of [true, ["127.0.0.1"], { toString() { return "127.0.0.1"; } }]) {
          if (app.isValidSocksHost(bad)) {
            throw new Error("non-string SOCKS host validated");
          }
          if (!throws(() => app.normalizeSocksHost(bad))) {
            throw new Error("non-string SOCKS host normalized");
          }
        }
        if (app.safeConfiguredSocksHostOrDefault(["10.0.0.1"]) !== "127.0.0.1") {
          throw new Error("non-string safe SOCKS host should fall back");
        }
        const failClosed = app.coreFailClosedPrefs({
          host: ["10.0.0.1"],
          port: [9050],
        });
        const pref = Object.fromEntries(failClosed.map(p => [p.name, p.value]));
        if (pref["network.proxy.socks"] !== "127.0.0.1" ||
            pref["network.proxy.socks_port"] !== 9050) {
          throw new Error("fail-closed prefs did not fall back to local Tor defaults");
        }

        let seed = 0x6a09e667;
        function rnd() {
          seed = (seed * 1664525 + 1013904223) >>> 0;
          return seed / 4294967296;
        }
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" +
          "0123456789-_.:[]@/\\\\\\u0000\\u0001<>{}();";
        function rstr(maxLen) {
          const len = Math.floor(rnd() * maxLen);
          let s = "";
          for (let i = 0; i < len; i++) {
            s += chars[Math.floor(rnd() * chars.length)];
          }
          return s;
        }
        function rval(depth = 0) {
          const pick = Math.floor(rnd() * 10);
          if (pick === 0) return null;
          if (pick === 1) return undefined;
          if (pick === 2) return rnd() < 0.5;
          if (pick === 3) return Math.floor(rnd() * 200000) - 100000;
          if (pick === 4) return rstr(360);
          if (pick === 5 && depth < 2) {
            const a = [];
            for (let i = 0; i < Math.floor(rnd() * 7); i++) a.push(rval(depth + 1));
            return a;
          }
          if (depth < 2) {
            const o = {};
            for (let i = 0; i < Math.floor(rnd() * 7); i++) o[rstr(40)] = rval(depth + 1);
            return o;
          }
          return rstr(80);
        }

        for (let i = 0; i < 5000; i++) {
          const value = rval();
          const cmd = app.safeRuntimeCommand(value);
          if (typeof cmd !== "string" || cmd.length > 64 || /[^\w:-]/.test(cmd)) {
            throw new Error(`unsafe command summary: ${cmd}`);
          }

          const masked = app.maskIpForLog(value);
          if (masked !== null && typeof masked !== "string") {
            throw new Error("maskIpForLog returned non-string");
          }

          const snapshotVerdict = app.snapshotValidationError(value);
          if (snapshotVerdict !== null && typeof snapshotVerdict !== "string") {
            throw new Error("snapshotValidationError returned malformed verdict");
          }

          if (value === null || value === undefined || value === "") {
            if (app.normalizeProbeHost(value, "check.torproject.org") !==
                "check.torproject.org") {
              throw new Error("empty probe host did not fall back");
            }
          } else if (typeof value !== "string") {
            if (!throws(() => app.normalizeProbeHost(value, "check.torproject.org"))) {
              throw new Error("non-string probe host normalized");
            }
          }

          const selfSummary = app.summarizeSelfTestForLog({
            host: rstr(120),
            socks_host: rstr(120),
            socks_port: value,
            tor_ips: [rstr(120), "1.2.3.4"],
            system_ip: rstr(120),
            system_ips: [rstr(120)],
            system_ptr: rstr(120),
            errors: [rstr(120)],
            leak_detected: rnd() < 0.5,
            error: rstr(120),
          });
          if (!selfSummary || typeof selfSummary.system_ptr_present !== "boolean") {
            throw new Error("bad self-test log summary");
          }
          assertJsonish(selfSummary, "self-test summary");

          const socksSummary = app.summarizeSocksForLog({
            ok: value,
            verified: value,
            source: rstr(40),
            host: rstr(120),
            port: value,
            probes: [value],
            error: rstr(120),
          });
          if (!socksSummary || typeof socksSummary.ok !== "boolean") {
            throw new Error("bad SOCKS log summary");
          }
          assertJsonish(socksSummary, "SOCKS summary");

          assertJsonish(app.summarizeSocksProbeForLog({
            source: rval(),
            socks_host: rval(),
            socks_port: rval(),
            host: rval(),
            ok: rval(),
            error: rval(),
          }), "SOCKS probe summary");
          assertJsonish(app.publicSocksProbe({
            source: rval(),
            socks_host: rval(),
            socks_port: rval(),
            host: rval(),
            ok: rval(),
            error: rval(),
          }), "public SOCKS probe");
          assertJsonish(app.summarizeHardeningResultForLog({
            ok: value,
            reason: rval(),
            socks: rval(),
            selfTest: rval(),
            prefs: rval(),
            failClosed: rval(),
            smtp: rval(),
            identities: rval(),
            logins: rval(),
          }), "hardening summary");
        }
        return { ok: true, iterations: 5000 };
        """,
        args=[background_js],
    )
    assert result == {"ok": True, "iterations": 5000}


def test_background_js_fuzzes_runtime_message_inputs_and_outputs(
    tb: TBClient,
) -> None:
    """Fuzz the runtime message listener's command input and public outputs."""
    background_js = _read("/addon/background.js")
    result = tb.exec_chrome(
        r"""
        const [source] = arguments;
        const store = {};
        function event() {
          return {
            listener: null,
            addListener(fn) { this.listener = fn; },
            removeListener(fn) { if (this.listener === fn) this.listener = null; },
          };
        }
        const browser = {
          runtime: {
            id: "onionbird@undisclose.de",
            getManifest() { return { version: "0.1.0" }; },
            onMessage: event(),
            onInstalled: event(),
          },
          accounts: {
            onCreated: event(),
            onUpdated: event(),
            onDeleted: event(),
          },
          storage: {
            local: {
              async get(key) {
                if (typeof key === "string") return { [key]: store[key] };
                if (Array.isArray(key)) {
                  const out = {};
                  for (const k of key) out[k] = store[k];
                  return out;
                }
                return { ...store };
              },
              async set(values) { Object.assign(store, values || {}); },
              async remove(key) { delete store[key]; },
            },
          },
          onionbird: {
            async getApiVersion() { return "0.1.0"; },
            async getPref(name) {
              if (name === "network.proxy.socks") return "127.0.0.1";
              if (name === "network.proxy.socks_port") return 9050;
              return null;
            },
            async setPref() { return true; },
            async snapshotPrefs(names) {
              const snap = {};
              for (const name of Array.isArray(names) ? names : []) snap[name] = null;
              return snap;
            },
            async restorePrefs(snapshot) {
              return { restored: Object.keys(snapshot || {}), failed: [] };
            },
            async applyPrefs(prefs) {
              return {
                applied: (Array.isArray(prefs) ? prefs : []).map((p) => p.name),
                failed: [],
                rolled_back: [],
                rollback_failed: [],
              };
            },
            async getSmtpHardeningPrefNames() { return { names: [], skipped: [], failed: [] }; },
            async getIdentityHardeningPrefNames() { return { names: [], failed: [] }; },
            async applyHardeningToAllSmtpServers() {
              return { applied: [], failed: [], skipped: [] };
            },
            async applyHardeningToAllIdentities() {
              return { applied: [], failed: [], mode: "from_domain" };
            },
            async clearHardeningFromAllSmtpServers() {
              return { cleared: [], failed: [], skipped: [] };
            },
            async clearHardeningFromAllIdentities() {
              return { cleared: [], failed: [] };
            },
            async auditSavedLoginsForTorServers() {
              return { origins: [], count: 0, logins: [], failed: [] };
            },
            async removeSavedLoginsForTorServers() {
              return { origins: [], removed: [], failed: [] };
            },
            async clearDnsCache() { return { dns: true, smtp_servers_closed: 0 }; },
            async probeSocks(socksHost, socksPort, host) {
              return {
                ok: true,
                socks_host: socksHost,
                socks_port: socksPort,
                host,
                ip: "127.0.0.1",
                error: null,
              };
            },
            async runSelfTest(host, options) {
              return {
                host,
                socks_host: options && options.socksHost || "127.0.0.1",
                socks_port: options && options.socksPort || 9050,
                tor_ips: ["127.0.0.1"],
                system_ip: "127.0.0.1",
                system_ips: ["127.0.0.1"],
                system_ptr: null,
                errors: [],
                leak_detected: false,
                error: null,
              };
            },
          },
        };
        const load = new Function("browser", `${source}
          return { stopHardeningMonitors };`);
        const app = load(browser);
        const listener = browser.runtime.onMessage.listener;
        if (typeof listener !== "function") {
          throw new Error("runtime listener was not registered");
        }

        function assertJsonish(value, path = "value") {
          if (value === undefined) return;
          if (typeof value === "function" || typeof value === "symbol") {
            throw new Error(`${path} is not JSON-shaped`);
          }
          if (typeof value === "number" && !Number.isFinite(value)) {
            throw new Error(`${path} is not finite`);
          }
          if (!value || typeof value !== "object") return;
          if (Array.isArray(value)) {
            for (let i = 0; i < value.length; i++) {
              assertJsonish(value[i], `${path}[${i}]`);
            }
            return;
          }
          for (const [k, v] of Object.entries(value)) {
            assertJsonish(v, `${path}.${k}`);
          }
        }
        let seed = 0x5eed1234;
        function rnd() {
          seed = (seed * 1664525 + 1013904223) >>> 0;
          return seed / 4294967296;
        }
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" +
          "0123456789-_.:[]@/\\\\\\u0000\\u0001<>{}();";
        function rstr(maxLen) {
          const len = Math.floor(rnd() * maxLen);
          let s = "";
          for (let i = 0; i < len; i++) {
            s += chars[Math.floor(rnd() * chars.length)];
          }
          return s;
        }
        function rval(depth = 0) {
          const pick = Math.floor(rnd() * 10);
          if (pick === 0) return null;
          if (pick === 1) return undefined;
          if (pick === 2) return rnd() < 0.5;
          if (pick === 3) return Math.floor(rnd() * 200000) - 100000;
          if (pick === 4) return rstr(360);
          if (pick === 5 && depth < 2) {
            const a = [];
            for (let i = 0; i < Math.floor(rnd() * 7); i++) a.push(rval(depth + 1));
            return a;
          }
          if (depth < 2) {
            const o = {};
            for (let i = 0; i < Math.floor(rnd() * 7); i++) o[rstr(40)] = rval(depth + 1);
            return o;
          }
          return rstr(80);
        }

        const trusted = { id: browser.runtime.id };
        const commands = [
          "enable-hardening",
          "disable-hardening",
          "get-status",
          "run-self-test",
          "run-tor-test",
          "get-message-id-fqdn",
          "save-message-id-fqdn",
          "unknown-command",
        ];
        for (const cmd of commands) {
          const msg = {
            cmd,
            host: rval(),
            mode: rval(),
            custom: rval(),
            scrubLogins: rval(),
          };
          const response = await listener(msg, trusted);
          assertJsonish(response, `response.${cmd}`);
        }
        for (let i = 0; i < 1200; i++) {
          const msg = i % 3 === 0
            ? rval()
            : {
              cmd: i % 5 === 0 ? commands[Math.floor(rnd() * commands.length)] : rval(),
              host: rval(),
              mode: rval(),
              custom: rval(),
              scrubLogins: rval(),
            };
          const sender = i % 7 === 0 ? { id: rstr(64) } : trusted;
          const response = await listener(msg, sender);
          assertJsonish(response, `response.${i}`);
        }
        app.stopHardeningMonitors();
        return { ok: true, iterations: 1200 };
        """,
        args=[background_js],
    )
    assert result == {"ok": True, "iterations": 1200}


def test_experiment_js_fuzzes_host_and_login_origin_parsing(
    tb: TBClient,
) -> None:
    """Fuzz parent-process host and login-origin parsing helpers in TB JS."""
    implementation_js = _read("/addon/experiments/onionbird/implementation.js")
    result = tb.exec_chrome(
        r"""
        const [source] = arguments;
        const load = new Function(`${source}
          return {
            addLoginOriginsForServer,
            canonicalizeIp,
            classifyMailHostForReport,
            isValidDnsHost,
            isValidIpv6Literal,
            isValidSocksHost,
            isOnionHost,
            normalizeLoginOriginPort,
            normalizeLoginOriginScheme,
            normalizeSocksHost,
            normalizeSocksPortValue,
            normalizeDnsComparisonHost,
            parseStrictIpv4Address,
            publicLoginOriginInfo,
            ptrConfirmsTargetHost,
          };`);
        const app = load.call({});
        const throws = (fn) => {
          try { fn(); return false; } catch (e) { return true; }
        };

        const validIpv6 = [
          "::1",
          "2001:db8::1",
          "1:2:3:4:5:6:7:8",
          "1:2:3:4:5:6:7::",
          "2001:0db8:0000:0000:0000:ff00:0042:8329",
        ];
        for (const ip of validIpv6) {
          if (!app.isValidIpv6Literal(ip)) {
            throw new Error(`valid IPv6 rejected: ${ip}`);
          }
          const canonical = app.canonicalizeIp(ip);
          if (!app.isValidIpv6Literal(canonical)) {
            throw new Error(`canonical IPv6 became invalid: ${ip} -> ${canonical}`);
          }
        }

        const invalidIpv6 = [
          "::",
          ":::",
          "1:::2",
          "2001:db8:::1",
          "1:2:3:4:5:6:7:8::",
          "zzzz::1",
          "1::zzzz",
        ];
        for (const ip of invalidIpv6) {
          if (app.isValidIpv6Literal(ip)) {
            throw new Error(`invalid IPv6 accepted: ${ip}`);
          }
          if (app.isValidSocksHost(ip)) {
            throw new Error(`invalid IPv6 accepted as SOCKS host: ${ip}`);
          }
          if (app.canonicalizeIp(ip) !== ip) {
            throw new Error(`invalid IPv6 should pass through unchanged: ${ip}`);
          }
        }
        for (const bad of [true, ["127.0.0.1"], { toString() { return "127.0.0.1"; } }]) {
          if (app.isValidSocksHost(bad)) {
            throw new Error("non-string SOCKS host validated");
          }
          if (!throws(() => app.normalizeSocksHost(bad))) {
            throw new Error("non-string SOCKS host normalized");
          }
          if (app.parseStrictIpv4Address(bad) !== null) {
            throw new Error("non-string IPv4 parsed");
          }
        }
        for (const bad of [true, false, [9050], { toString() { return "9050"; } }]) {
          if (!throws(() => app.normalizeSocksPortValue(bad))) {
            throw new Error(`coerced invalid SOCKS port: ${String(bad)}`);
          }
        }
        const onion = "b".repeat(56) + ".onion";
        if (!app.isOnionHost(onion) || !app.isOnionHost(`${onion}:587.`)) {
          throw new Error("valid v3 onion host not classified");
        }
        if (app.isOnionHost(`[${onion}]:587`) ||
            app.classifyMailHostForReport(`[${onion}]:587`) !== "other") {
          throw new Error("bracketed onion host should not disable STARTTLS");
        }
        if (app.publicLoginOriginInfo(`[${onion}]:587`).host_type !== "unknown") {
          throw new Error("bare host is not a login origin");
        }
        if (app.publicLoginOriginInfo(`smtp://[${onion}]:587`).host_type !== "other") {
          throw new Error("bracketed onion origin must not report onion");
        }
        if (app.publicLoginOriginInfo("smtp://[::1]:993").host_type !== "loopback") {
          throw new Error("bracketed IPv6 loopback origin should report loopback");
        }
        if (app.normalizeDnsComparisonHost(["archive.torproject.org"]) !== "" ||
            app.ptrConfirmsTargetHost(["archive.torproject.org"], "torproject.org")) {
          throw new Error("non-string PTR host was coerced");
        }
        if (app.ptrConfirmsTargetHost(
          { toString() { return "archive.torproject.org"; } },
          "torproject.org"
        )) {
          throw new Error("object PTR host was coerced");
        }
        for (const bad of [
          ["smtp://127.0.0.1:25"],
          { toString() { return "smtp://127.0.0.1:25"; } },
        ]) {
          if (app.publicLoginOriginInfo(bad).host_type !== "unknown") {
            throw new Error("non-string login origin was coerced");
          }
        }

        const origins = new Set();
        app.addLoginOriginsForServer(origins, "smtp", onion, 25);
        if (!origins.has(`smtp://${onion}`) || !origins.has(`smtp://${onion}:25`)) {
          throw new Error("valid SMTP onion origins missing");
        }
        origins.clear();
        app.addLoginOriginsForServer(origins, "smtp\nhttp", onion, 25);
        app.addLoginOriginsForServer(origins, ["smtp"], onion, 25);
        if (origins.size !== 0) {
          throw new Error("unsafe login origin scheme accepted");
        }
        app.addLoginOriginsForServer(origins, "imap", "::1", "993");
        if (!origins.has("imap://[::1]") || !origins.has("imap://[::1]:993")) {
          throw new Error("valid IMAP loopback origins missing");
        }
        origins.clear();
        app.addLoginOriginsForServer(origins, "imap", "::1", true);
        if (origins.has("imap://[::1]:1")) {
          throw new Error("boolean login origin port was coerced to 1");
        }
        app.addLoginOriginsForServer(origins, "imap", "::1", [993]);
        if (origins.has("imap://[::1]:993")) {
          throw new Error("array login origin port was coerced");
        }

        let seed = 0xbadc0de;
        function rnd() {
          seed = (seed * 1664525 + 1013904223) >>> 0;
          return seed / 4294967296;
        }
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" +
          "0123456789-_.:[]@/\\\\\\u0000\\u0001";
        function rstr(maxLen) {
          const len = Math.floor(rnd() * maxLen);
          let s = "";
          for (let i = 0; i < len; i++) {
            s += chars[Math.floor(rnd() * chars.length)];
          }
          return s;
        }

        for (let i = 0; i < 6000; i++) {
          const s = rstr(320);
          const ipv6 = app.isValidIpv6Literal(s);
          if (typeof ipv6 !== "boolean") {
            throw new Error("IPv6 validator returned non-boolean");
          }
          const socks = app.isValidSocksHost(s);
          if (typeof socks !== "boolean") {
            throw new Error("SOCKS host validator returned non-boolean");
          }
          const dns = app.isValidDnsHost(s);
          if (typeof dns !== "boolean") {
            throw new Error("DNS host validator returned non-boolean");
          }
          const v4 = app.parseStrictIpv4Address(s);
          if (v4 !== null && (!Array.isArray(v4) || v4.length !== 4)) {
            throw new Error("IPv4 parser returned malformed value");
          }
          const canonical = app.canonicalizeIp(s);
          if (typeof canonical !== "string") {
            throw new Error("canonicalizeIp returned non-string");
          }
          if (canonical !== s && /nan/i.test(canonical)) {
            throw new Error(`canonicalizeIp produced NaN artifact: ${s} -> ${canonical}`);
          }
          if (!ipv6 && s.indexOf(":") !== -1 && canonical !== s) {
            throw new Error(`invalid IPv6-like value was rewritten: ${s}`);
          }
          if (ipv6 && !app.isValidIpv6Literal(canonical)) {
            throw new Error(`valid IPv6 canonicalized to invalid: ${canonical}`);
          }
          const normalized = app.normalizeDnsComparisonHost(s);
          if (typeof normalized !== "string") {
            throw new Error("normalizeDnsComparisonHost returned non-string");
          }
          const ptr = app.ptrConfirmsTargetHost(s, rstr(128));
          if (typeof ptr !== "boolean") {
            throw new Error("PTR comparison returned non-boolean");
          }

          const scheme = app.normalizeLoginOriginScheme(rstr(40));
          if (scheme !== "" && !["smtp", "imap", "pop3", "nntp"].includes(scheme)) {
            throw new Error(`unsafe login origin scheme normalized: ${scheme}`);
          }
          const port = app.normalizeLoginOriginPort(valueForPort(i, s));
          if (port !== null &&
              (!Number.isInteger(port) || port < 1 || port > 65535)) {
            throw new Error(`bad login origin port normalized: ${port}`);
          }
        }
        return { ok: true, iterations: 6000 };

        function valueForPort(i, s) {
          if (i % 13 === 0) return true;
          if (i % 17 === 0) return [993];
          if (i % 19 === 0) return { toString() { return "993"; } };
          if (i % 23 === 0) return String(Math.floor(rnd() * 70000));
          if (i % 29 === 0) return Math.floor(rnd() * 70000);
          return s;
        }
        """,
        args=[implementation_js],
    )
    assert result == {"ok": True, "iterations": 6000}


def test_experiment_api_fuzzes_public_inputs_and_outputs(tb: TBClient) -> None:
    """Fuzz the experiment API with fake Services/MailServices boundaries."""
    import json
    implementation_js = _read("/addon/experiments/onionbird/implementation.js")
    # B-083: derive expected API version from manifest at test time so a
    # version bump doesn't require touching the fuzz harness's literal.
    manifest = json.loads(_read("/addon/manifest.json"))
    expected_api_version = manifest["version"]
    result = tb.exec_chrome(
        r"""
        const [source, expectedApiVersion] = arguments;
        const onion = "c".repeat(56) + ".onion";
        const prefStore = Object.create(null);
        const fakePrefs = {
          PREF_INVALID: 0,
          PREF_STRING: 32,
          PREF_INT: 64,
          PREF_BOOL: 128,
          prefHasUserValue(name) {
            return Object.prototype.hasOwnProperty.call(prefStore, name);
          },
          getPrefType(name) {
            if (!this.prefHasUserValue(name)) return this.PREF_INVALID;
            const value = prefStore[name];
            if (typeof value === "string") return this.PREF_STRING;
            if (typeof value === "number") return this.PREF_INT;
            if (typeof value === "boolean") return this.PREF_BOOL;
            return this.PREF_INVALID;
          },
          getCharPref(name) {
            if (typeof prefStore[name] !== "string") throw new Error("not string");
            return prefStore[name];
          },
          getIntPref(name) {
            if (!Number.isInteger(prefStore[name])) throw new Error("not int");
            return prefStore[name];
          },
          getBoolPref(name) {
            if (typeof prefStore[name] !== "boolean") throw new Error("not bool");
            return prefStore[name];
          },
          setCharPref(name, value) { prefStore[name] = String(value); },
          setIntPref(name, value) { prefStore[name] = value; },
          setBoolPref(name, value) { prefStore[name] = value; },
          clearUserPref(name) { delete prefStore[name]; },
        };
        prefStore["network.proxy.socks"] = "127.0.0.1";
        prefStore["network.proxy.socks_port"] = 9050;

        const smtpServer = {
          key: "smtp1",
          hostname: onion,
          port: 587,
          QueryInterface() { return this; },
          closeCachedConnections() {},
        };
        const fakeMailServices = {
          outgoingServer: { servers: [smtpServer] },
          accounts: {
            allIdentities: [{ key: "id1", email: "user@example.com" }],
            allServers: [
              { key: "imap1", type: "imap", hostName: onion, port: 993 },
              { key: "bad/key", type: ["imap"], hostName: ["127.0.0.1"], port: [993] },
            ],
          },
        };
        const fakeInterfaces = {
          nsISmtpServer: function nsISmtpServer() {},
          nsIDNSService: { RESOLVE_TYPE_DEFAULT: 0 },
          nsIThreadManager: function nsIThreadManager() {},
        };
        const fakeComponents = {
          Ci: fakeInterfaces,
          interfaces: fakeInterfaces,
          classes: {
            "@mozilla.org/network/dns-service;1": {
              getService() {
                return {
                  clearCache() {},
                  asyncResolve() { throw new Error("dns disabled in fuzzer"); },
                };
              },
            },
            "@mozilla.org/thread-manager;1": {
              getService() {
                return {
                  mainThread: {},
                  dispatchToMainThread(task) { task.run(); },
                };
              },
            },
          },
          isSuccessCode(status) { return status === 0; },
        };
        const fakeServices = {
          prefs: fakePrefs,
          logins: {
            searchLogins() { return []; },
            removeLogin() {},
          },
        };
        const fakeCrypto = {
          getRandomValues(bytes) {
            for (let i = 0; i < bytes.length; i++) bytes[i] = i & 0xff;
            return bytes;
          },
        };
        const fakeChromeUtils = {
          importESModule(path) {
            if (path.includes("ExtensionCommon")) {
              return { ExtensionCommon: { ExtensionAPI: class ExtensionAPI {} } };
            }
            if (path.includes("MailServices")) {
              return { MailServices: fakeMailServices };
            }
            throw new Error(`unexpected import: ${path}`);
          },
          generateQI() { return function QueryInterface() {}; },
        };
        const load = new Function(
          "ChromeUtils", "Components", "globalThis",
          `${source}\nreturn this.onionbird;`
        );
        const ApiClass = load.call(
          {},
          fakeChromeUtils,
          fakeComponents,
          { Services: fakeServices, Components: fakeComponents, crypto: fakeCrypto }
        );
        const api = new ApiClass().getAPI({}).onionbird;

        function assertJsonish(value, path = "value") {
          if (value === undefined || typeof value === "function" ||
              typeof value === "symbol") {
            throw new Error(`${path} is not JSON-shaped`);
          }
          if (typeof value === "number" && !Number.isFinite(value)) {
            throw new Error(`${path} is not finite`);
          }
          if (!value || typeof value !== "object") return;
          if (Array.isArray(value)) {
            for (let i = 0; i < value.length; i++) {
              assertJsonish(value[i], `${path}[${i}]`);
            }
            return;
          }
          for (const [k, v] of Object.entries(value)) {
            assertJsonish(v, `${path}.${k}`);
          }
        }
        function assertResultObject(value, name) {
          if (!value || typeof value !== "object" || Array.isArray(value)) {
            throw new Error(`${name} did not return an object`);
          }
          assertJsonish(value, name);
        }

        let seed = 0xdecafbad;
        function rnd() {
          seed = (seed * 1664525 + 1013904223) >>> 0;
          return seed / 4294967296;
        }
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" +
          "0123456789-_.:[]@/\\\\\\u0000\\u0001<>{}();";
        function rstr(maxLen) {
          const len = Math.floor(rnd() * maxLen);
          let s = "";
          for (let i = 0; i < len; i++) {
            s += chars[Math.floor(rnd() * chars.length)];
          }
          return s;
        }
        function rval(depth = 0) {
          const pick = Math.floor(rnd() * 11);
          if (pick === 0) return null;
          if (pick === 1) return undefined;
          if (pick === 2) return rnd() < 0.5;
          if (pick === 3) return Math.floor(rnd() * 200000) - 100000;
          if (pick === 4) return rstr(360);
          if (pick === 5) return Number.NaN;
          if (pick === 6 && depth < 2) {
            const a = [];
            for (let i = 0; i < Math.floor(rnd() * 7); i++) a.push(rval(depth + 1));
            return a;
          }
          if (depth < 2) {
            const o = {};
            for (let i = 0; i < Math.floor(rnd() * 7); i++) o[rstr(40)] = rval(depth + 1);
            return o;
          }
          return rstr(80);
        }
        function prefBatch() {
          const prefs = [];
          const names = [
            "network.proxy.socks",
            "network.proxy.socks_port",
            "onionbird.messageid.fqdn_mode",
            "mail.smtpserver.smtp1.try_ssl",
            "mail.identity.id1.FQDN",
            "xpinstall.signatures.required",
            rstr(80),
          ];
          for (let i = 0; i < Math.floor(rnd() * 8); i++) {
            prefs.push({ name: names[Math.floor(rnd() * names.length)], value: rval() });
          }
          return prefs;
        }
        function snapshotObject() {
          const snap = {};
          const names = [
            "network.proxy.socks",
            "network.proxy.socks_port",
            "mail.smtpserver.smtp1.try_ssl",
            "mail.identity.id1.FQDN",
            "xpinstall.signatures.required",
            rstr(80),
          ];
          for (let i = 0; i < Math.floor(rnd() * 8); i++) {
            snap[names[Math.floor(rnd() * names.length)]] = rval();
          }
          return snap;
        }

        if (await api.getApiVersion() !== expectedApiVersion) {
          throw new Error("bad API version (got " + (await api.getApiVersion()) + ", expected " + expectedApiVersion + ")");
        }
        const badProbe = await api.probeSocks(
          ["127.0.0.1"],
          [9050],
          ["check.torproject.org"]
        );
        assertResultObject(badProbe, "bad probe");
        if (badProbe.host !== null || badProbe.socks_port !== null || badProbe.ok !== false) {
          throw new Error("probeSocks leaked coerced non-string/non-integer fields");
        }
        const noCoercedTries = await api.runSelfTest(
          "check.torproject.org",
          { tries: [10], socksHost: "127.0.0.1", socksPort: 9050 }
        );
        assertResultObject(noCoercedTries, "runSelfTest tries regression");
        if (!Array.isArray(noCoercedTries.errors) || noCoercedTries.errors.length !== 3) {
          throw new Error("runSelfTest coerced array tries");
        }

        for (const call of [
          ["clearDnsCache", () => api.clearDnsCache()],
          ["getSmtpHardeningPrefNames", () => api.getSmtpHardeningPrefNames(rval())],
          ["getIdentityHardeningPrefNames", () => api.getIdentityHardeningPrefNames()],
          ["applyHardeningToAllSmtpServers", () => api.applyHardeningToAllSmtpServers(rval())],
          ["applyHardeningToAllIdentities", () => api.applyHardeningToAllIdentities()],
          ["clearHardeningFromAllSmtpServers", () => api.clearHardeningFromAllSmtpServers()],
          ["clearHardeningFromAllIdentities", () => api.clearHardeningFromAllIdentities()],
          ["auditSavedLoginsForTorServers", () => api.auditSavedLoginsForTorServers()],
          ["removeSavedLoginsForTorServers", () => api.removeSavedLoginsForTorServers()],
        ]) {
          assertResultObject(await call[1](), call[0]);
        }

        for (let i = 0; i < 900; i++) {
          const setResult = await api.setPref(rval(), rval());
          if (typeof setResult !== "boolean") {
            throw new Error("setPref returned non-boolean");
          }
          const clearResult = await api.clearPref(rval());
          if (typeof clearResult !== "boolean") {
            throw new Error("clearPref returned non-boolean");
          }
          const pref = await api.getPref(rval());
          assertJsonish(pref, "getPref");

          assertResultObject(
            await api.applyPrefs(i % 2 === 0 ? prefBatch() : rval()),
            "applyPrefs"
          );
          assertJsonish(
            await api.snapshotPrefs(i % 2 === 0 ? [
              "network.proxy.socks",
              "network.proxy.socks_port",
              rval(),
            ] : rval()),
            "snapshotPrefs"
          );
          assertResultObject(
            await api.restorePrefs(i % 2 === 0 ? snapshotObject() : rval()),
            "restorePrefs"
          );
          assertResultObject(
            await api.probeSocks(rval(), rval(), rval()),
            "probeSocks"
          );
          assertResultObject(
            await api.runSelfTest(rval(), rval()),
            "runSelfTest"
          );
        }
        return { ok: true, iterations: 900 };
        """,
        args=[implementation_js, expected_api_version],
    )
    assert result == {"ok": True, "iterations": 900}


def _v3_onion(label_char: str = "a") -> str:
    return f"{label_char * 56}.onion"


def test_install_user_js_fuzzes_prefs_without_policy_or_line_injection(tmp_path: Path) -> None:
    """Fuzz prefs.js account data consumed by install-user-js.sh.

    prefs.js is writable by Thunderbird and local tooling. The installer must
    treat it as untrusted: only safe account keys may produce output lines, and
    STARTTLS may be disabled only for strict v3 onion hostnames.
    """
    rng = random.Random(0xA11CE)
    profile = tmp_path / "fuzz.default"
    profile.mkdir()

    cases: dict[str, tuple[str, int]] = {
        "smtp_onion": (_v3_onion("b"), 0),
        "smtp_onion_port": (f"{_v3_onion('c')}:587.", 0),
        "smtp_short": ("abc123def456.onion", 3),
        "smtp_glob": ("attacker.onion[glob]", 3),
        "smtp_suffix": ("evil" + _v3_onion("d"), 3),
        "smtp_bracket": (f"[{_v3_onion('e')}]:9050", 3),
        "smtp_public": ("smtp.example.com", 3),
    }
    alphabet = string.ascii_letters + string.digits + "_"
    host_chars = string.ascii_letters + string.digits + "-_.:[]@/\\ "
    for i in range(80):
        key = "smtp" + "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 18)))
        host = "".join(rng.choice(host_chars) for _ in range(rng.randint(0, 100)))
        if rng.random() < 0.15:
            host = _v3_onion(rng.choice("abcde234567"))
            expected = 0
        else:
            expected = 3
        cases[f"{key}_{i}"] = (host, expected)

    lines = ["# Mozilla user preferences file"]
    for key, (host, _expected) in cases.items():
        lines.append(f'user_pref("mail.smtpserver.{key}.hostname", "{host}");')
        lines.append(
            f'user_pref("mail.smtpserver.{key}.username", "user-{key}@example.com");'
        )
    for raw_key in [
        "smtp.bad",
        "smtp-bad",
        "smtp/bad",
        'smtp1");user_pref("mail.smtpserver.pwn.try_ssl", 0);//',
    ]:
        lines.append(
            f'user_pref("mail.smtpserver.{raw_key}.hostname", "{_v3_onion()}");'
        )
    (profile / "prefs.js").write_text("\n".join(lines) + "\n")

    subprocess.run(
        ["bash", str(SCRIPT), str(profile)],
        capture_output=True,
        text=True,
        check=True,
    )
    out = (profile / "user.js").read_text()

    emitted_try_ssl = dict(
        re.findall(
            r'user_pref\("mail\.smtpserver\.([A-Za-z0-9_]+)\.try_ssl", ([03])\);',
            out,
        )
    )
    assert "pwn" not in emitted_try_ssl
    assert set(emitted_try_ssl) == set(cases)
    for key, (_host, expected) in cases.items():
        assert emitted_try_ssl[key] == str(expected), f"{key} classified incorrectly"

    for line in out.splitlines():
        if 'user_pref("mail.smtpserver.' in line:
            assert re.fullmatch(
                r'user_pref\("mail\.smtpserver\.[A-Za-z0-9_]+\.(hello_argument|try_ssl)", '
                r'("[^"]*"|[03])\);',
                line,
            ), f"unsafe generated line: {line!r}"
