"""Unit tests for experiment API pref validation."""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def test_set_pref_reuses_socks_override_validation() -> None:
    """The generic setPref path must not bypass SOCKS override validation."""
    script = r"""
const fs = require("fs");
const source = fs.readFileSync(process.argv[1], "utf8");
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
const fakeChromeUtils = {
  importESModule(path) {
    if (path.includes("ExtensionCommon")) {
      return { ExtensionCommon: { ExtensionAPI: class ExtensionAPI {} } };
    }
    if (path.includes("MailServices")) {
      return { MailServices: null };
    }
    throw new Error(`unexpected import: ${path}`);
  },
};
const fakeComponents = { interfaces: {}, classes: {} };
const fakeServices = { prefs: fakePrefs, logins: {} };
const load = new Function(
  "ChromeUtils",
  "Components",
  "globalThis",
  `${source}\nreturn this.onionbird;`,
);
const ApiClass = load.call(
  {},
  fakeChromeUtils,
  fakeComponents,
  { Services: fakeServices, Components: fakeComponents },
);
const api = new ApiClass().getAPI({}).onionbird;

async function requireSet(name, value, stored) {
  delete prefStore[name];
  const ok = await api.setPref(name, value);
  if (!ok) throw new Error(`${name} rejected ${JSON.stringify(value)}`);
  if (prefStore[name] !== stored) {
    throw new Error(`${name} stored ${JSON.stringify(prefStore[name])}`);
  }
}

async function requireReject(name, value, previous) {
  prefStore[name] = previous;
  const ok = await api.setPref(name, value);
  if (ok) throw new Error(`${name} accepted ${JSON.stringify(value)}`);
  if (prefStore[name] !== previous) {
    throw new Error(`${name} mutated failed write to ${JSON.stringify(prefStore[name])}`);
  }
}

(async () => {
  await requireSet("onionbird.messageid.fqdn_mode", "custom", "custom");
  await requireSet("onionbird.socks.host", "127.0.0.1", "127.0.0.1");
  await requireSet("onionbird.socks.host", " ::1 ", "::1");
  await requireReject("onionbird.socks.host", "tor", "127.0.0.1");
  await requireReject("onionbird.socks.host", "proxy.example", "127.0.0.1");
  await requireSet("onionbird.socks.port", 9050, 9050);
  await requireSet("onionbird.socks.port", 65535, 65535);
  await requireReject("onionbird.socks.port", 0, 9050);
  await requireReject("onionbird.socks.port", "9050", 9050);
})().catch((error) => {
  console.error(error && error.stack ? error.stack : error);
  process.exit(1);
});
"""
    subprocess.run(
        [
            "node",
            "-e",
            script,
            str(REPO / "addon" / "experiments" / "onionbird" / "implementation.js"),
        ],
        check=True,
        text=True,
    )
