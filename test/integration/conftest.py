"""Shared pytest fixtures."""

from __future__ import annotations

import os
from collections.abc import Iterator

import httpx
import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "no_tb_reset: skip the reset_global_prefs autouse fixture "
        "for tests that genuinely do not touch Thunderbird (T-079)",
    )

SMTP_TRAP_HTTP = "http://smtp-trap:8025"
DNS_TRAP_HTTP = "http://dns-trap:8053"
TOR_HOST = "tor"
TOR_SOCKS_PORT = 9050
THUNDERBIRD_HOST = "thunderbird"
THUNDERBIRD_MARIONETTE_PORT = 2828


# B-009 fix: autouse fixture resets known-leaky prefs between tests AND
# closes any cached SMTP connections (those cache proxy info at connect time).
# I-3 (T-076 review follow-up): also close any compose windows the previous
# test left around. The compose-window helper has a try/close path, but if a
# test crashes mid-helper or returns early the window leaks into the next
# test's TB session and confuses any test that looks at `getEnumerator("msgcompose")`.
RESET_GLOBAL_PREFS = r"""
const prefs = [
  "network.proxy.type",
  "network.proxy.socks",
  "network.proxy.socks_port",
  "network.proxy.socks_version",
  "network.proxy.socks_remote_dns",
  "network.proxy.failover_direct",
  "mailnews.headers.sendUserAgent",
  "privacy.resistFingerprinting",
  "network.dns.disableIPv6",
  // F-173: test-pollution gaps caught by the bug-search pass.
  // test_behavioural_addon_drives writes these as "leak-on baseline"
  // before installing the addon; if the addon's enable then fails
  // mid-way (or another test installs after this one), the leak-on
  // state persists into later tests that expect TB defaults.
  "network.predictor.enabled",
  "network.prefetch-next",
];

// F-168 review I-2: sweep ALL onionbird.* user-set prefs rather than
// hardcoding individual names. Older approach hardcoded the
// `onionbird.socks.*` pair (added with F-168) but missed the existing
// `onionbird.messageid.fqdn_*` family — a fqdn_custom test that left a
// stale value behind could silently poison a later test expecting the
// per-install random-fallback path. The branch sweep is forward-
// compatible: any new addon-owned pref gets reset automatically.
try {
  const branch = Services.prefs.getBranch("onionbird.");
  for (const child of branch.getChildList("")) {
    try { branch.clearUserPref(child); } catch (e) {}
  }
} catch (e) {}
for (const p of prefs) {
  try { Services.prefs.clearUserPref(p); } catch (e) {}
}

// Close cached SMTP connections — they cache proxy info & server lookups.
try {
  const { MailServices } = ChromeUtils.importESModule(
    "resource:///modules/MailServices.sys.mjs"
  );
  const Ci = Components.interfaces;
  const outgoing = MailServices.outgoingServer || MailServices.smtp;
  if (outgoing && outgoing.servers) {
    for (const s of outgoing.servers) {
      try { s.QueryInterface(Ci.nsISmtpServer).closeCachedConnections(); }
      catch (e) {}
    }
  }
} catch (e) {}

// I-3: close any stray compose windows from a previous test.
try {
  for (const w of Services.wm.getEnumerator("msgcompose")) {
    try { w.close(); } catch (e) {}
  }
} catch (e) {}

return "reset";
"""


@pytest.fixture(autouse=True)
def reset_global_prefs(request) -> Iterator[None]:
    """Clear known-leaky prefs at start of every test.

    T-079: the previous version swallowed every exception silently,
    which meant a stuck Marionette session (e.g. previous test left
    an undismissed modal) made every subsequent test run with the
    leaked state of whichever earlier test last wrote — green-but-
    meaningless. Tests that genuinely don't need TB (the infra
    smoke tests, unit tests) can opt out with the
    `no_tb_reset` marker:

        @pytest.mark.no_tb_reset
        def test_does_not_touch_tb(): ...

    Any other test that the reset can't reach surfaces as a hard
    error instead of silently leaking pref state."""
    if "no_tb_reset" in request.keywords:
        yield
        return
    try:
        from helpers.tb_client import TBClient

        client = TBClient(host=THUNDERBIRD_HOST, port=THUNDERBIRD_MARIONETTE_PORT)
        client.exec_chrome(RESET_GLOBAL_PREFS)
        client.close()
    except Exception as e:
        # Infra-only tests don't need TB but they should declare it.
        # If a test forgot the marker but doesn't actually touch TB,
        # the fixture failure is louder than the silent leak — the
        # test author either adds @pytest.mark.no_tb_reset or
        # discovers that TB is unreachable for a real reason.
        import warnings
        warnings.warn(
            f"T-079: reset_global_prefs could not reach TB "
            f"({type(e).__name__}: {e}). If this test genuinely "
            f"doesn't need TB, add `@pytest.mark.no_tb_reset` to "
            f"document that. Otherwise the test is now running "
            f"with whatever pref state the previous test left "
            f"behind.",
            stacklevel=2,
        )
    yield


@pytest.fixture
def http() -> Iterator[httpx.Client]:
    with httpx.Client(timeout=10) as c:
        yield c


@pytest.fixture
def clear_traps(http: httpx.Client) -> None:
    http.delete(f"{SMTP_TRAP_HTTP}/messages")
    http.delete(f"{DNS_TRAP_HTTP}/queries")


@pytest.fixture
def onion_hostname() -> str:
    path = "/tests/fixtures/onion-hostname.txt"
    if not os.path.exists(path):
        pytest.skip("onion-hostname.txt not present; run `make test-up`")
    with open(path) as f:
        return f.read().strip()
