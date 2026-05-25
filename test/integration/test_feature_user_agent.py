"""User-Agent suppression — driven by the real addon enable path.

The previous version of this file only proved that Mozilla's pref
service could store and return a boolean (Services.prefs round-trip
via Marionette). That tested zero OnionBird code.

This version installs the XPI, lets the addon's onInstalled handler
run enableHardening, and polls until the hardening pref it owns
(`mailnews.headers.sendUserAgent=false`) materialises — i.e. the
addon -> background.js -> applyPrefs chain actually wrote it.
"""

from __future__ import annotations

import time

import pytest
from helpers.tb_client import TBClient

XPI = "/build/onionbird.xpi"
PREF = "mailnews.headers.sendUserAgent"


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


def _wait_for_pref(tb: TBClient, name: str, expected, timeout: float = 30.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = tb.get_pref(name)
        if last == expected:
            return last
        time.sleep(0.25)
    return last


def test_addon_enable_disables_user_agent_header(tb: TBClient) -> None:
    """After XPI install, the addon's enableHardening must clear
    `mailnews.headers.sendUserAgent`. Proves the addon writes the pref,
    not that Mozilla's pref-service stores booleans."""
    # Pre-seed the leak-on state. Without this we cannot distinguish
    # "addon wrote false" from "Mozilla's default was false anyway".
    tb.set_pref(PREF, True)
    # Auto-enable depends on a reachable SOCKS endpoint. Point at the
    # container Tor (same convention as test_feature_defense_in_depth).
    tb.set_pref("network.proxy.socks", "tor")
    tb.set_pref("network.proxy.socks_port", 9050)

    tb.install_addon(XPI, temporary=True)

    final = _wait_for_pref(tb, PREF, False)
    assert final is False, (
        f"addon enable did not flip {PREF} to false (got {final!r}); "
        f"the User-Agent suppression chain is broken"
    )
