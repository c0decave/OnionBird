"""Upgrade / reinstall path: a fresh install after a previous one was
removed must re-run enableHardening cleanly.

The audit flagged this as a coverage gap: the upgrade branch in
`browser.runtime.onInstalled` was only tested by source-grep
(test_audit_fixes.py::test_B004_*). This file exercises the real
behavior end-to-end via Marionette's install/uninstall API.

A note on what is NOT covered here: a *real* upgrade-version path
(install pre-v0.1.0 XPI, install v0.1.0 over it, assert
`reason='update'` triggers enableHardening). That requires a
historical XPI artifact in the repo; tracked as follow-up.
The reinstall test below is the strongest behavioural coverage
possible without that artifact.
"""

from __future__ import annotations

import time

import pytest
from helpers.tb_client import TBClient

XPI = "/build/onionbird.xpi"
MARKER = "mailnews.headers.sendUserAgent"


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


def _wait(get, expected, timeout=30.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = get()
        if last == expected:
            return last
        time.sleep(0.25)
    return last


def test_reinstall_re_hardens_after_uninstall(tb: TBClient) -> None:
    """Install → uninstall → reinstall must run enableHardening
    again. Covers the path where a user removes the addon (Mozilla
    cleans up storage.local for temporary installs), then reinstalls
    — the second install's onInstalled fires with reason='install'
    and must take effect."""
    tb.set_pref(MARKER, True)
    tb.set_pref("network.proxy.socks", "tor")
    tb.set_pref("network.proxy.socks_port", 9050)

    # First install
    addon_id = tb.install_addon(XPI, temporary=True)
    assert _wait(lambda: tb.get_pref(MARKER), False) is False, (
        "first install did not enable hardening"
    )

    # Uninstall + reset pref to leak-on
    tb.uninstall_addon(addon_id)
    time.sleep(1)
    tb.set_pref(MARKER, True)
    assert tb.get_pref(MARKER) is True

    # Reinstall — must enable again
    tb.install_addon(XPI, temporary=True)
    final = _wait(lambda: tb.get_pref(MARKER), False)
    assert final is False, (
        f"second install did not re-enable hardening (got {final!r}); "
        f"reinstall path is broken"
    )
