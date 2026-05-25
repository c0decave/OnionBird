"""Install the addon into running TB and verify experiment API."""

from __future__ import annotations

import pytest
from helpers.tb_client import TBClient

XPI = "/build/onionbird.xpi"


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


def test_addon_installs(tb: TBClient) -> None:
    addon_id = tb.install_addon(XPI, temporary=True)
    assert addon_id == "onionbird@undisclose.de"


def test_experiment_api_via_pref(tb: TBClient) -> None:
    """T-083: prove the experiment API ACTUALLY loaded and writes
    prefs from the parent process, not just that Mozilla's pref
    service stores strings. The original test set
    `onionbird.test.marker` itself and asserted Mozilla honoured
    the write — that's a pref-service test, not an experiment-API
    test. The addon could ship without the `experiments/onionbird/`
    directory and the old test still passed.

    Behavioural shape: after install, the addon's enableHardening
    calls `browser.onionbird.applyPrefs(HARDENING_PREFS)` which
    routes through the parent-process writePref(). At least one
    HARDENING_PREFS entry that depends on the experiment-API
    surface MUST be set. We pick `mailnews.headers.sendUserAgent`
    because it's in HARDENING_PREFS, has a behaviourally
    distinguishable TB default, and is written via writePref()
    (the parent-process surface)."""
    import time
    tb.set_pref("mailnews.headers.sendUserAgent", True)
    assert tb.get_pref("mailnews.headers.sendUserAgent") is True
    tb.install_addon(XPI, temporary=True)
    deadline = time.time() + 30
    final = True
    while time.time() < deadline:
        final = tb.get_pref("mailnews.headers.sendUserAgent")
        if final is False:
            break
        time.sleep(0.25)
    assert final is False, (
        "T-083: addon installed but the experiment API surface "
        "did not write mailnews.headers.sendUserAgent. Either "
        "experiments/onionbird/ failed to load OR writePref() in "
        "the parent process is broken — both invalidate every "
        "other test in this file."
    )
