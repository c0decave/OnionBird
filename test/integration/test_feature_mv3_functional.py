"""MV3 functional smoke — proves the MV3 XPI actually works, not just
that the manifest parses.

`test_feature_mv3_manifest.py::test_mv3_install_smoke` is intentionally
tolerated: it skips on Mozilla rejection rather than failing. That
gives zero regression coverage for the day Mozilla flips MV3 support
on. This file goes further: when the MV3 XPI *does* install, we drive
it through the same enableHardening path the MV2 XPI uses and assert
the hardening pref ends up flipped. Tests skip cleanly on TB versions
where MV3 install is rejected — but if install succeeds, the addon
MUST actually function.
"""

from __future__ import annotations

import os
import time

import pytest
from helpers.tb_client import TBClient

XPI_MV3 = "/build/onionbird-mv3.xpi"
HARDENING_MARKER_PREF = "mailnews.headers.sendUserAgent"


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


def _try_install_mv3(tb: TBClient) -> str | None:
    if not os.path.exists(XPI_MV3):
        pytest.skip(f"{XPI_MV3} not built — run `make build-mv3`")
    try:
        return tb.install_addon(XPI_MV3, temporary=True)
    except Exception as e:
        pytest.skip(f"TB rejected MV3 install (expected on some ESRs): {e}")


def _wait_for_pref(tb: TBClient, name: str, expected, timeout: float = 30.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = tb.get_pref(name)
        if last == expected:
            return last
        time.sleep(0.25)
    return last


def test_mv3_addon_actually_hardens_when_installed(tb: TBClient) -> None:
    """When the MV3 XPI installs successfully, enableHardening must
    run and flip the same hardening pref the MV2 XPI flips. Without
    this, the MV3 build could ship a no-op binary and the only
    existing test (test_mv3_install_smoke) would still pass.

    This is the load-bearing functional check for MV3: it proves the
    WebExtension background script runs, the experiment API binding
    works under MV3, and applyPrefs reaches Services.prefs."""
    # Pre-seed the leak-on state so we observe a real write.
    tb.set_pref(HARDENING_MARKER_PREF, True)
    tb.set_pref("network.proxy.socks", "tor")
    tb.set_pref("network.proxy.socks_port", 9050)

    addon_id = _try_install_mv3(tb)
    assert addon_id == "onionbird@undisclose.de"

    final = _wait_for_pref(tb, HARDENING_MARKER_PREF, False)
    assert final is False, (
        f"MV3 addon installed but did not run enableHardening "
        f"({HARDENING_MARKER_PREF} still {final!r}). The MV3 XPI is a "
        f"no-op — likely a manifest format / experiment-API binding "
        f"regression that the manifest-parse smoke test doesn't catch."
    )
