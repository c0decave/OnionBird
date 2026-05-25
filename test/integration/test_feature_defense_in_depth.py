"""Defense-in-depth prefs in the addon's HARDENING_PREFS + user.js.

SOCKS5+remoteDNS already covers TB 140's SmtpClient empirically (see
external/test_dns_leak_audit.py::test_S9). The prefs asserted here close
independent leak surfaces:

- TRR (DNS-over-HTTPS) — could bypass Tor with an upstream DoH endpoint
- WebRTC — independent IP-disclosure vector
- network.proxy.no_proxies_on — must NOT exempt any host from SOCKS
- DNS prefetch / predictor — speculative lookups fire before connect

We verify three layers:
1. background.js HARDENING_PREFS declares the entries (source-of-truth)
2. user.js declares the always-safe subset for pre-startup
3. The applyPrefs mechanism actually writes them when invoked at runtime
"""

from __future__ import annotations

import time

import pytest
from helpers.tb_client import TBClient

XPI = "/build/onionbird.xpi"


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


# What MUST be in addon/background.js HARDENING_PREFS (applied at enable-hardening).
HARDENING_PREFS_DEFENSE = {
    "network.trr.mode": 5,                    # TRR (DoH) off-by-choice
    "network.proxy.no_proxies_on": "",        # no SOCKS bypass exemptions
    "media.peerconnection.enabled": False,    # no WebRTC
    "network.dns.disablePrefetch": True,
    "network.predictor.enabled": False,
    "network.prefetch-next": False,
    "geo.enabled": False,
}

# What MUST be in user-js/onionbird-user.js (always-safe pre-startup).
USERJS_DEFENSE = {
    "network.trr.mode": 5,
    "media.peerconnection.enabled": False,
    "network.dns.disablePrefetch": True,
    "network.predictor.enabled": False,
    "network.prefetch-next": False,
    "geo.enabled": False,
}


def _read_background() -> str:
    with open("/addon/background.js") as f:
        return f.read()


def _read_userjs() -> str:
    with open("/user-js/onionbird-user.js") as f:
        return f.read()


def _js_value_repr(value: object) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    return f'"{value}"'


@pytest.mark.parametrize("pref,value", list(HARDENING_PREFS_DEFENSE.items()))
def test_hardening_prefs_declares_defense_in_depth(pref: str, value: object) -> None:
    bg = _read_background()
    needle = f'"{pref}", value: {_js_value_repr(value)}'
    assert needle in bg, (
        f"background.js HARDENING_PREFS missing defense-in-depth pref: {needle}"
    )


@pytest.mark.parametrize("pref,value", list(USERJS_DEFENSE.items()))
def test_userjs_declares_defense_in_depth(pref: str, value: object) -> None:
    src = _read_userjs()
    needle = f'user_pref("{pref}", {_js_value_repr(value)})'
    assert needle in src, (
        f"user.js missing defense-in-depth pref: {needle}"
    )


def test_defense_prefs_apply_via_addon_enable_runtime(tb: TBClient) -> None:
    """The real addon enable path writes every defense-in-depth pref.

    This intentionally avoids direct `Services.prefs.set*Pref`: the point is
    to prove background.js -> browser.onionbird.applyPrefs -> writePref, not
    merely that Mozilla's pref service can store values.
    """
    tb.set_pref("network.proxy.socks", "tor")
    tb.set_pref("network.proxy.socks_port", 9050)
    tb.install_addon(XPI, temporary=True)

    deadline = time.time() + 30
    last = {}
    while time.time() < deadline:
        last = {name: tb.get_pref(name) for name in HARDENING_PREFS_DEFENSE}
        if all(last[name] == value for name, value in HARDENING_PREFS_DEFENSE.items()):
            break
        time.sleep(0.25)
    else:
        expected = HARDENING_PREFS_DEFENSE
        assert last == expected, f"addon enable did not apply defense prefs: {last}"
