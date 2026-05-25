"""F-175: Auto-enable-failure desktop notification must be localised.

The F-081 work added a `browser.notifications.create` call inside the
`runtime.onInstalled` handler so a user who installs the addon without
a reachable Tor sees an actionable "Tor not reachable" notification
instead of a silent send-block. The notification's title + body were
written as English string literals — bypassing the `browser.i18n.
getMessage` path every other user-visible string in background.js
uses.

A Farsi / Burmese / Bengali user (the F-168 cited repression-hotspot
locales) sees only English when their sends start failing — exactly
the population the localised cancelMessage work (U-072) was meant to
serve, undermined here by an inconsistent code path.

Fix: 4 new i18n keys covering the (title, message) pairs for the two
branches (`socksUnreachable` and `canary-self-test-failed`),
propagated to all 30 locales via the existing pipeline.
"""
from __future__ import annotations

import json
import re


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_F175_autoenable_notification_uses_i18n_keys() -> None:
    """background.js onInstalled-failure path must call
    browser.i18n.getMessage(...) for both the title and the message,
    NOT use string literals. Mutation-resistant assertion: the
    relevant notification.create block (inside onInstalled) must
    contain BOTH a getMessage call AND must NOT contain the previous
    hardcoded English text fragments that would have stayed in a
    half-converted regression."""
    bg = _read("/addon/background.js")
    # Slice the onInstalled handler body.
    start = bg.index("browser.runtime.onInstalled.addListener")
    end = bg.index("async function main()", start)
    block = bg[start:end]
    assert "browser.notifications.create" in block, (
        "F-175: notification.create call missing from onInstalled — "
        "the F-081 surface itself regressed"
    )
    # i18n call must be present in the title/message construction.
    assert "browser.i18n.getMessage" in block, (
        "F-175: notification title/message do not route through "
        "browser.i18n.getMessage — non-English users see English."
    )
    # Hardcoded English fragments from the pre-F-175 implementation
    # must NOT linger (half-converted regression).
    for fragment in (
        "Tor not reachable",
        "hardening incomplete",
        "canary self-test did",
    ):
        assert fragment not in block, (
            f"F-175: hardcoded English fragment {fragment!r} still "
            f"present in onInstalled notification path. Either the "
            f"i18n conversion was partial or a later edit re-introduced "
            f"the literal."
        )


def test_F175_i18n_keys_in_english_locale() -> None:
    """The 4 new i18n keys for the autoenable-failure notification
    must exist in the source-of-truth en bundle. Other locales follow
    via the existing pipeline; this test gates the en bundle."""
    en = json.loads(_read("/addon/_locales/en/messages.json"))
    required = (
        "autoEnableNotificationTitleSocksUnreachable",
        "autoEnableNotificationMessageSocksUnreachable",
        "autoEnableNotificationTitleCanaryFail",
        "autoEnableNotificationMessageCanaryFail",
    )
    missing = [k for k in required if k not in en]
    assert not missing, (
        f"F-175: en/messages.json missing i18n keys for the "
        f"autoenable-failure notification: {missing}."
    )
