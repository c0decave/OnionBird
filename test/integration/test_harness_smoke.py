"""Verify the test harness can drive Thunderbird via Marionette."""

from __future__ import annotations

import pytest
from helpers.dns_capture import DNSCapture
from helpers.mail_capture import MailCapture
from helpers.tb_client import TBClient


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


@pytest.fixture
def mail() -> MailCapture:
    m = MailCapture()
    m.clear()
    return m


@pytest.fixture
def dns() -> DNSCapture:
    d = DNSCapture()
    d.clear()
    return d


def test_can_read_app_name(tb: TBClient) -> None:
    name = tb.exec_chrome("return Services.appinfo.name;")
    assert name == "Thunderbird"


def test_can_set_and_read_pref(tb: TBClient) -> None:
    tb.set_pref("onionbird.smoke", True)
    assert tb.get_pref("onionbird.smoke") is True


def test_mail_capture_empty(mail: MailCapture) -> None:
    assert mail.list() == []


def test_dns_capture_empty(dns: DNSCapture) -> None:
    assert dns.queries() == []
