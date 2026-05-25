"""External-test fixtures. Connect to host TB via Marionette; require
credentials in env."""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from helpers.tb_client import TBClient  # noqa: E402

from external import providers as P  # noqa: E402
from external.imap_fetch import IMAPOverTor  # noqa: E402

# Bug X2 fix: autouse fixture for external tests too.
RESET_EXTERNAL_PREFS = r"""
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
];
for (const p of prefs) {
  try { Services.prefs.clearUserPref(p); } catch (e) {}
}
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
return "reset";
"""


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "external: real-network tests; require T0R_* env vars"
    )


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--provider",
        action="store",
        default=None,
        help="external provider code to test (default: T0R_TEST_PROVIDER or DISROOT)",
    )


@pytest.fixture(scope="session")
def tb_host() -> str:
    return os.environ.get("T0R_TB_HOST", "127.0.0.1")


@pytest.fixture(scope="session")
def tb_port() -> int:
    return int(os.environ.get("T0R_TB_PORT", "2828"))


@pytest.fixture(scope="session")
def socks_host() -> str:
    return os.environ.get("T0R_SOCKS_HOST", "127.0.0.1")


@pytest.fixture(scope="session")
def socks_port() -> int:
    return int(os.environ.get("T0R_SOCKS_PORT", "9050"))


@pytest.fixture(autouse=True)
def reset_state(request: pytest.FixtureRequest, tb_host: str, tb_port: int) -> Iterator[None]:
    """Reset proxy/header prefs between tests. Skips pure unit tests that don't
    use the `tb` or `provider` fixture (Bug Y1: was running for all 50 unit
    tests, costing 5+ minutes per suite)."""
    needs_tb = any(
        n in request.fixturenames
        for n in ("tb", "provider", "imap", "recv_email")
    )
    if needs_tb:
        try:
            client = TBClient(host=tb_host, port=tb_port)
            client.exec_chrome(RESET_EXTERNAL_PREFS)
            client.close()
        except Exception:
            pass  # tb not reachable: provider fixture will skip
    yield


@pytest.fixture
def tb(tb_host: str, tb_port: int) -> Iterator[TBClient]:
    try:
        client = TBClient(host=tb_host, port=tb_port)
    except Exception as e:
        pytest.skip(f"host TB not reachable on {tb_host}:{tb_port}: {e}")
    yield client
    client.close()


@pytest.fixture
def provider(request: pytest.FixtureRequest) -> P.ProviderConfig:
    provider_code = request.config.getoption("--provider")
    p = P.selected(provider_code)
    if p is None:
        selected = provider_code or os.environ.get("T0R_TEST_PROVIDER", "DISROOT")
        pytest.skip(
            f"no {selected} provider credentials in env; "
            "copy test/external/secrets.env.example to secrets.env and fill in"
        )
    if not p.password:
        pytest.skip(f"provider {p.code} has no password set")
    return p


@pytest.fixture
def imap(provider: P.ProviderConfig, socks_host: str, socks_port: int) -> IMAPOverTor:
    return IMAPOverTor(
        host=provider.imap_host,
        port=provider.imap_port,
        user=provider.user,
        password=provider.password,
        use_ssl=provider.imap_use_ssl,
        socks_host=socks_host,
        socks_port=socks_port,
    )


@pytest.fixture
def recv_email(provider: P.ProviderConfig) -> str:
    """Where to send the test mail TO. Defaults to send-to-self."""
    return os.environ.get("T0R_RECV_EMAIL") or provider.email


@pytest.fixture
def recv_provider(provider: P.ProviderConfig) -> P.ProviderConfig:
    """Provider config for the RECIPIENT mailbox (T0R_RECV_*).

    Falls back to the sender's provider if no T0R_RECV_USER is set — this
    means send-to-self and `imap_recv` aliases `imap`. When the env has
    T0R_RECV_USER/PASS/IMAP_HOST/IMAP_PORT, this returns a distinct
    ProviderConfig so tests can verify cross-account delivery in the
    recipient's INBOX.
    """
    user = os.environ.get("T0R_RECV_USER")
    if not user:
        return provider
    email = os.environ.get("T0R_RECV_EMAIL", "")
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        pytest.fail(
            "T0R_RECV_USER is set, so T0R_RECV_EMAIL must be a distinct "
            "RFC-5321-shaped recipient address"
        )
    if email.lower() == provider.email.lower() or user == provider.user:
        pytest.fail(
            "T0R_RECV_* must point at a distinct recipient mailbox; refusing "
            "to degrade cross-account tests to send-to-self"
        )
    password = os.environ.get("T0R_RECV_PASS", "")
    if not password:
        pytest.fail("T0R_RECV_USER is set but T0R_RECV_PASS is empty")
    return P.ProviderConfig(
        code=f"{provider.code}_RECV",
        email=email,
        user=user,
        password=password,
        smtp_host=provider.smtp_host,
        smtp_port=provider.smtp_port,
        imap_host=os.environ.get("T0R_RECV_IMAP_HOST", provider.imap_host),
        imap_port=int(os.environ.get("T0R_RECV_IMAP_PORT", str(provider.imap_port))),
        smtp_socket_type=provider.smtp_socket_type,
        imap_use_ssl=provider.imap_use_ssl,
    )


@pytest.fixture
def imap_recv(
    recv_provider: P.ProviderConfig,
    socks_host: str,
    socks_port: int,
) -> IMAPOverTor:
    """IMAP-over-Tor pointing at the RECIPIENT mailbox.

    If T0R_RECV_* env is not set, this is the same as `imap` (send-to-self)
    — which lets every cross-account test degrade gracefully to a send-to-
    self verification when only one mailbox is configured.
    """
    if not recv_provider.password:
        pytest.skip(
            f"recv mailbox {recv_provider.user!r} has no password — "
            "set T0R_RECV_PASS in secrets.env to enable cross-account tests"
        )
    return IMAPOverTor(
        host=recv_provider.imap_host,
        port=recv_provider.imap_port,
        user=recv_provider.user,
        password=recv_provider.password,
        use_ssl=recv_provider.imap_use_ssl,
        socks_host=socks_host,
        socks_port=socks_port,
    )


@pytest.fixture
def delivery_timeout() -> int:
    return int(os.environ.get("T0R_TEST_WAIT_DELIVERY", "30"))
