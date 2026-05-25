"""Provider configurations loaded from environment."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderConfig:
    code: str
    email: str
    user: str
    password: str
    smtp_host: str
    smtp_port: int
    imap_host: str
    imap_port: int
    # 0=plain, 1=STARTTLS-via-587 handled by TB, 2=SSL/TLS-implicit
    smtp_use_ssl: bool = False
    # nsISmtpServer.socketType: 0=plain, 2=STARTTLS, 3=SSL
    smtp_socket_type: int = 2
    imap_use_ssl: bool = True


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _envint(name: str, default: int = 0) -> int:
    v = os.environ.get(name)
    return int(v) if v else default


def disroot() -> ProviderConfig | None:
    user = _env("T0R_DISROOT_USER")
    if not user:
        return None
    use_onion = _env("T0R_TEST_USE_ONION", "true").lower() == "true"
    return ProviderConfig(
        code="DISROOT",
        email=_env("T0R_DISROOT_EMAIL"),
        user=user,
        password=_env("T0R_DISROOT_PASS"),
        smtp_host=_env("T0R_DISROOT_SMTP_ONION") if use_onion else "disroot.org",
        smtp_port=_envint("T0R_DISROOT_SMTP_PORT", 25 if use_onion else 587),
        imap_host=_env("T0R_DISROOT_IMAP_ONION") if use_onion else "disroot.org",
        imap_port=_envint("T0R_DISROOT_IMAP_PORT", 143 if use_onion else 993),
        smtp_socket_type=0 if use_onion else 2,  # onion=plain, clearnet=STARTTLS
        imap_use_ssl=not use_onion,
    )


def riseup() -> ProviderConfig | None:
    user = _env("T0R_RISEUP_USER")
    if not user:
        return None
    return ProviderConfig(
        code="RISEUP",
        email=_env("T0R_RISEUP_EMAIL"),
        user=user,
        password=_env("T0R_RISEUP_PASS"),
        smtp_host=_env("T0R_RISEUP_SMTP_HOST", "mail.riseup.net"),
        smtp_port=_envint("T0R_RISEUP_SMTP_PORT", 587),
        imap_host=_env("T0R_RISEUP_IMAP_HOST", "mail.riseup.net"),
        imap_port=_envint("T0R_RISEUP_IMAP_PORT", 993),
        smtp_socket_type=2,
    )


def own() -> ProviderConfig | None:
    user = _env("T0R_OWN_USER")
    if not user:
        return None
    return ProviderConfig(
        code="OWN",
        email=_env("T0R_OWN_EMAIL"),
        user=user,
        password=_env("T0R_OWN_PASS"),
        smtp_host=_env("T0R_OWN_SMTP_HOST"),
        smtp_port=_envint("T0R_OWN_SMTP_PORT", 587),
        imap_host=_env("T0R_OWN_IMAP_HOST"),
        imap_port=_envint("T0R_OWN_IMAP_PORT", 993),
        smtp_socket_type=2,
    )


def undisclose() -> ProviderConfig | None:
    user = _env("T0R_UNDISCLOSE_USER")
    if not user:
        return None
    return ProviderConfig(
        code="UNDISCLOSE",
        email=_env("T0R_UNDISCLOSE_EMAIL"),
        user=user,
        password=_env("T0R_UNDISCLOSE_PASS"),
        smtp_host=_env("T0R_UNDISCLOSE_SMTP_HOST", "mail.undisclose.de"),
        smtp_port=_envint("T0R_UNDISCLOSE_SMTP_PORT", 587),
        imap_host=_env("T0R_UNDISCLOSE_IMAP_HOST", "mail.undisclose.de"),
        imap_port=_envint("T0R_UNDISCLOSE_IMAP_PORT", 993),
        smtp_socket_type=2,   # STARTTLS
        imap_use_ssl=True,
    )


def posteo() -> ProviderConfig | None:
    user = _env("T0R_POSTEO_USER")
    if not user:
        return None
    return ProviderConfig(
        code="POSTEO",
        email=_env("T0R_POSTEO_EMAIL"),
        user=user,
        password=_env("T0R_POSTEO_PASS"),
        smtp_host=_env("T0R_POSTEO_SMTP_HOST", "posteo.de"),
        smtp_port=_envint("T0R_POSTEO_SMTP_PORT", 587),
        imap_host=_env("T0R_POSTEO_IMAP_HOST", "posteo.de"),
        imap_port=_envint("T0R_POSTEO_IMAP_PORT", 993),
        smtp_socket_type=2,
        imap_use_ssl=True,
    )


REGISTRY = {
    "DISROOT": disroot,
    "RISEUP": riseup,
    "OWN": own,
    "UNDISCLOSE": undisclose,
    "POSTEO": posteo,
}


def get(code: str) -> ProviderConfig | None:
    factory = REGISTRY.get(code.upper())
    return factory() if factory else None


def selected(code: str | None = None) -> ProviderConfig | None:
    return get(code or _env("T0R_TEST_PROVIDER", "DISROOT"))
