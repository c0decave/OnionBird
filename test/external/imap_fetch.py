"""IMAP fetch over SOCKS5/Tor — retrieve sent mail for header audit.

Uses a subclass of imaplib.IMAP4_SSL that overrides _create_socket() to
return a SOCKS5-tunneled socket. This is the proper way; the previous
implementation manually patched private attrs and broke under Python 3.12.
"""

from __future__ import annotations

import contextlib
import email
import imaplib
import ssl
import time
from dataclasses import dataclass
from typing import Any

import socks


@dataclass
class FetchedMessage:
    raw: bytes
    headers: dict[str, str]
    headers_multi: dict[str, list[str]]
    subject: str
    message_id: str
    body_text: str

    def get_all(self, name: str) -> list[str]:
        return self.headers_multi.get(name, [])


class _IMAP4_SOCKS_SSL(imaplib.IMAP4_SSL):
    """IMAP4_SSL that tunnels through a SOCKS5 proxy."""

    def __init__(
        self,
        host: str,
        port: int,
        socks_host: str,
        socks_port: int,
        timeout: int = 60,
    ) -> None:
        self._socks_host = socks_host
        self._socks_port = socks_port
        self._socks_timeout = timeout
        super().__init__(host=host, port=port, timeout=timeout)

    def _create_socket(self, timeout=None):  # type: ignore[override]
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, self._socks_host, self._socks_port, rdns=True)
        s.settimeout(timeout or self._socks_timeout)
        s.connect((self.host, self.port))
        return s

    def open(self, host="", port=imaplib.IMAP4_SSL_PORT, timeout=None):  # type: ignore[override]
        # Mirror IMAP4_SSL.open but wrap our SOCKS socket in SSL.
        self.host = host
        self.port = port
        sock = self._create_socket(timeout)
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(sock, server_hostname=host)
        self.file = self.sock.makefile("rb")


class _IMAP4_SOCKS_PLAIN(imaplib.IMAP4):
    """IMAP4 (no SSL) that tunnels through a SOCKS5 proxy."""

    def __init__(
        self,
        host: str,
        port: int,
        socks_host: str,
        socks_port: int,
        timeout: int = 60,
    ) -> None:
        self._socks_host = socks_host
        self._socks_port = socks_port
        self._socks_timeout = timeout
        super().__init__(host=host, port=port, timeout=timeout)

    def _create_socket(self, timeout=None):  # type: ignore[override]
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, self._socks_host, self._socks_port, rdns=True)
        s.settimeout(timeout or self._socks_timeout)
        s.connect((self.host, self.port))
        return s


class IMAPOverTor:
    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        password: str,
        use_ssl: bool = True,
        socks_host: str = "127.0.0.1",
        socks_port: int = 9050,
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.use_ssl = use_ssl
        self.socks_host = socks_host
        self.socks_port = socks_port

    @contextlib.contextmanager
    def connection(self) -> Any:
        cls = _IMAP4_SOCKS_SSL if self.use_ssl else _IMAP4_SOCKS_PLAIN
        imap = cls(
            host=self.host,
            port=self.port,
            socks_host=self.socks_host,
            socks_port=self.socks_port,
        )
        imap.login(self.user, self.password)
        try:
            yield imap
        finally:
            try:
                imap.logout()
            except Exception:
                pass

    def wait_for_subject(
        self, subject_substring: str, timeout: float = 60
    ) -> FetchedMessage | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.connection() as imap:
                imap.select("INBOX")
                typ, data = imap.search(None, "ALL")
                if typ == "OK" and data and data[0]:
                    for num in reversed(data[0].split()):
                        typ, mdata = imap.fetch(num, "(RFC822)")
                        if typ != "OK":
                            continue
                        raw = mdata[0][1]
                        msg = email.message_from_bytes(raw)
                        subj = msg.get("Subject") or ""
                        # Decode RFC 2047 if needed
                        from email.header import decode_header, make_header
                        try:
                            subj = str(make_header(decode_header(subj)))
                        except Exception:
                            pass
                        if subject_substring in subj:
                            return _to_fetched(raw, msg)
            time.sleep(3)
        return None


def _to_fetched(raw: bytes, msg: email.message.Message) -> FetchedMessage:
    headers: dict[str, str] = {}
    headers_multi: dict[str, list[str]] = {}
    for k, v in msg.items():
        headers[k] = v
        headers_multi.setdefault(k, []).append(v)

    # Decode RFC 2047 subject
    subject = msg.get("Subject", "")
    try:
        from email.header import decode_header, make_header
        subject = str(make_header(decode_header(subject)))
    except Exception:
        pass

    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload is not None:
                    body_text = payload.decode(errors="replace")
                break
    else:
        payload = msg.get_payload(decode=True)
        if payload is not None:
            body_text = payload.decode(errors="replace")

    return FetchedMessage(
        raw=raw,
        headers=headers,
        headers_multi=headers_multi,
        subject=subject,
        message_id=msg.get("Message-ID", ""),
        body_text=body_text,
    )
