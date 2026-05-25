"""HTTP client for the SMTP capture trap."""

from __future__ import annotations

from typing import Any

import httpx


class MailCapture:
    def __init__(self, base: str = "http://smtp-trap:8025") -> None:
        self.base = base
        self.client = httpx.Client(timeout=120)

    def clear(self) -> None:
        self.client.delete(f"{self.base}/messages")

    def list(self) -> list[dict[str, Any]]:
        r = self.client.get(f"{self.base}/messages")
        r.raise_for_status()
        return r.json()

    def wait_for(self, n: int = 1, timeout: float = 60) -> list[dict[str, Any]]:
        r = self.client.get(
            f"{self.base}/messages/wait",
            params={"n": n, "timeout": timeout},
        )
        if r.status_code == 408:
            raise TimeoutError(f"only captured {r.json()['captured']} of {n}")
        r.raise_for_status()
        return r.json()
