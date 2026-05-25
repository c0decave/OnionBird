"""HTTP client for the DNS leak trap."""

from __future__ import annotations

from typing import Any

import httpx


class DNSCapture:
    def __init__(self, base: str = "http://dns-trap:8053") -> None:
        self.base = base
        self.client = httpx.Client(timeout=10)

    def clear(self) -> None:
        self.client.delete(f"{self.base}/queries")

    def queries(self) -> list[dict[str, Any]]:
        r = self.client.get(f"{self.base}/queries")
        r.raise_for_status()
        return r.json()

    def queries_for(self, hostname_substr: str) -> list[dict[str, Any]]:
        return [q for q in self.queries() if hostname_substr in q["qname"]]
