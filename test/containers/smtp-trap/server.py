"""SMTP capture server.

Listens on port 25 for SMTP, accepts every message, records peer IP, HELO,
MAIL FROM, RCPT TO, raw RFC 5322 content, timestamp. HTTP API on port 8025:

- GET    /messages              -> list captured messages (newest first)
- DELETE /messages              -> clear capture buffer
- GET    /messages/wait?n=1&timeout=30 -> long-poll for N messages
- GET    /healthz               -> 200 OK
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from aiohttp import web
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope, Session


@dataclass
class CapturedMessage:
    peer_host: str
    peer_port: int
    helo: str | None
    mail_from: str
    rcpt_tos: list[str]
    content: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CaptureHandler:
    def __init__(self) -> None:
        self.messages: list[CapturedMessage] = []
        self.new_message_event = asyncio.Event()

    async def handle_DATA(
        self,
        server: Any,
        session: Session,
        envelope: Envelope,
    ) -> str:
        msg = CapturedMessage(
            peer_host=session.peer[0],
            peer_port=session.peer[1],
            helo=session.host_name,
            mail_from=envelope.mail_from or "",
            rcpt_tos=list(envelope.rcpt_tos),
            content=envelope.content.decode("utf-8", errors="replace"),
        )
        self.messages.append(msg)
        self.new_message_event.set()
        self.new_message_event.clear()
        print(f"captured from {msg.peer_host}:{msg.peer_port} helo={msg.helo!r}", flush=True)
        return "250 Message accepted for capture"


async def make_app(handler: CaptureHandler) -> web.Application:
    app = web.Application()

    async def list_messages(_: web.Request) -> web.Response:
        return web.json_response(
            [m.to_dict() for m in reversed(handler.messages)]
        )

    async def clear_messages(_: web.Request) -> web.Response:
        handler.messages.clear()
        return web.json_response({"cleared": True})

    async def wait_messages(request: web.Request) -> web.Response:
        n = int(request.query.get("n", "1"))
        timeout = float(request.query.get("timeout", "30"))
        deadline = time.monotonic() + timeout
        while len(handler.messages) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return web.json_response(
                    {"error": "timeout", "captured": len(handler.messages)},
                    status=408,
                )
            try:
                await asyncio.wait_for(
                    handler.new_message_event.wait(), timeout=remaining
                )
            except TimeoutError:
                pass
        return web.json_response(
            [m.to_dict() for m in handler.messages[:n]]
        )

    async def healthz(_: web.Request) -> web.Response:
        return web.Response(text="ok")

    app.router.add_get("/messages", list_messages)
    app.router.add_delete("/messages", clear_messages)
    app.router.add_get("/messages/wait", wait_messages)
    app.router.add_get("/healthz", healthz)
    return app


async def main() -> None:
    handler = CaptureHandler()
    controller = Controller(handler, hostname="0.0.0.0", port=25)
    controller.start()
    print("SMTP capture listening on :25", flush=True)

    app = await make_app(handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 8025)
    await site.start()
    print("HTTP API listening on :8025", flush=True)

    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main())
