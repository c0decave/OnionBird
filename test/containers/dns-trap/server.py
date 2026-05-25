"""DNS audit gateway + Tor-DNS forwarder.

Listens on UDP/53. Every query is recorded with a *disposition*:

- `rejected_onion`  .onion queries are answered NXDOMAIN — a .onion that
                    travels through DNS is by definition a leak (it should
                    have gone through SOCKS5 with remote DNS).
- `forwarded`       Clearnet queries are forwarded to the Tor container's
                    DNSPort (default tor:5353) and the answer returned
                    verbatim. This is what closes the TCPSocket pre-resolve
                    leak: TB's local resolver still does the lookup, but
                    that lookup hits Tor — not the system / ISP resolver.
- `nxdomain`        Forward timed out / failed — fail closed.

HTTP API on :8053:
- GET    /queries          -> list of {source, qname, qtype, disposition, ts}
- DELETE /queries          -> clear log
- GET    /healthz          -> 200 OK

Env:
- T0_TOR_DNS_HOST  (default: tor)
- T0_TOR_DNS_PORT  (default: 5353)
- T0_FORWARD_TIMEOUT_S  (default: 4.0)
"""

from __future__ import annotations

import asyncio
import os
import socket
import time
from dataclasses import asdict, dataclass, field

from aiohttp import web
from dnslib import RCODE, DNSRecord

TOR_DNS_HOST = os.environ.get("T0_TOR_DNS_HOST", "tor")
TOR_DNS_PORT = int(os.environ.get("T0_TOR_DNS_PORT", "5353"))
FORWARD_TIMEOUT_S = float(os.environ.get("T0_FORWARD_TIMEOUT_S", "4.0"))


@dataclass
class DNSQuery:
    source: str
    qname: str
    qtype: str
    disposition: str
    timestamp: float = field(default_factory=time.time)


def _is_onion(qname: str) -> bool:
    n = qname.rstrip(".").lower()
    return n.endswith(".onion") or n == "onion"


async def _forward_to_tor(packet: bytes) -> bytes | None:
    """Forward a raw DNS query packet to Tor's DNSPort over UDP.

    Returns the raw response bytes, or None on timeout / failure.
    """
    loop = asyncio.get_running_loop()

    class _Forwarder(asyncio.DatagramProtocol):
        def __init__(self) -> None:
            self.fut: asyncio.Future[bytes] = loop.create_future()

        def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
            if not self.fut.done():
                self.fut.set_result(data)

        def error_received(self, exc: Exception) -> None:
            if not self.fut.done():
                self.fut.set_exception(exc)

    transport: asyncio.DatagramTransport | None = None
    try:
        transport, proto = await loop.create_datagram_endpoint(
            _Forwarder,
            remote_addr=(TOR_DNS_HOST, TOR_DNS_PORT),
        )
        transport.sendto(packet)
        return await asyncio.wait_for(proto.fut, timeout=FORWARD_TIMEOUT_S)
    except (TimeoutError, OSError, socket.gaierror):
        return None
    finally:
        if transport is not None:
            transport.close()


class DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, queries: list[DNSQuery]) -> None:
        self.queries = queries
        self.transport: asyncio.DatagramTransport | None = None
        # Per asyncio docs: hold strong references to background tasks,
        # otherwise the event loop can GC them mid-execution — meaning a
        # query could be silently dropped (no answer to TB, no log entry).
        # For a privacy audit trap, "silently dropped" reads as "no leak
        # attempted" and is exactly the failure mode we cannot tolerate.
        self._tasks: set[asyncio.Task] = set()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        t = asyncio.create_task(self._handle(data, addr))
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def _handle(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            req = DNSRecord.parse(data)
        except Exception as exc:  # noqa: BLE001
            print(f"DNS parse error from {addr[0]}: {exc}", flush=True)
            return

        qname = str(req.q.qname).rstrip(".")
        qtype = str(req.q.qtype)

        if _is_onion(qname):
            disposition = "rejected_onion"
            reply = req.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            answer = reply.pack()
        else:
            forwarded = await _forward_to_tor(data)
            if forwarded is None:
                disposition = "nxdomain"
                reply = req.reply()
                reply.header.rcode = RCODE.NXDOMAIN
                answer = reply.pack()
            else:
                disposition = "forwarded"
                answer = forwarded

        self.queries.append(
            DNSQuery(source=addr[0], qname=qname, qtype=qtype, disposition=disposition)
        )
        print(
            f"DNS {disposition:14s} from {addr[0]}: {qname} ({qtype})",
            flush=True,
        )
        if self.transport is not None:
            self.transport.sendto(answer, addr)


async def make_app(queries: list[DNSQuery]) -> web.Application:
    app = web.Application()

    async def list_q(_: web.Request) -> web.Response:
        return web.json_response([asdict(q) for q in queries])

    async def clear_q(_: web.Request) -> web.Response:
        queries.clear()
        return web.json_response({"cleared": True})

    async def healthz(_: web.Request) -> web.Response:
        return web.Response(text="ok")

    app.router.add_get("/queries", list_q)
    app.router.add_delete("/queries", clear_q)
    app.router.add_get("/healthz", healthz)
    return app


async def main() -> None:
    queries: list[DNSQuery] = []
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: DNSProtocol(queries),
        local_addr=("0.0.0.0", 53),
    )
    print(
        f"DNS listening on :53/udp, forwarding clearnet to {TOR_DNS_HOST}:{TOR_DNS_PORT}",
        flush=True,
    )

    app = await make_app(queries)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 8053)
    await site.start()
    print("HTTP API listening on :8053", flush=True)

    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        transport.close()


if __name__ == "__main__":
    asyncio.run(main())
