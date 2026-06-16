"""Data-plane tunnel client: the agent side of the multiplexed WebSocket.

While an internal hunt is running (the heartbeat says ``tunnel_required``), the agent
holds one outbound WebSocket to ares. ares opens logical streams over it to internal
hosts; the agent dials each one locally and relays the bytes. Every target is checked
against the agent's own network allowlist, so the tunnel can only reach the ranges this
agent was registered for, never arbitrary internal IPs.

The frame format mirrors ``ares/infra/net/tunnel.py`` byte for byte; the two repos must
change it together.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import ssl
import struct

import websockets

logger = logging.getLogger("ares.agent.tunnel")

_OPEN = 1
_OPEN_OK = 2
_OPEN_ERR = 3
_DATA = 4
_CLOSE = 5
_HEADER = struct.Struct(">BQ")
_RELAY_CHUNK = 65536
_DIAL_TIMEOUT = 10.0
_RECONNECT_BACKOFF = 3.0


def _encode(opcode: int, stream_id: int, payload: bytes = b"") -> bytes:
    return _HEADER.pack(opcode, stream_id) + payload


def _decode(frame: bytes) -> tuple[int, int, bytes]:
    opcode, stream_id = _HEADER.unpack_from(frame)
    return opcode, stream_id, frame[_HEADER.size :]


def tunnel_url(base_url: str) -> str:
    """Derive the WebSocket tunnel URL from the control-plane base URL."""
    ws = base_url.rstrip("/")
    if ws.startswith("https://"):
        ws = "wss://" + ws[len("https://") :]
    elif ws.startswith("http://"):
        ws = "ws://" + ws[len("http://") :]
    return f"{ws}/api/v1/agent/tunnel"


class TunnelClient:
    """One connected WebSocket. Lives for as long as the connection; reconnect is the
    manager's job."""

    def __init__(
        self, url: str, token: str, allowed_networks: list[str], *, insecure: bool
    ) -> None:
        self._url = url
        self._token = token
        self._insecure = insecure
        self._allowed = [ipaddress.ip_network(n, strict=False) for n in allowed_networks]
        self._writers: dict[int, asyncio.StreamWriter] = {}
        self._ws: websockets.ClientConnection | None = None

    def _target_allowed(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False  # discovered hosts are IPs; never resolve names through the agent
        return any(ip in net for net in self._allowed)

    async def run(self) -> None:
        ssl_context: ssl.SSLContext | None = None
        if self._url.startswith("wss://"):
            ssl_context = ssl.create_default_context()
            if self._insecure:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
        async with websockets.connect(
            self._url,
            additional_headers={"Authorization": f"Bearer {self._token}"},
            ssl=ssl_context,
            max_size=None,
        ) as ws:
            self._ws = ws
            logger.info("tunnel connected")
            try:
                async for message in ws:
                    if isinstance(message, bytes):
                        await self._handle(message)
            finally:
                for writer in self._writers.values():
                    writer.close()
                self._writers.clear()

    async def _handle(self, frame: bytes) -> None:
        opcode, stream_id, payload = _decode(frame)
        if opcode == _OPEN:
            await self._open(stream_id, payload)
        elif opcode == _DATA:
            writer = self._writers.get(stream_id)
            if writer is not None:
                writer.write(payload)
                await writer.drain()
        elif opcode == _CLOSE:
            writer = self._writers.pop(stream_id, None)
            if writer is not None:
                writer.close()

    async def _open(self, stream_id: int, payload: bytes) -> None:
        target = json.loads(payload)
        host, port = target["host"], int(target["port"])
        if not self._target_allowed(host):
            logger.warning("refused tunnel target outside allowlist: %s", host)
            await self._send(_encode(_OPEN_ERR, stream_id))
            return
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=_DIAL_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError):
            await self._send(_encode(_OPEN_ERR, stream_id))
            return
        self._writers[stream_id] = writer
        await self._send(_encode(_OPEN_OK, stream_id))
        asyncio.create_task(self._relay_to_ares(stream_id, reader))

    async def _relay_to_ares(self, stream_id: int, reader: asyncio.StreamReader) -> None:
        try:
            while True:
                data = await reader.read(_RELAY_CHUNK)
                if not data:
                    break
                await self._send(_encode(_DATA, stream_id, data))
        except OSError:
            pass
        finally:
            self._writers.pop(stream_id, None)
            await self._send(_encode(_CLOSE, stream_id))

    async def _send(self, frame: bytes) -> None:
        if self._ws is not None:
            try:
                await self._ws.send(frame)
            except websockets.ConnectionClosed:
                pass


class TunnelManager:
    """Opens the tunnel while a hunt needs it and tears it down when it does not.

    Driven by the heartbeat: ``sync(tunnel_required)`` each beat. While required, a
    supervisor keeps a ``TunnelClient`` connected, reconnecting with backoff if the
    socket drops; when no longer required, it is cancelled.
    """

    def __init__(self, url: str, token: str, allowed_networks: list[str], *, insecure: bool) -> None:
        self._args = (url, token, allowed_networks)
        self._insecure = insecure
        self._task: asyncio.Task[None] | None = None

    def sync(self, required: bool) -> None:
        running = self._task is not None and not self._task.done()
        if required and not running:
            logger.info("internal hunt active; opening data-plane tunnel")
            self._task = asyncio.create_task(self._supervise())
        elif not required and running:
            logger.info("no internal hunt active; closing data-plane tunnel")
            self.stop()

    def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            self._task = None

    async def _supervise(self) -> None:
        while True:
            try:
                await TunnelClient(*self._args, insecure=self._insecure).run()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - reconnect on any transport error
                logger.warning("tunnel disconnected: %s; reconnecting", exc)
            await asyncio.sleep(_RECONNECT_BACKOFF)
