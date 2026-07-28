"""Data-plane tunnel client: the agent side of the multiplexed WebSocket.

While an internal hunt is running (the heartbeat says ``tunnel_required``), the agent
holds one outbound WebSocket to ares. ares opens logical streams over it to internal
hosts; the agent dials each one locally and relays the bytes.

Two kinds of destination are authorized, and the agent is the one that decides:

* an **IP literal** must fall inside the agent's own registered networks, exactly as it
  always has, so a discovered host can only be reached inside the ranges this agent was
  registered for;
* a **hostname** is resolved *here*, on the agent's resolver (that is the whole point: the
  name may only exist on the customer's internal DNS, and split-horizon DNS would give ares
  the wrong answer). It is allowed when every address it resolves to is inside the registered
  networks, or when ares named that host in ``tunnel_allowed_hosts`` on the heartbeat, which
  it only does for the target of a hunt that is actually running. The dial then goes to the
  address we checked, never back through the resolver, so a second lookup cannot swap the
  destination out from under the check.

The frame format mirrors ``ares/infra/net/tunnel.py`` byte for byte; the two repos must
change it together.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
import ssl
import struct
from collections.abc import Iterable

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
_RESOLVE_TIMEOUT = 5.0
_RECONNECT_BACKOFF_MIN = 1.0
_RECONNECT_BACKOFF_MAX = 30.0


def _encode(opcode: int, stream_id: int, payload: bytes = b"") -> bytes:
    return _HEADER.pack(opcode, stream_id) + payload


def _decode(frame: bytes) -> tuple[int, int, bytes]:
    opcode, stream_id = _HEADER.unpack_from(frame)
    return opcode, stream_id, frame[_HEADER.size :]


def _dedupe(values: Iterable[str]) -> list[str]:
    """The values in first-seen order, without duplicates."""
    seen: set[str] = set()
    return [v for v in values if not (v in seen or seen.add(v))]


def tunnel_url(base_url: str) -> str:
    """Derive the WebSocket tunnel URL from the control-plane base URL."""
    ws = base_url.rstrip("/")
    if ws.startswith("https://"):
        ws = "wss://" + ws[len("https://") :]
    elif ws.startswith("http://"):
        ws = "ws://" + ws[len("http://") :]
    return f"{ws}/api/v1/agent/tunnel"


def normalize_host(host: str) -> str:
    """Comparable form of a hostname: lowercase, no trailing root dot."""
    return host.strip().rstrip(".").lower()


class Refused(Exception):
    """The destination is not authorized for this agent; the message is the log reason."""


class TunnelClient:
    """One connected WebSocket. Lives for as long as the connection; reconnect is the
    manager's job.

    ``allowed_hosts`` is shared with the :class:`TunnelManager` and mutated in place as the
    heartbeat pushes a new set, so a hunt starting or ending never costs a reconnect.
    """

    def __init__(
        self,
        url: str,
        token: str,
        allowed_networks: list[str],
        allowed_hosts: set[str],
        *,
        insecure: bool,
    ) -> None:
        self._url = url
        self._token = token
        self._insecure = insecure
        self._allowed = [ipaddress.ip_network(n, strict=False) for n in allowed_networks]
        self._allowed_hosts = allowed_hosts
        self._writers: dict[int, asyncio.StreamWriter] = {}
        self._ws: websockets.ClientConnection | None = None

    def _in_allowed_networks(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False  # fail closed: an address we cannot parse is never "inside"
        return any(ip in net for net in self._allowed)

    async def _dial_address(self, host: str, port: int) -> str:
        """The address to dial for ``host``, or raise :class:`Refused`.

        An IP literal must be inside the registered networks. A hostname is resolved here and
        allowed when *every* address it resolves to is inside them, or when ares pushed the name
        for a running hunt. Returning a concrete address (not the name) is what keeps the check
        and the connect on the same destination.
        """
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            if not self._in_allowed_networks(host):
                raise Refused(f"{host} is outside this agent's registered networks")
            return host
        addresses = await self._resolve(host, port)
        if all(self._in_allowed_networks(a) for a in addresses):
            return addresses[0]
        if normalize_host(host) in self._allowed_hosts:
            return addresses[0]
        raise Refused(
            f"{host} resolves outside this agent's registered networks "
            f"({', '.join(addresses)}) and is not an approved target of a running assessment"
        )

    async def _resolve(self, host: str, port: int) -> list[str]:
        """Resolve ``host`` on this agent's resolver; deduplicated, order preserved."""
        try:
            infos = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
                _RESOLVE_TIMEOUT,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise Refused(f"{host} did not resolve on this agent: {exc}") from exc
        addresses = _dedupe(str(info[4][0]) for info in infos)
        if not addresses:
            raise Refused(f"{host} resolved to no address on this agent")
        return addresses

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
                    if not isinstance(message, bytes):
                        continue
                    try:
                        await self._handle(message)
                    except Exception as exc:  # noqa: BLE001 - one bad frame must not drop the tunnel
                        logger.warning("error handling tunnel frame: %s", exc)
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
        try:
            target = json.loads(payload)
            host, port = str(target["host"]), int(target["port"])
        except (ValueError, KeyError, TypeError) as exc:
            logger.warning("ignoring malformed OPEN frame: %s", exc)
            await self._send(_encode(_OPEN_ERR, stream_id))
            return
        try:
            address = await self._dial_address(host, port)
        except Refused as exc:
            logger.warning("refused tunnel target: %s", exc)
            await self._send(_encode(_OPEN_ERR, stream_id))
            return
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(address, port), timeout=_DIAL_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError) as exc:
            logger.info("tunnel dial to %s:%d failed: %s", address, port, exc)
            await self._send(_encode(_OPEN_ERR, stream_id))
            return
        if address != host:
            logger.info("tunnel dialed %s:%d for %s", address, port, host)
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

    Driven by the heartbeat: ``sync(tunnel_required, allowed_hosts)`` each beat. While required,
    a supervisor keeps a ``TunnelClient`` connected, reconnecting with backoff if the socket
    drops; when no longer required, it is cancelled. The pushed host set is updated in place, so
    the live client sees the current one without reconnecting.
    """

    def __init__(self, url: str, token: str, allowed_networks: list[str], *, insecure: bool) -> None:
        self._allowed_hosts: set[str] = set()
        self._args = (url, token, allowed_networks, self._allowed_hosts)
        self._insecure = insecure
        self._task: asyncio.Task[None] | None = None

    def sync(self, required: bool, allowed_hosts: Iterable[str] = ()) -> None:
        pushed = {normalize_host(h) for h in allowed_hosts if h and h.strip()}
        if pushed != self._allowed_hosts:
            logger.info("tunnel hostname destinations: %s", ", ".join(sorted(pushed)) or "none")
        self._allowed_hosts.clear()
        self._allowed_hosts.update(pushed)
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
        backoff = _RECONNECT_BACKOFF_MIN
        while True:
            try:
                await TunnelClient(*self._args, insecure=self._insecure).run()
                backoff = _RECONNECT_BACKOFF_MIN  # clean close; the next reconnect starts fresh
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - reconnect on any transport error
                logger.warning("tunnel disconnected: %s; reconnecting in %.0fs", exc, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, _RECONNECT_BACKOFF_MAX)
