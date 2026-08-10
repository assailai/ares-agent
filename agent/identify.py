"""Identity evidence for a live host: what is this box, and what is it called?

The port sweep in :mod:`agent.scan` only ever learns "this ip:port answered", which is why the
dashboard could show ``10.1.0.4:2379`` and nothing else. This module runs as a third phase, once
per *live* host, and gathers the raw signals a name can be derived from:

* **reverse DNS** - the customer's own resolver is where internal device names actually live, so a
  PTR is the closest thing to an authoritative answer. Missing PTRs are extremely common, so this
  is a best-effort source, never a required one.
* **the host's /etc/hosts** - :mod:`agent.hostpins` already parses the mounted host file into
  ``{name: [address]}`` for dialling; inverting it is free and covers names DNS will not answer.
* **the TLS certificate** - a device's cert usually carries its real FQDN in the subject or a SAN.
  This is the highest-value source on a VMware estate, where every host serves 443 and 902.
* **an HTTP probe** - the page title, ``Server`` header and any redirect target say what *product*
  is running, which is mostly a signal about the host's role rather than its name.
* **NetBIOS** - a NBSTAT query names Windows machines that have no PTR, which is most of them on a
  network where DHCP does not register clients.

**This module deliberately does not decide anything.** It collects evidence and hands it back
verbatim; ares turns evidence into a name and a device role. In particular the TLS certificate is
shipped as raw DER rather than a parsed CN, because the parsing rules (which SAN to prefer, which
vendor default subjects to reject) change far more often than the agent fleet updates, and ares
already has a real x509 library. An agent that guessed names itself would freeze our naming rules
at whatever version each customer happens to be running.

Every probe is individually failable, individually disableable, and bounded by its own timeout: a
network where nothing answers must cost the scan a bounded amount of time, not stall it.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import re
import socket
import ssl
import struct
from dataclasses import dataclass, field

logger = logging.getLogger("ares.agent.identify")

# Ports whose certificate is worth reading, in preference order. Deliberately short: a host with
# twenty open ports must not cost twenty handshakes, and the first cert a device presents is
# almost always the one carrying its name. 902 is VMware's authd, which serves a cert too.
TLS_PORTS: tuple[int, ...] = (443, 8443, 902, 636, 5986, 993, 995, 8006, 5480)
# Ports worth one plain GET. Ordered so the canonical web surface wins over an admin sidecar.
HTTP_PORTS: tuple[int, ...] = (443, 80, 8443, 8080, 8000, 8081, 8888, 5000, 9000, 3000)
# Ports we treat as speaking TLS when probing over HTTP.
_HTTPS_PORTS: frozenset[int] = frozenset({443, 8443, 5986, 8006, 5480, 9443})
# At most this many certificate reads and this many HTTP probes per host, so a host that listens
# on everything costs the same as a host that listens on two things.
MAX_TLS_PROBES = 2
MAX_HTTP_PROBES = 2
# Cap on the certificate we ship. A normal leaf is 1-2 KiB; anything past this is a device doing
# something strange and is not worth the bytes on a report carrying hundreds of hosts.
MAX_CERT_BYTES = 8192
# Cap on the response bytes read while looking for a <title>. The tag is in the <head>, so the
# first few KiB is generous; this bounds a device that streams forever.
MAX_HTTP_BYTES = 16384
# NetBIOS name service. UDP, so a network that drops it costs exactly one timeout.
NBSTAT_PORT = 137

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
# NetBIOS pads names to 15 chars + a 1-byte suffix; suffix 0x00 on a unique name is the machine.
_NB_NAME_LEN = 15
_NB_ENTRY_LEN = 18


@dataclass(slots=True)
class ServiceEvidence:
    """What one ``(ip, port)`` said about itself."""

    port: int
    tls_cert_der: str | None = None  # base64 DER, so it survives JSON
    http_title: str | None = None
    http_server: str | None = None
    http_status: int | None = None
    http_location: str | None = None
    http_auth_realm: str | None = None

    def is_empty(self) -> bool:
        return not any(
            (
                self.tls_cert_der,
                self.http_title,
                self.http_server,
                self.http_status,
                self.http_location,
                self.http_auth_realm,
            )
        )

    def as_payload(self) -> dict:
        payload: dict = {"port": self.port}
        for key in (
            "tls_cert_der",
            "http_title",
            "http_server",
            "http_status",
            "http_location",
            "http_auth_realm",
        ):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        return payload


@dataclass(slots=True)
class HostEvidence:
    """Everything one host said about itself, across all its probed services."""

    ip: str
    ptr_name: str | None = None
    hosts_file_name: str | None = None
    netbios_name: str | None = None
    services: list[ServiceEvidence] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not any((self.ptr_name, self.hosts_file_name, self.netbios_name, self.services))

    def as_payload(self) -> dict:
        payload: dict = {"ip": self.ip}
        for key in ("ptr_name", "hosts_file_name", "netbios_name"):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        if self.services:
            payload["services"] = [s.as_payload() for s in self.services]
        return payload


def _unverified_tls_context() -> ssl.SSLContext:
    """A context that completes a handshake with anything and verifies nothing.

    Deliberately NOT ``agent.tlsconf.build_trust``: that builds the *verifying* trust used to talk
    to ares, where a bad certificate must fail. Here a self-signed or expired certificate is the
    normal case (it is most of an internal estate) and is exactly what we want to read, so
    verification would throw away the evidence we came for.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def reverse_dns(ip: str, *, timeout: float) -> str | None:
    """The PTR name for ``ip`` on this agent's resolver, or ``None``.

    ``NI_NAMEREQD`` makes a missing PTR an error rather than the address echoed back as a "name",
    which is the difference between "no name" and a name that is a lie.

    The caller MUST bound how many of these run at once. ``loop.getnameinfo`` dispatches to
    asyncio's default thread pool, and a timeout here cancels the await but not the thread, so an
    internal resolver that black-holes queries would otherwise pin every worker in that shared
    pool and stall unrelated agent work.
    """
    loop = asyncio.get_running_loop()
    try:
        name, _ = await asyncio.wait_for(
            loop.getnameinfo((ip, 0), socket.NI_NAMEREQD), timeout=timeout
        )
    except (asyncio.TimeoutError, TimeoutError):
        return None
    except (OSError, UnicodeError):
        # gaierror for "no PTR record", which is the common case on a real network.
        return None
    return name or None


async def tls_certificate(ip: str, port: int, *, timeout: float) -> str | None:
    """Base64 DER of the certificate ``ip:port`` presents, or ``None``.

    ``getpeercert(binary_form=True)`` is not interchangeable with ``getpeercert()`` here: under
    ``CERT_NONE`` the dict form returns ``{}`` (CPython only decodes a certificate it validated),
    so the binary form is the only way to see an unverified peer's certificate at all.

    No SNI is sent, because at this point we have no name to send: an IP literal is not a valid
    SNI value. A vhost that requires SNI therefore answers with its default certificate, which is
    still evidence, just weaker.
    """
    ctx = _unverified_tls_context()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx), timeout=timeout
        )
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            return None
        der = ssl_object.getpeercert(binary_form=True)
    except (asyncio.TimeoutError, TimeoutError):
        return None
    except (OSError, ssl.SSLError, ValueError):
        # a plaintext service on a "TLS" port, a reset, a protocol the peer will not speak.
        return None
    finally:
        if writer is not None:
            await _close(writer)
    if not der or len(der) > MAX_CERT_BYTES:
        if der:
            logger.debug("certificate at %s:%d is %d bytes; too large to report", ip, port, len(der))
        return None
    return base64.b64encode(der).decode("ascii")


async def http_probe(ip: str, port: int, *, timeout: float) -> ServiceEvidence | None:
    """One unauthenticated ``GET /`` against ``ip:port``, kept to what identifies the service.

    Raw asyncio rather than httpx so the request is exactly one plaintext GET with no redirect
    following, no retry and no credential of any kind: this probe must never be able to trip an
    account lockout or a login-failure alert on a customer's device.
    """
    use_tls = port in _HTTPS_PORTS
    ctx = _unverified_tls_context() if use_tls else None
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx), timeout=timeout
        )
        request = (
            f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Ares-Agent\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        )
        writer.write(request.encode("ascii"))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        raw = await asyncio.wait_for(reader.read(MAX_HTTP_BYTES), timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        return None
    except (OSError, ssl.SSLError, ValueError, UnicodeEncodeError):
        return None
    finally:
        if writer is not None:
            await _close(writer)
    return _parse_http(port, raw)


def _parse_http(port: int, raw: bytes) -> ServiceEvidence | None:
    """Pull the identifying bits out of a raw HTTP response. Returns ``None`` if it is not HTTP."""
    if not raw.startswith(b"HTTP/"):
        return None
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status: int | None = None
    parts = lines[0].split(b" ", 2)
    if len(parts) >= 2:
        try:
            status = int(parts[1])
        except ValueError:
            status = None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, sep, value = line.partition(b":")
        if not sep:
            continue
        headers.setdefault(
            key.strip().decode("latin-1").lower(), value.strip().decode("latin-1")
        )
    title = None
    match = _TITLE_RE.search(body)
    if match:
        title = " ".join(match.group(1).decode("utf-8", "replace").split())[:200] or None
    return ServiceEvidence(
        port=port,
        http_title=title,
        http_server=headers.get("server"),
        http_status=status,
        http_location=headers.get("location"),
        http_auth_realm=headers.get("www-authenticate"),
    )


def build_nbstat_query(transaction_id: int = 0x4152) -> bytes:
    """A NetBIOS node-status (NBSTAT) request for the wildcard name.

    The name is the single character ``*`` padded to 16 bytes and first-level encoded, which is
    NetBIOS's way of asking "whoever you are, list your names".
    """
    header = struct.pack(">HHHHHH", transaction_id, 0x0000, 1, 0, 0, 0)
    padded = b"*" + b"\x00" * 15
    encoded = bytearray()
    for byte in padded:
        encoded.append((byte >> 4) + 0x41)
        encoded.append((byte & 0x0F) + 0x41)
    question = bytes([len(encoded)]) + bytes(encoded) + b"\x00" + struct.pack(">HH", 0x0021, 0x0001)
    return header + question


def parse_nbstat_reply(data: bytes) -> str | None:
    """The machine name out of an NBSTAT reply, or ``None``.

    The name table starts after the question echo and the resource-record header, and is a count
    byte followed by fixed 18-byte entries (15 chars of name, a 1-byte suffix, 2 flag bytes). We
    want the first unique (not group) entry with suffix ``0x00``, which is the workstation name.
    """
    # 12-byte header + the encoded question (1 length byte + 32 chars + terminator) + type/class,
    # then the RR's own name pointer/copy, type, class, ttl and length.
    offset = 12 + 1 + 32 + 1 + 4
    offset += 1 + 32 + 1 + 4 + 4 + 2  # answer name + type + class + ttl + rdlength
    if len(data) <= offset:
        return None
    count = data[offset]
    offset += 1
    for _ in range(count):
        if len(data) < offset + _NB_ENTRY_LEN:
            return None
        entry = data[offset : offset + _NB_ENTRY_LEN]
        offset += _NB_ENTRY_LEN
        suffix = entry[_NB_NAME_LEN]
        flags = struct.unpack(">H", entry[16:18])[0]
        is_group = bool(flags & 0x8000)
        if suffix != 0x00 or is_group:
            continue
        name = entry[:_NB_NAME_LEN].decode("latin-1").strip().strip("\x00")
        if name:
            return name
    return None


class _NbstatProtocol(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future[bytes]) -> None:
        self._future = future

    def datagram_received(self, data: bytes, addr: tuple) -> None:  # noqa: ARG002
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(exc)


async def netbios_name(ip: str, *, timeout: float) -> str | None:
    """The NetBIOS machine name for ``ip``, or ``None`` when nothing answers.

    UDP and single-shot: a network that filters 137 costs exactly one timeout per host.
    """
    loop = asyncio.get_running_loop()
    future: asyncio.Future[bytes] = loop.create_future()
    transport = None
    try:
        transport, _ = await asyncio.wait_for(
            loop.create_datagram_endpoint(
                lambda: _NbstatProtocol(future), remote_addr=(ip, NBSTAT_PORT)
            ),
            timeout=timeout,
        )
        transport.sendto(build_nbstat_query())
        data = await asyncio.wait_for(future, timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        return None
    except (OSError, ValueError):
        return None
    finally:
        if transport is not None:
            transport.close()
    try:
        return parse_nbstat_reply(data)
    except (IndexError, struct.error, UnicodeDecodeError, binascii.Error):
        return None


def _pick_ports(open_ports: set[int], preferred: tuple[int, ...], limit: int) -> list[int]:
    """The first ``limit`` of ``preferred`` that are actually open on this host."""
    return [p for p in preferred if p in open_ports][:limit]


async def _close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except (OSError, ssl.SSLError, asyncio.TimeoutError, TimeoutError):
        pass


@dataclass(slots=True)
class IdentityProbe:
    """Per-source toggles and timeouts for one scan's identity phase.

    Every source is separately disableable because this phase sends application-layer bytes into a
    customer network, and some estates hold devices (OT controllers, older printers) where the
    right answer is to ask them nothing at all.
    """

    reverse_dns: bool = True
    tls: bool = True
    http: bool = True
    netbios: bool = True
    dns_timeout: float = 2.0
    tls_timeout: float = 3.0
    http_timeout: float = 3.0
    netbios_timeout: float = 1.0
    hosts_file_lookup: object | None = None  # a callable ip -> name | None

    async def run(self, ip: str, open_ports: set[int]) -> HostEvidence:
        """Collect every enabled source for one host, concurrently.

        A failure in any one source is that source returning ``None``; the others still report.
        """
        evidence = HostEvidence(ip=ip)

        if self.hosts_file_lookup is not None:
            try:
                evidence.hosts_file_name = self.hosts_file_lookup(ip)  # type: ignore[operator]
            except Exception:  # noqa: BLE001 - a bad pin table must not cost the whole probe
                logger.debug("hosts-file lookup failed for %s", ip, exc_info=True)

        tls_ports = _pick_ports(open_ports, TLS_PORTS, MAX_TLS_PROBES) if self.tls else []
        http_ports = _pick_ports(open_ports, HTTP_PORTS, MAX_HTTP_PROBES) if self.http else []

        ptr_task = reverse_dns(ip, timeout=self.dns_timeout) if self.reverse_dns else _none()
        # NBSTAT is asked unconditionally when enabled rather than gated on 137 being open: 137 is
        # UDP and the port sweep is TCP-only, so it never appears in ``open_ports``.
        nb_task = netbios_name(ip, timeout=self.netbios_timeout) if self.netbios else _none()
        results = await asyncio.gather(
            ptr_task,
            nb_task,
            *(tls_certificate(ip, p, timeout=self.tls_timeout) for p in tls_ports),
            *(http_probe(ip, p, timeout=self.http_timeout) for p in http_ports),
            return_exceptions=True,
        )

        evidence.ptr_name = _ok(results[0])
        evidence.netbios_name = _ok(results[1])

        by_port: dict[int, ServiceEvidence] = {}
        for port, der in zip(tls_ports, results[2 : 2 + len(tls_ports)]):
            value = _ok(der)
            if value:
                by_port.setdefault(port, ServiceEvidence(port=port)).tls_cert_der = value
        for probe in results[2 + len(tls_ports) :]:
            value = _ok(probe)
            if isinstance(value, ServiceEvidence):
                existing = by_port.get(value.port)
                if existing is None:
                    by_port[value.port] = value
                else:
                    existing.http_title = value.http_title
                    existing.http_server = value.http_server
                    existing.http_status = value.http_status
                    existing.http_location = value.http_location
                    existing.http_auth_realm = value.http_auth_realm
        evidence.services = [s for _, s in sorted(by_port.items()) if not s.is_empty()]
        return evidence


async def _none() -> None:
    return None


def _ok(result: object) -> object:
    """``None`` for a gathered exception, the value otherwise.

    ``return_exceptions=True`` on the gather means one probe raising cannot cancel its siblings;
    this turns that into a plain missing signal.
    """
    if isinstance(result, BaseException):
        return None
    return result
