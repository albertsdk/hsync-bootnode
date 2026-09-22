"""QUIC/UDP transport for ``boot/1`` (aioquic).

The transport is a thin adapter around aioquic: it handles the single
QUIC/UDP listener, the mandatory RETRY + address-validation tokens (``retry``
aioquic flag), per-connection peer tracking (STUN-echo source) and the
NDJSON-over-bidi-stream framing. All business rules live in
``hsync_bootnode.handler.BootHandler`` and are fully testable without sockets.

TLS identity: an in-memory, per-process self-signed certificate built from
``hsync_common.ssl_utils`` — nothing is ever written to disk (no-log).
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Callable
from typing import Any, cast

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_key
from cryptography.x509.oid import NameOID
from hsync_common import ssl_utils

from hsync_bootnode.debug import debug_event
from hsync_bootnode.handler import BootHandler, CertificateFingerprint

__all__ = [
    "BOOT_ALPN",
    "BOOT_IDLE_TIMEOUT",
    "MAX_FRAME_BYTES",
    "NodeIdentity",
    "BootQuicProtocol",
    "make_identity",
    "build_quic_configuration",
    "start_server",
]

# ALPN protocol advertised on the QUIC handshake (client and server must agree).
BOOT_ALPN = "hsync-boot/1"
# Spec: idle connections are dropped after 30 s.
BOOT_IDLE_TIMEOUT = 30.0
# One boot/1 frame must not exceed 8 KiB (register carries at most 16 endpoints).
MAX_FRAME_BYTES = 8192


class NodeIdentity:
    """In-memory TLS identity (self-signed cert + RSA key). Never persisted."""

    def __init__(
        self,
        certificate: x509.Certificate,
        private_key: rsa_key.RSAPrivateKey,
    ) -> None:
        self.certificate = certificate
        self.private_key = private_key

    @property
    def fingerprint(self) -> CertificateFingerprint:
        return CertificateFingerprint(ssl_utils.compute_cert_fingerprint(self.certificate))

    @property
    def is_ca(self) -> bool:
        return False


def make_identity(host: str = "0.0.0.0") -> NodeIdentity:
    """Build a fresh self-signed certificate for this process (no disk writes)."""
    key = ssl_utils.generate_rsa_private_key()
    # cryptography models SANs as a GeneralName union; keep the mypy-visible
    # annotation aligned with what build_self_signed_certificate accepts.
    san: list[x509.IPAddress | x509.DNSName]
    if host not in ("0.0.0.0", "::"):
        san = [x509.IPAddress(ipaddress.ip_address(host))]
    else:
        san = [x509.DNSName("hsync-bootnode")]
    cert = ssl_utils.build_self_signed_certificate(
        key,
        subject_attrs=[x509.NameAttribute(NameOID.COMMON_NAME, "hsync-bootnode")],
        san_list=san,
        validity_days=365,
        basic_constraints_ca=False,
    )
    return NodeIdentity(certificate=cert, private_key=key)


def build_quic_configuration(
    identity: NodeIdentity,
    *,
    idle_timeout: float = BOOT_IDLE_TIMEOUT,
) -> QuicConfiguration:
    """Server-side QUIC/TLS configuration bound to the in-memory identity."""
    config = QuicConfiguration(
        is_client=False,
        alpn_protocols=[BOOT_ALPN],
        idle_timeout=idle_timeout,
    )
    config.certificate = identity.certificate
    config.private_key = identity.private_key
    config.certificate_chain = []
    return config


class BootQuicProtocol(QuicConnectionProtocol):
    """One QUIC/UDP connection; every bidirectional stream is a ``boot/1`` session.

    ``boot_handler`` is bound by :func:`start_server` before the first datagram
    is dispatched (class attribute shared by all connections of the server).
    """

    boot_handler: BootHandler

    def __init__(
        self,
        quic: Any,
        stream_handler: Callable[[Any, Any], Any] | None = None,
    ) -> None:
        super().__init__(quic, stream_handler)
        self.peer_addr: tuple[str, int] | None = None
        # Route every new stream to our per-session coroutine instead of the
        # bare callback (aioquic does not await the stream handler itself).
        self._stream_handler = self._spawn_stream

    def datagram_received(self, data: bytes | str, addr: Any) -> None:
        # Keep the observed source endpoint: it is both the anti-amplification
        # ground truth and the STUN-echo answer (observed NAT-mapped port).
        self.peer_addr = (str(addr[0]), int(addr[1]))
        super().datagram_received(data, addr)

    def _spawn_stream(self, reader: Any, writer: Any) -> None:
        peer = self.peer_addr if self.peer_addr is not None else ("0.0.0.0", 0)
        debug_event("session open", peer=f"{peer[0]}:{peer[1]}")
        asyncio.create_task(self._serve_stream(reader, writer))

    async def _serve_stream(self, reader: Any, writer: Any) -> None:
        peer = self.peer_addr if self.peer_addr is not None else ("0.0.0.0", 0)
        peer_ip: str = str(peer[0])
        peer_port: int = int(peer[1])
        try:
            pending = bytearray()
            while True:
                raw = await _read_frame(reader, pending)
                if raw is None:
                    return  # EOF: normal stream close, not a protocol drop
                response = self.boot_handler.handle(
                    raw,
                    peer_ip=peer_ip,
                    peer_port=peer_port,
                )
                if response is not None:
                    writer.write(response + b"\n")
                    await writer.drain()
        except _OversizedFrame:
            debug_event("drop oversized-frame", peer=f"{peer_ip}:{peer_port}")
            return  # oversized frame: refuse and close the session silently
        except (asyncio.CancelledError, ConnectionError, TimeoutError):
            return
        finally:
            debug_event("session close", peer=f"{peer_ip}:{peer_port}")
            if not writer.is_closing():
                writer.close()

    def close_connection(self, error_code: int = 0, reason: str = "") -> None:
        """Close the whole QUIC connection (idle/termination path)."""
        self.close(error_code=error_code, reason_phrase=reason)


async def start_server(
    host: str,
    port: int,
    handler: BootHandler,
    *,
    retry: bool = True,
    identity: NodeIdentity | None = None,
    idle_timeout: float = BOOT_IDLE_TIMEOUT,
) -> tuple[Any, int, NodeIdentity]:
    """Start the QUIC/UDP listener and return ``(server, bound_port, identity)``.

    ``retry`` enables QUIC RETRY packets + address-validation tokens before any
    connection state is allocated (spec: mandatory, anti-amplification).
    """
    identity = identity or make_identity(host)
    config = build_quic_configuration(identity, idle_timeout=idle_timeout)

    protocol_type = cast(
        Callable[[Any, Any], Any],
        type(
            "BootQuicServerProtocol",
            (BootQuicProtocol,),
            {"boot_handler": handler},
        ),
    )
    server = await serve(
        host,
        port,
        configuration=config,
        retry=retry,
        create_protocol=protocol_type,
    )
    transport = server._transport
    sockname = transport.get_extra_info("sockname") if transport is not None else None
    bound_port = int(sockname[1]) if sockname is not None else int(port)
    return server, bound_port, identity


class _OversizedFrame(Exception):
    """A single frame exceeded MAX_FRAME_BYTES (refused, no-log)."""


async def _read_frame(reader: Any, pending: bytearray) -> bytes | None:
    """Read one newline-terminated frame (bounded to MAX_FRAME_BYTES).

    ``pending`` keeps bytes already received but not yet consumed, so several
    frames sent back-to-back on the same stream are each returned in turn
    (no pipelined frame is ever lost). Returns ``None`` on EOF; raises
    ``_OversizedFrame`` when a single frame exceeds the bound (the session is
    then silently dropped — oversized frames are refused, no-log).
    """
    while True:
        newline = pending.find(b"\n")
        if newline != -1:
            if newline > MAX_FRAME_BYTES:
                raise _OversizedFrame
            frame = bytes(pending[:newline])
            del pending[: newline + 1]
            return frame
        if len(pending) > MAX_FRAME_BYTES:
            # No newline within the bound: the frame is already oversized, and a
            # larger read chunk must not let an oversized frame slip through as a
            # "malformed" one just because its newline arrived in the same read.
            raise _OversizedFrame
        chunk = await reader.read(4096)
        if not chunk:
            return None
        pending.extend(chunk)
