"""QUIC/UDP transport for ``boot/1`` (aioquic).

The transport is a thin adapter around aioquic: it handles the single
QUIC/UDP listener, the mandatory RETRY + address-validation tokens (``retry``
aioquic flag), per-connection peer tracking (STUN-echo source) and the
NDJSON-over-bidi-stream framing. All business rules live in
``hsync_bootnode.handler.BootHandler`` and are fully testable without sockets.

TLS identity: a self-signed certificate built from ``hsync_common.ssl_utils``
(ECDSA P-256 — ADR-0037). It persists by default at a state path (``0600`` in a
``0700`` directory) so its fingerprint is stable and pin-able across restarts;
``run --ephemeral`` keeps it in memory instead. Either way, no peer data is ever
written to disk (no-log).
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import time
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, QuicEvent
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hsync_common import ssl_utils

from hsync_bootnode.diagnostics import debug_event, error_event, warn_event
from hsync_bootnode.handler import BootHandler
from hsync_bootnode.ratelimit import TokenBucketLimiter

__all__ = [
    "BOOT_ALPN",
    "BOOT_IDLE_TIMEOUT",
    "CONNECTION_ACTIVE_MAX_PER_IP",
    "HANDSHAKE_BURST_PER_IP",
    "HANDSHAKE_RATE_PER_SECOND",
    "MAX_FRAME_BYTES",
    "BootQuicProtocol",
    "ConnectionGuard",
    "IdentityError",
    "NodeIdentity",
    "build_quic_configuration",
    "load_identity",
    "load_or_create_identity",
    "make_identity",
    "rotate_identity",
    "start_server",
]

# ALPN protocol advertised on the QUIC handshake (client and server must agree).
BOOT_ALPN = "hsync-boot/1"
# Spec: idle connections are dropped after 30 s.
BOOT_IDLE_TIMEOUT = 30.0
# One boot/1 frame must not exceed 8 KiB (register carries at most 16 endpoints).
MAX_FRAME_BYTES = 8192

# Per-IP handshake admission and open-connection cap; RETRY only stops
# *amplified* (spoofed) handshakes, so the node needs its own budget — full
# rationale and sizing in the ConnectionGuard docstring.
HANDSHAKE_RATE_PER_SECOND = 30
HANDSHAKE_BURST_PER_IP = 100
CONNECTION_ACTIVE_MAX_PER_IP = 256

# HSYNC service identities are always ECDSA P-256 (ADR-0037).
PrivateKey = ec.EllipticCurvePrivateKey

# PEM block extractors for the combined ``identity.pem`` (cert + private key).
_CERT_PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)
_KEY_PEM_RE = re.compile(rb"-----BEGIN PRIVATE KEY-----.+?-----END PRIVATE KEY-----", re.DOTALL)

# Identity file/dir permissions: a long-lived private key must not be world-readable.
_IDENTITY_FILE_MODE = 0o600
_IDENTITY_DIR_MODE = 0o700


class NodeIdentity:
    """TLS identity (self-signed cert + private key), ephemeral or persistent."""

    def __init__(
        self,
        certificate: x509.Certificate,
        private_key: PrivateKey,
    ) -> None:
        self.certificate = certificate
        self.private_key = private_key

    @property
    def fingerprint(self) -> str:
        return ssl_utils.compute_cert_fingerprint(self.certificate)

    @property
    def expires_at(self) -> datetime:
        """The certificate's ``NotAfter`` (UTC) — when the pinned identity lapses."""
        return self.certificate.not_valid_after_utc


def _generate_identity(host: str, public_hosts: Sequence[str]) -> NodeIdentity:
    """Build a fresh in-memory ECDSA P-256 identity (no disk writes).

    One constructor for every path (`make_identity`, first-use creation,
    rotation) so the subject, SANs and validity can never drift between them.
    """
    key = ssl_utils.generate_ecdsa_private_key()
    cert = ssl_utils.build_self_signed_certificate(
        key,
        subject_attrs=[x509.NameAttribute(NameOID.COMMON_NAME, "hsync-bootnode")],
        san_list=_sans_for(host, public_hosts),
        validity_days=ssl_utils.SERVICE_CERT_VALIDITY_DAYS,
        basic_constraints_ca=False,
    )
    return NodeIdentity(certificate=cert, private_key=key)


def _identity_pem(identity: NodeIdentity) -> bytes:
    """Serialize a combined cert + unencrypted PKCS#8 key PEM payload."""
    return (
        ssl_utils.serialize_cert_pem(identity.certificate)
        + b"\n"
        + ssl_utils.serialize_private_key_unencrypted(identity.private_key)
    )


def make_identity(host: str = "0.0.0.0", *, public_hosts: Sequence[str] = ()) -> NodeIdentity:
    """Build a fresh in-memory self-signed identity (no disk writes).

    Used by ``run --ephemeral`` (read-only filesystems, throwaway nodes) and by
    tests; the default run persists the identity via :func:`load_or_create_identity`.
    """
    return _generate_identity(host, public_hosts)


def load_or_create_identity(
    path: str | Path,
    *,
    host: str = "0.0.0.0",
    public_hosts: Sequence[str] = (),
) -> NodeIdentity:
    """Load the persistent identity at ``path``, generating it on first use.

    The file is a combined PEM (certificate followed by the unencrypted PKCS#8
    private key), written with ``0600`` permissions in a ``0700`` directory — the
    same model as SSH host keys. When the file exists it is loaded as-is; when
    absent a fresh ECDSA P-256 identity is generated and written. This is the
    default code path: :func:`make_identity` is used only for ``run --ephemeral``.
    """
    identity_path = Path(path)
    if identity_path.exists():
        return load_identity(identity_path)

    identity = _generate_identity(host, public_hosts)
    identity_path.parent.mkdir(parents=True, exist_ok=True, mode=_IDENTITY_DIR_MODE)
    os.chmod(identity_path.parent, _IDENTITY_DIR_MODE)
    _atomic_write_identity(identity_path, _identity_pem(identity))
    return identity


def rotate_identity(
    path: str | Path,
    *,
    host: str = "0.0.0.0",
    public_hosts: Sequence[str] = (),
) -> NodeIdentity:
    """Regenerate the persistent identity at ``path`` with a fresh key.

    Preserves the certificate SANs (from the explicit ``host``/``public_hosts``
    arguments); the old certificate is replaced atomically. The caller must
    distribute the new fingerprint to clients (two-pin rotation window).
    """
    identity_path = Path(path)
    if not identity_path.exists():
        raise IdentityError(f"identity file {identity_path} does not exist; nothing to rotate")
    load_identity(identity_path)  # fail early if the current file is unusable
    identity = _generate_identity(host, public_hosts)
    _atomic_write_identity(identity_path, _identity_pem(identity))
    return identity


def load_identity(path: str | Path) -> NodeIdentity:
    """Load a persistent identity from a combined cert+key PEM file (read-only)."""
    identity_path = Path(path)
    if not identity_path.exists():
        raise IdentityError(f"identity file {identity_path} does not exist")
    return _load_identity_file(identity_path)


def _load_identity_file(identity_path: Path) -> NodeIdentity:
    """Parse a combined cert+key PEM file into a :class:`NodeIdentity`.

    Fails with a clear error when the file does not contain both a certificate
    and an unencrypted PKCS#8 private key (never falls back to a fresh identity,
    which would silently rotate the pinned fingerprint).

    Unattended daemons need the key readable without a passphrase, so the
    *at-rest* protection is file permission: on load, a group/world-readable
    key file is re-chmodded to 0600 and the operator is warned once (the
    identity is the node's impersonation anchor — a leaked key lets an attacker
    take its fingerprint over).
    """
    try:
        data = identity_path.read_bytes()
    except OSError as exc:
        raise IdentityError(f"could not read identity file {identity_path}: {exc}") from exc
    try:
        mode = identity_path.stat().st_mode & 0o777
    except OSError as exc:
        raise IdentityError(f"could not stat identity file {identity_path}: {exc}") from exc
    if mode != _IDENTITY_FILE_MODE:
        try:
            os.chmod(identity_path, _IDENTITY_FILE_MODE)
            warn_event(
                "identity file permissions hardened",
                path=str(identity_path),
                reason=f"mode {oct(mode)} -> 0600",
            )
        except OSError as exc:
            error_event(
                "identity file permissions could not be hardened",
                path=str(identity_path),
                reason=type(exc).__name__,
            )
    cert_match = _CERT_PEM_RE.search(data)
    key_match = _KEY_PEM_RE.search(data)
    if cert_match is None or key_match is None:
        raise IdentityError(
            f"identity file {identity_path} must contain a certificate and a "
            "PKCS#8 private key (run 'identity rotate' to regenerate it)"
        )
    cert = x509.load_pem_x509_certificate(cert_match.group(0))
    key = serialization.load_pem_private_key(key_match.group(0), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise IdentityError(f"identity file {identity_path} must hold an ECDSA P-256 private key")
    return NodeIdentity(certificate=cert, private_key=key)


def _atomic_write_identity(identity_path: Path, payload: bytes) -> None:
    """Write the identity file atomically with owner-only permissions."""
    tmp = identity_path.with_name(f".{identity_path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _IDENTITY_FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, _IDENTITY_FILE_MODE)
        os.replace(tmp, identity_path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _sans_for(host: str, public_hosts: Sequence[str]) -> list[x509.GeneralName]:
    """Build the SAN list: every ``--public-host`` plus the bind address.

    A bind address of ``0.0.0.0``/``::`` has no usable IP SAN, so it falls back to
    the fixed DNS name ``hsync-bootnode`` (the out-of-band pin is what actually
    authenticates the node, not the SAN).
    """
    sans: list[x509.GeneralName] = []
    for name in public_hosts:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            sans.append(x509.DNSName(name))
    if host not in ("0.0.0.0", "::"):
        sans.append(x509.IPAddress(ipaddress.ip_address(host)))
    else:
        sans.append(x509.DNSName("hsync-bootnode"))
    return sans


class IdentityError(RuntimeError):
    """The persistent identity file could not be loaded or written safely."""


class ConnectionGuard:
    """Per-IP transport admission gate for one listener process (RAM only).

    Two controls, both bound to the peer's source IP and never persisted
    (no-log): a token-bucket on new connections (the TLS handshake is the only
    step any RETRY-protected QUIC server cannot refuse for free) and a ceiling
    on simultaneously-open connections (each one may hold up to 128 QUIC
    streams, so unbounded connections also mean unbounded idle-task memory).

    Sizing (see the module constants): the handshake budget stays far above
    what a whole NAT umbrella of legitimate clients can produce — they open a
    connection per exchange and idle out after 30 s — while a single-IP flood
    is throttled to at most ``handshake_burst`` new handshakes per second.
    """

    def __init__(
        self,
        *,
        handshake_rate: float = HANDSHAKE_RATE_PER_SECOND,
        handshake_burst: int = HANDSHAKE_BURST_PER_IP,
        active_max: int = CONNECTION_ACTIVE_MAX_PER_IP,
    ) -> None:
        self._handshakes = TokenBucketLimiter(
            capacity=handshake_burst, refill=handshake_rate, window=1.0
        )
        self._active_max = active_max
        # Seconds an IP must stay quiet (with all of its connections closed)
        # before evict_stale() forgets it: capacity/rate refills the bucket to
        # exactly the first-use value, so forgetting is decision-neutral.
        self._quiet_horizon = handshake_burst / handshake_rate
        # ip -> [open connection count, last seen]
        self._active: dict[str, list[float]] = {}

    def admit(self, peer_ip: str, *, now: float | None = None) -> bool:
        """Admit one new (connecting) connection from ``peer_ip``.

        Returns False when the IP has no handshake budget left or already holds
        ``active_max`` open connections; the caller must then refuse the
        connection instead of running its handshake.
        """
        now = time.monotonic() if now is None else now
        entry = self._active.get(peer_ip)
        if entry is not None and entry[0] >= self._active_max:
            return False
        if not self._handshakes.allow(peer_ip, now=now):
            self._note(peer_ip, now)
            return False
        if entry is None:
            self._active[peer_ip] = [1, now]
        else:
            entry[0] += 1
            entry[1] = now
        return True

    def release(self, peer_ip: str, *, now: float | None = None) -> None:
        """Mark one connection from ``peer_ip`` as closed."""
        entry = self._active.get(peer_ip)
        if entry is None:
            return
        entry[0] = max(0.0, entry[0] - 1.0)
        entry[1] = time.monotonic() if now is None else now

    def open_count(self, peer_ip: str) -> int:
        """Active connections currently accounted for (``0`` when unknown)."""
        entry = self._active.get(peer_ip)
        return int(entry[0]) if entry is not None else 0

    def evict_stale(self, now: float | None = None) -> int:
        """Forget an IP once all of its connections closed and it went quiet.

        A refilled handshake bucket (``capacity / rate`` since last seen)
        behaves identically to a fresh one, so forgetting that IP cannot
        change any decision; this bounds the map under IP churn.
        """
        now = time.monotonic() if now is None else now
        stale = [
            ip
            for ip, entry in self._active.items()
            if entry[0] <= 0 and now - entry[1] >= self._quiet_horizon
        ]
        for ip in stale:
            del self._active[ip]
        return len(stale)

    def _note(self, peer_ip: str, now: float) -> None:
        """Stamp the last-seen time so evict_stale() can reap refused IPs too."""
        entry = self._active.get(peer_ip)
        if entry is not None:
            entry[1] = now


def build_quic_configuration(
    identity: NodeIdentity,
    *,
    idle_timeout: float = BOOT_IDLE_TIMEOUT,
) -> QuicConfiguration:
    """Server-side QUIC/TLS configuration bound to the given TLS identity."""
    config = QuicConfiguration(
        is_client=False,
        alpn_protocols=[BOOT_ALPN],
        idle_timeout=idle_timeout,
    )
    config.certificate = identity.certificate
    config.private_key = identity.private_key
    return config


class BootQuicProtocol(QuicConnectionProtocol):
    """One QUIC/UDP connection; every bidirectional stream is a ``boot/1`` session.

    ``boot_handler`` is bound by :func:`start_server` before the first datagram
    is dispatched (class attribute shared by all connections of the server).
    When a ``ConnectionGuard`` is bound too, a connecting peer is admitted
    against the per-IP handshake budget and active-connection cap before its
    server-side handshake work runs at all (see :meth:`datagram_received`).
    """

    boot_handler: BootHandler

    def __init__(
        self,
        quic: Any,
        stream_handler: Callable[[Any, Any], Any] | None = None,
        guard: ConnectionGuard | None = None,
    ) -> None:
        super().__init__(quic, stream_handler)
        self.guard = guard
        # True once this connection was counted on the guard (one release per
        # admitted connection; the flag makes the count idempotent if QUIC
        # surfaces ConnectionTerminated twice).
        self.admitted_on_guard = False
        self.peer_addr: tuple[str, int] | None = None
        # Strong references to the per-session tasks: aioquic does not await the
        # stream handler, so without this the loop could garbage-collect a
        # running session.
        self._stream_tasks: set[asyncio.Task[None]] = set()
        # Route every new stream to our per-session coroutine instead of the
        # bare callback (aioquic does not await the stream handler itself).
        self._stream_handler = self._spawn_stream

    def datagram_received(self, data: bytes | str, addr: Any) -> None:
        peer_ip = str(addr[0])
        first = self.peer_addr is None
        # Transport admission happens BEFORE any handshake work: a refused IP
        # gets one CONNECTION_CLOSE and nothing else (see _refuse_unadmitted).
        if first:
            guard = self.guard
            if guard is not None:
                if not guard.admit(peer_ip):
                    debug_event("connection refused ip-guard", peer=peer_ip)
                    payload = data.encode("utf-8") if isinstance(data, str) else data
                    self._refuse_unadmitted(payload, addr)
                    return
                self.admitted_on_guard = True
            # Keep the observed source endpoint: it is both the anti-amplification
            # ground truth and the STUN-echo answer (observed NAT-mapped port).
            self.peer_addr = (peer_ip, int(addr[1]))
        super().datagram_received(data, addr)

    def _refuse_unadmitted(self, data: bytes, addr: Any) -> None:
        """Reject an unadmitted connection without running any handshake work.

        aioquic registers a connection's QUIC network path only while processing
        its first datagram, and a CONNECTION_CLOSE cannot be sent without it, so
        the datagram is fed to ``QuicConnection`` at the bookkeeping layer only
        (``receive_datagram`` — no event processing, so no TLS work) and the
        connection is then closed. This is the single place that reaches into
        aioquic's private connection/loop (pinned ``>=1.2.0,<2.0.0``); the
        loopback guard test fails loudly if a future aioquic changes that shape.
        """
        self._quic.receive_datagram(data, addr, now=self._loop.time())
        self.close()

    def quic_event_received(self, event: QuicEvent) -> None:
        # Connection teardown releases the per-IP open-connection slot: the
        # guard's active count must converge to the real connection population.
        if (
            isinstance(event, ConnectionTerminated)
            and self.admitted_on_guard
            and self.guard is not None
        ):
            self.admitted_on_guard = False
            ip = self.peer_addr[0] if self.peer_addr is not None else "0.0.0.0"
            self.guard.release(ip)
        super().quic_event_received(event)

    def _observed_peer(self) -> tuple[str, int]:
        """Observed source endpoint, or a placeholder before the first datagram."""
        return self.peer_addr if self.peer_addr is not None else ("0.0.0.0", 0)

    def _spawn_stream(self, reader: Any, writer: Any) -> None:
        peer = self._observed_peer()
        debug_event("session open", peer=f"{peer[0]}:{peer[1]}")
        task = asyncio.create_task(self._serve_stream(reader, writer))
        self._stream_tasks.add(task)
        task.add_done_callback(self._stream_tasks.discard)

    async def _serve_stream(self, reader: Any, writer: Any) -> None:
        peer_ip, peer_port = self._observed_peer()
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
        except Exception as exc:
            # Unexpected failure in one session: the listener and every other
            # session stay up (isolation), but the operator must still see it —
            # the always-on error channel carries the exception CLASS only, no
            # peer identity. Without this the traceback would reach asyncio's
            # fallback handler in an unformatted, undocumented shape.
            error_event("session failed", exc=type(exc).__name__)
            return
        finally:
            debug_event("session close", peer=f"{peer_ip}:{peer_port}")
            if not writer.is_closing():
                writer.close()


def _protocol_factory(
    handler: BootHandler, guard: ConnectionGuard | None = None
) -> Callable[[Any, Any], Any]:
    """Build the aioquic ``create_protocol`` callable for one shared handler.

    aioquic instantiates one protocol object per QUIC connection; the closure
    binds the process-wide :class:`BootHandler` and the optional :class:`ConnectionGuard`
    to each instance.
    """

    def _create(quic: Any, stream_handler: Any = None) -> BootQuicProtocol:
        protocol = BootQuicProtocol(quic, stream_handler, guard)
        protocol.boot_handler = handler
        return protocol

    return _create


async def start_server(
    host: str,
    port: int,
    handler: BootHandler,
    *,
    retry: bool = True,
    identity: NodeIdentity | None = None,
    idle_timeout: float = BOOT_IDLE_TIMEOUT,
    connection_guard: ConnectionGuard | None = None,
) -> tuple[Any, int, NodeIdentity]:
    """Start the QUIC/UDP listener and return ``(server, bound_port, identity)``.

    ``retry`` enables QUIC RETRY packets + address-validation tokens before any
    connection state is allocated (spec: mandatory, anti-amplification).
    ``connection_guard`` adds the node-side per-IP handshake budget and
    active-connection cap (production: always provided when rate limits are
    enabled; tests may pass ``None`` for an unguarded listener).
    """
    identity = identity or make_identity(host)
    config = build_quic_configuration(identity, idle_timeout=idle_timeout)

    server = await serve(
        host,
        port,
        configuration=config,
        retry=retry,
        create_protocol=_protocol_factory(handler, connection_guard),
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
