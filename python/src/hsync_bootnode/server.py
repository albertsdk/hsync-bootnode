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
import os
import re
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, cast

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
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
    "load_or_create_identity",
    "load_identity",
    "rotate_identity",
    "IdentityError",
    "build_quic_configuration",
    "start_server",
]

# ALPN protocol advertised on the QUIC handshake (client and server must agree).
BOOT_ALPN = "hsync-boot/1"
# Spec: idle connections are dropped after 30 s.
BOOT_IDLE_TIMEOUT = 30.0
# One boot/1 frame must not exceed 8 KiB (register carries at most 16 endpoints).
MAX_FRAME_BYTES = 8192

# A TLS identity may use Ed25519 (preferred for new identities, ADR-0034) or RSA
# (pre-existing identity files, kept until rotated).
PrivateKey = rsa_key.RSAPrivateKey | ed25519.Ed25519PrivateKey

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
    def fingerprint(self) -> CertificateFingerprint:
        return CertificateFingerprint(ssl_utils.compute_cert_fingerprint(self.certificate))

    @property
    def is_ca(self) -> bool:
        return False


def make_identity(host: str = "0.0.0.0", *, public_hosts: Sequence[str] = ()) -> NodeIdentity:
    """Build a fresh ephemeral self-signed identity for this process (no disk writes)."""
    key = ssl_utils.generate_ed25519_private_key()
    cert = ssl_utils.build_self_signed_certificate(
        key,
        subject_attrs=[x509.NameAttribute(NameOID.COMMON_NAME, "hsync-bootnode")],
        san_list=_sans_for(host, public_hosts),
        validity_days=365,
        basic_constraints_ca=False,
    )
    return NodeIdentity(certificate=cert, private_key=key)


def load_or_create_identity(
    path: str | Path,
    *,
    host: str = "0.0.0.0",
    public_hosts: Sequence[str] = (),
) -> NodeIdentity:
    """Load the persistent identity at ``path``, generating it on first use.

    The file is a combined PEM (certificate followed by the unencrypted PKCS#8
    private key), written with ``0600`` permissions in a ``0700`` directory —
    the same model as SSH host keys. When the file exists it is loaded as-is
    (RSA or Ed25519); when absent a fresh Ed25519 identity is generated and
    written. This is the only code path that ever persists key material; the
    default run stays ephemeral via :func:`make_identity`.
    """
    identity_path = Path(path)
    if identity_path.exists():
        return load_identity(identity_path)

    key = ssl_utils.generate_ed25519_private_key()
    cert = ssl_utils.build_self_signed_certificate(
        key,
        subject_attrs=[x509.NameAttribute(NameOID.COMMON_NAME, "hsync-bootnode")],
        san_list=_sans_for(host, public_hosts),
        validity_days=365,
        basic_constraints_ca=False,
    )
    identity_path.parent.mkdir(parents=True, exist_ok=True, mode=_IDENTITY_DIR_MODE)
    os.chmod(identity_path.parent, _IDENTITY_DIR_MODE)
    payload = (
        ssl_utils.serialize_cert_pem(cert)
        + b"\n"
        + ssl_utils.serialize_private_key_unencrypted(key)
    )
    _atomic_write_identity(identity_path, payload)
    return NodeIdentity(certificate=cert, private_key=key)


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
    key = ssl_utils.generate_ed25519_private_key()
    cert = ssl_utils.build_self_signed_certificate(
        key,
        subject_attrs=[x509.NameAttribute(NameOID.COMMON_NAME, "hsync-bootnode")],
        san_list=_sans_for(host, public_hosts),
        validity_days=365,
        basic_constraints_ca=False,
    )
    payload = (
        ssl_utils.serialize_cert_pem(cert)
        + b"\n"
        + ssl_utils.serialize_private_key_unencrypted(key)
    )
    _atomic_write_identity(identity_path, payload)
    return NodeIdentity(certificate=cert, private_key=key)


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
    """
    try:
        data = identity_path.read_bytes()
    except OSError as exc:
        raise IdentityError(f"could not read identity file {identity_path}: {exc}") from exc
    cert_match = _CERT_PEM_RE.search(data)
    key_match = _KEY_PEM_RE.search(data)
    if cert_match is None or key_match is None:
        raise IdentityError(
            f"identity file {identity_path} must contain a certificate and a "
            "PKCS#8 private key (run 'identity rotate' to regenerate it)"
        )
    cert = x509.load_pem_x509_certificate(cert_match.group(0))
    key = serialization.load_pem_private_key(key_match.group(0), password=None)
    if not isinstance(key, (rsa_key.RSAPrivateKey, ed25519.Ed25519PrivateKey)):
        raise IdentityError(f"identity file {identity_path} has an unsupported key type")
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

    def _observed_peer(self) -> tuple[str, int]:
        """Observed source endpoint, or a placeholder before the first datagram."""
        return self.peer_addr if self.peer_addr is not None else ("0.0.0.0", 0)

    def _spawn_stream(self, reader: Any, writer: Any) -> None:
        peer = self._observed_peer()
        debug_event("session open", peer=f"{peer[0]}:{peer[1]}")
        asyncio.create_task(self._serve_stream(reader, writer))

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
        finally:
            debug_event("session close", peer=f"{peer_ip}:{peer_port}")
            if not writer.is_closing():
                writer.close()


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
