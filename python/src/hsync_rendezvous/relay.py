"""``rdv/1`` data relay: pair two peers and pump their opaque TLS bytes.

The rendezvous is the only element of a p2p group that is always publicly
reachable, so it is also the only place that can join two peers whose NATs
accept no inbound connection (mobile CGNAT, a hotspot behind a carrier, hotel
Wi-Fi). The relay carries the peers' own TLS session **verbatim**: the node
never terminates it, never sees file names or content, and the two peers still
authenticate each other by certificate pinning. What the node does see is the
pairing (CID ↔ CID) and the byte volume, which is why the relay is opt-in per
node (``--relay``) and bounded by quotas.

Streams
-------
* A listener (the peer that serves: the p2p master) opens one **control** stream
  with ``relay_listen``; the node answers ``relay_listening`` and pushes one
  ``relay_incoming`` per requester. The listener answers with ``relay_ping``
  lines, which keep the QUIC connection alive while no session is running.
* A requester opens a **fresh** stream with ``relay_connect``; the node answers
  ``relay_ok`` and from that byte on the stream is opaque.
* The listener answers each ``relay_incoming`` with a **fresh** stream whose
  first line is ``relay_attach``; from there it is opaque too.

The pump is symmetric: two forwarding tasks, a fixed 64 KiB read buffer,
``drain()`` on both sides (so backpressure reaches the real sender), an idle
timeout per direction and a per-session byte cap. Every counter kept here is an
aggregate — no CID, bucket, IP or port leaves this module.

Consumers: ``hsync_rendezvous.server`` (stream handoff), ``hsync_rendezvous.handler``
(validation/authorization), ``hsync_rendezvous.cli`` (opt-in + quotas) and the
white-box tests.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from hsync_rendezvous.diagnostics import debug_event, debug_log
from hsync_rendezvous.protocol import (
    PROTOCOL_VERSION_RDV,
    RDV_FRAME_ADAPTER,
    RDV_RELAY_ERROR_ADAPTER,
    RDV_RELAY_INCOMING_ADAPTER,
    RDV_RELAY_LISTENING_ADAPTER,
    RDV_RELAY_OK_ADAPTER,
    RdvError,
    RdvRelayAttach,
    RdvRelayConnect,
    RdvRelayError,
    RdvRelayIncoming,
    RdvRelayListen,
    RdvRelayListening,
    RdvRelayOk,
    RdvRelayPing,
)
from hsync_rendezvous.stats import NodeStats

__all__ = [
    "RELAY_ATTACH_TIMEOUT_S",
    "RELAY_BUFFER_BYTES",
    "RELAY_ID_BYTES",
    "PrefixedReader",
    "RelayHandoff",
    "RelayQuotas",
    "RelayRegistry",
]

# Read/write chunk of one bridge. Fixed, so the memory a session can pin is
# bounded by ``sessions * 2 * RELAY_BUFFER_BYTES`` regardless of traffic shape.
RELAY_BUFFER_BYTES = 64 * 1024

# How long a listener has to attach a session the node announced. Long enough
# for a reconnect over a slow uplink, short enough that a dead listener cannot
# pin a pending session (and the requester's stream) indefinitely.
RELAY_ATTACH_TIMEOUT_S = 10.0

# Random session id width (``RelayId`` on the wire is its lowercase hex form).
RELAY_ID_BYTES = 16

# Bytes one control line may occupy (the ``relay_ping`` keepalive). The data
# streams are opaque and never framed, so this bound only protects the control
# stream parser.
_CONTROL_FRAME_BYTES = 1024


@dataclass(slots=True, frozen=True)
class RelayQuotas:
    """Hard bounds applied to the relay, derived from the host or the flags.

    ``session_bytes`` and ``bytes_per_second`` are unlimited when ``0``; the
    session cap is enforced by closing the session (a requester reconnects and
    resumes), the byte rate by throttling the pump (real backpressure).
    """

    max_sessions: int
    max_sessions_per_ip: int
    max_sessions_per_bucket: int
    session_bytes: int = 0
    bytes_per_second: int = 0


@dataclass(slots=True, frozen=True)
class RelayHandoff:
    """A validated relay frame whose work needs the connection's own streams.

    ``RendezvousHandler`` validates and authorizes relay frames (it owns the token
    policy and the record-ownership rules) and returns one of these instead of
    reply bytes; the QUIC stream coroutine then hands the reader/writer to
    :meth:`RelayRegistry.run`. ``authorized=False`` is how a frame whose stream
    is already opaque (``relay_attach``) is refused: the node just closes it.
    """

    model: RdvRelayListen | RdvRelayConnect | RdvRelayAttach
    authorized: bool = True


@dataclass(slots=True)
class _Listener:
    cid: str
    bucket: str
    group: str | None
    peer_ip: str
    writer: Any
    sessions: int = 0


@dataclass(slots=True)
class _Pending:
    listener: _Listener
    dialer_cid: str
    dialer_ip: str
    dialer_reader: Any
    dialer_writer: Any
    bucket: str
    attached: asyncio.Event = field(default_factory=asyncio.Event)
    done: asyncio.Event = field(default_factory=asyncio.Event)
    acceptor: tuple[Any, Any] | None = None
    bytes: int = 0
    reserved: bool = True


class _Bandwidth:
    """Process-wide byte-rate shaper (token bucket, ``await``-based)."""

    def __init__(self, bytes_per_second: int) -> None:
        self._rate = float(bytes_per_second)
        self._tokens = float(bytes_per_second)
        self._stamp = time.monotonic()

    async def take(self, size: int) -> None:
        """Wait until ``size`` bytes may be relayed, then charge them."""
        while True:
            now = time.monotonic()
            self._tokens = min(self._rate, self._tokens + (now - self._stamp) * self._rate)
            self._stamp = now
            if self._tokens >= size:
                self._tokens -= size
                return
            await asyncio.sleep((size - self._tokens) / self._rate)


class PrefixedReader:
    """Reader that replays bytes the frame reader already buffered.

    The NDJSON frame reader may read past the newline of a relay handshake line
    (``relay_attach``/``relay_connect``), and those bytes are the *beginning* of
    the opaque stream: dropping them would corrupt the relayed TLS of any client
    that pipelines its first bytes with the handshake. ``read`` returns the
    buffered prefix first, then delegates to the connection's own reader.
    """

    __slots__ = ("_buffer", "_reader")

    def __init__(self, prefix: bytes, reader: Any) -> None:
        self._buffer = bytearray(prefix)
        self._reader = reader

    async def read(self, size: int = -1) -> bytes:
        """Return buffered bytes first, then read from the wrapped stream."""
        if self._buffer:
            if size is None or size < 0:
                data = bytes(self._buffer)
                self._buffer.clear()
                return data
            data = bytes(self._buffer[:size])
            del self._buffer[:size]
            return data
        return await self._reader.read(size)


class RelayRegistry:
    """Listener registry, session pairing and byte pump (RAM only)."""

    def __init__(
        self,
        *,
        enabled: bool,
        quotas: RelayQuotas,
        stats: NodeStats,
        idle_timeout: float,
        attach_timeout: float = RELAY_ATTACH_TIMEOUT_S,
        ttl: int = 60,
    ) -> None:
        self.enabled = enabled
        self.quotas = quotas
        self.stats = stats
        self._idle_timeout = idle_timeout
        self._attach_timeout = attach_timeout
        self._ttl = ttl
        self._listeners: dict[tuple[str, str], _Listener] = {}
        self._pending: dict[str, _Pending] = {}
        self._sessions = 0
        self._per_ip: dict[str, int] = {}
        self._per_bucket: dict[str, int] = {}
        self._bandwidth = _Bandwidth(quotas.bytes_per_second) if quotas.bytes_per_second else None

    # -- introspection ---------------------------------------------------------

    @property
    def sessions(self) -> int:
        """Number of reserved relay sessions (pending or actively relaying)."""
        return self._sessions

    def has_listener(self, cid: str, bucket: str) -> bool:
        """Whether ``cid`` is currently listening for a relay on ``bucket``."""
        return (cid, bucket) in self._listeners

    # -- entry point -----------------------------------------------------------

    async def run(
        self,
        handoff: RelayHandoff,
        *,
        reader: Any,
        writer: Any,
        peer_ip: str,
    ) -> None:
        """Take over one stream for the validated relay ``handoff``."""
        if not handoff.authorized:
            _close(writer)
            return
        model = handoff.model
        if isinstance(model, RdvRelayListen):
            await self._listen(model, reader=reader, writer=writer, peer_ip=peer_ip)
        elif isinstance(model, RdvRelayConnect):
            await self._connect(model, reader=reader, writer=writer, peer_ip=peer_ip)
        else:
            await self._attach(model, reader=reader, writer=writer, peer_ip=peer_ip)

    # -- listener --------------------------------------------------------------

    async def _listen(
        self,
        model: RdvRelayListen,
        *,
        reader: Any,
        writer: Any,
        peer_ip: str,
    ) -> None:
        """Hold one listener's control stream open and consume its keepalives."""
        key = (model.cid, model.bucket)
        previous = self._listeners.get(key)
        if previous is not None and previous.writer is not writer:
            # A reconnecting peer replaces its own listener: the previous control
            # stream belongs to a connection that is going away.
            self._listeners.pop(key, None)
            _close(previous.writer)
        listener = _Listener(
            cid=model.cid,
            bucket=model.bucket,
            group=model.group,
            peer_ip=peer_ip,
            writer=writer,
        )
        self._listeners[key] = listener
        debug_event("relay listener open", cid=model.cid, bucket=model.bucket)
        try:
            writer.write(_line(_listening(ttl=self._ttl)))
            await writer.drain()
            pending = bytearray()
            while True:
                raw = await _read_line(reader, pending, self._idle_timeout)
                if raw is None:
                    return
                if not _is_ping(raw, model.cid, model.bucket):
                    # The control stream carries only keepalives, so anything
                    # else is a protocol violation: drop the listener.
                    return
        except (asyncio.CancelledError, ConnectionError, TimeoutError, OSError):
            return
        finally:
            if self._listeners.get(key) is listener:
                self._listeners.pop(key, None)
            debug_event("relay listener close", cid=model.cid, bucket=model.bucket)
            _close(writer)

    # -- requester -------------------------------------------------------------

    async def _connect(
        self,
        model: RdvRelayConnect,
        *,
        reader: Any,
        writer: Any,
        peer_ip: str,
    ) -> None:
        """Pair the requester with a listener, then pump until either side ends."""
        listener = self._listeners.get((model.target_cid, model.bucket))
        if listener is None:
            await _refuse(writer, "relay_unavailable")
            return
        if not self._admit(peer_ip, model.bucket):
            await _refuse(writer, "overloaded")
            return
        relay_id = secrets.token_hex(RELAY_ID_BYTES)
        session = _Pending(
            listener=listener,
            dialer_cid=model.cid,
            dialer_ip=peer_ip,
            dialer_reader=reader,
            dialer_writer=writer,
            bucket=model.bucket,
        )
        self._pending[relay_id] = session
        listener.sessions += 1
        try:
            try:
                listener.writer.write(
                    _line(
                        _incoming(
                            relay_id=relay_id,
                            cid=model.cid,
                            expires_in=max(1, int(self._attach_timeout)),
                        )
                    )
                )
                await listener.writer.drain()
            except (ConnectionError, TimeoutError, OSError):
                await _refuse(writer, "relay_unavailable")
                return
            writer.write(_line(_ok(relay_id)))
            await writer.drain()
            try:
                await asyncio.wait_for(session.attached.wait(), self._attach_timeout)
            except TimeoutError:
                debug_event("relay attach timeout", cid=model.cid, bucket=model.bucket)
                return
            await self._pump(session)
        except (asyncio.CancelledError, ConnectionError, TimeoutError, OSError):
            return
        finally:
            self._pending.pop(relay_id, None)
            session.done.set()
            listener.sessions = max(0, listener.sessions - 1)
            self._release(session)
            _close(writer)
            if session.acceptor is not None:
                _close(session.acceptor[1])

    # -- listener side of one session -----------------------------------------

    async def _attach(
        self,
        model: RdvRelayAttach,
        *,
        reader: Any,
        writer: Any,
        peer_ip: str,
    ) -> None:
        """Hand a listener's fresh stream to the pending session it belongs to."""
        session = self._pending.get(model.relay_id)
        if (
            session is None
            or session.listener.cid != model.cid
            or session.listener.bucket != model.bucket
            or session.listener.peer_ip != peer_ip
            or session.acceptor is not None
        ):
            _close(writer)
            return
        session.acceptor = (reader, writer)
        session.attached.set()
        try:
            await session.done.wait()
        except asyncio.CancelledError:
            return

    # -- pump ------------------------------------------------------------------

    async def _pump(self, session: _Pending) -> None:
        """Forward bytes both ways until one direction ends or a bound trips."""
        acceptor_reader, acceptor_writer = session.acceptor  # type: ignore[misc]
        debug_event("relay session open", cid=session.dialer_cid, bucket=session.bucket)
        self.stats.relay_session_opened()
        tasks = [
            asyncio.create_task(
                self._forward(session, session.dialer_reader, acceptor_writer),
                name="relay-forward-dialer",
            ),
            asyncio.create_task(
                self._forward(session, acceptor_reader, session.dialer_writer),
                name="relay-forward-acceptor",
            ),
        ]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.stats.relay_session_closed()
            debug_event(
                "relay session close",
                cid=session.dialer_cid,
                bucket=session.bucket,
                bytes=session.bytes,
            )

    async def _forward(self, session: _Pending, reader: Any, writer: Any) -> None:
        """Copy one direction, enforcing the idle timeout and the byte bounds."""
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(RELAY_BUFFER_BYTES), self._idle_timeout)
            except (TimeoutError, ConnectionError, OSError):
                return
            if not chunk:
                return
            session.bytes += len(chunk)
            if self.quotas.session_bytes and session.bytes > self.quotas.session_bytes:
                debug_event("relay session byte cap", cid=session.dialer_cid, bytes=session.bytes)
                return
            self.stats.relay_bytes(len(chunk))
            if self._bandwidth is not None:
                await self._bandwidth.take(len(chunk))
            try:
                writer.write(chunk)
                await writer.drain()
            except (ConnectionError, TimeoutError, OSError):
                return

    # -- quotas ----------------------------------------------------------------

    def _admit(self, peer_ip: str, bucket: str) -> bool:
        """Reserve one session slot, or report ``overloaded`` (node capacity).

        The global, per-source and per-bucket ceilings mirror the routing-table
        shape: the per-bucket one is what a single bucket cannot rotate around,
        the per-source one what one abusive IP cannot exhaust.
        """
        if self._sessions >= self.quotas.max_sessions:
            return False
        if self._per_ip.get(peer_ip, 0) >= self.quotas.max_sessions_per_ip:
            return False
        if self._per_bucket.get(bucket, 0) >= self.quotas.max_sessions_per_bucket:
            return False
        self._sessions += 1
        self._per_ip[peer_ip] = self._per_ip.get(peer_ip, 0) + 1
        self._per_bucket[bucket] = self._per_bucket.get(bucket, 0) + 1
        return True

    def _release(self, session: _Pending) -> None:
        """Return the reserved session slot exactly once per session."""
        if not session.reserved:
            return
        session.reserved = False
        self._sessions = max(0, self._sessions - 1)
        for counters, key in (
            (self._per_ip, session.dialer_ip),
            (self._per_bucket, session.bucket),
        ):
            current = counters.get(key, 0) - 1
            if current > 0:
                counters[key] = current
            else:
                counters.pop(key, None)

    def close(self) -> None:
        """Drop every listener and pending session (shutdown path)."""
        for session in list(self._pending.values()):
            session.done.set()
            _close(session.dialer_writer)
            if session.acceptor is not None:
                _close(session.acceptor[1])
        self._pending.clear()
        for listener in list(self._listeners.values()):
            _close(listener.writer)
        self._listeners.clear()
        debug_log("relay registry closed")


def _close(writer: Any) -> None:
    """Close a QUIC stream writer, tolerating an already-closed stream."""
    try:
        if not writer.is_closing():
            writer.close()
    except Exception:  # noqa: BLE001 - teardown must never raise
        return


async def _refuse(writer: Any, error: RdvError) -> None:
    """Write a ``relay_error`` line and close the stream."""
    try:
        writer.write(_line(_error(error)))
        await writer.drain()
    except (ConnectionError, TimeoutError, OSError):
        pass
    _close(writer)


async def _read_line(reader: Any, pending: bytearray, idle_timeout: float) -> bytes | None:
    """Read one newline-terminated control frame, or ``None`` on EOF/timeout."""
    while True:
        newline = pending.find(b"\n")
        if newline != -1:
            frame = bytes(pending[:newline])
            del pending[: newline + 1]
            return frame
        if len(pending) > _CONTROL_FRAME_BYTES:
            return None
        try:
            chunk = await asyncio.wait_for(reader.read(1024), idle_timeout)
        except (TimeoutError, ConnectionError, OSError):
            return None
        if not chunk:
            return None
        pending.extend(chunk)


def _is_ping(raw: bytes, cid: str, bucket: str) -> bool:
    """Whether ``raw`` is a ``relay_ping`` for this listener (never logged)."""
    try:
        frame = RDV_FRAME_ADAPTER.validate_json(raw)
    except Exception:  # noqa: BLE001 - any validation failure is a violation
        return False
    return isinstance(frame, RdvRelayPing) and frame.cid == cid and frame.bucket == bucket


def _line(payload: bytes) -> bytes:
    """Terminate one serialized frame the way ``rdv/1`` NDJSON expects."""
    return payload + b"\n"


def _listening(*, ttl: int) -> bytes:
    return RDV_RELAY_LISTENING_ADAPTER.dump_json(
        RdvRelayListening(protocol_version=PROTOCOL_VERSION_RDV, type="relay_listening", ttl=ttl)
    )


def _incoming(*, relay_id: str, cid: str, expires_in: int) -> bytes:
    return RDV_RELAY_INCOMING_ADAPTER.dump_json(
        RdvRelayIncoming(
            protocol_version=PROTOCOL_VERSION_RDV,
            type="relay_incoming",
            relay_id=relay_id,
            cid=cid,
            expires_in=expires_in,
        )
    )


def _ok(relay_id: str) -> bytes:
    return RDV_RELAY_OK_ADAPTER.dump_json(
        RdvRelayOk(protocol_version=PROTOCOL_VERSION_RDV, type="relay_ok", relay_id=relay_id)
    )


def _error(error: RdvError) -> bytes:
    """Serialize one uniform refusal (never a bucket-existence oracle)."""
    return RDV_RELAY_ERROR_ADAPTER.dump_json(
        RdvRelayError(protocol_version=PROTOCOL_VERSION_RDV, type="relay_error", error=error)
    )
