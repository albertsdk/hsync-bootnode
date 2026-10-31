"""White-box tests for the ``rdv/1`` data relay (pairing, pump, quotas).

The registry is driven directly with in-memory stream pairs: the real wire is
covered by the language-neutral black-box suite
(``tests/test_bb_rendezvous_relay.py``), so these tests stay fast and deterministic
while pinning the semantics that are hard to observe from outside (quota
accounting, attach ownership, teardown).
"""

from __future__ import annotations

import asyncio
import json

from hsync_rendezvous.protocol import (
    RdvRelayAttach,
    RdvRelayConnect,
    RdvRelayListen,
    RdvRelayPing,
)
from hsync_rendezvous.relay import PrefixedReader, RelayHandoff, RelayQuotas, RelayRegistry
from hsync_rendezvous.stats import NodeStats

CID = "A1b2C3d4E5f6G7h8I9j0K"
PEER_CID = "L0m1N2o3P4q5R6s7T8u9V"
BUCKET = "shared"
LISTENER_IP = "203.0.113.5"
DIALER_IP = "198.51.100.9"


class _Writer:
    """Writer that hands every chunk to the peer's reader (no transport)."""

    def __init__(self, reader: asyncio.StreamReader) -> None:
        self._reader = reader
        self.closed = False

    def write(self, data: bytes) -> None:
        self._reader.feed_data(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def is_closing(self) -> bool:
        return self.closed


class Side:
    """One peer of the registry: what it sends and what it receives."""

    def __init__(self) -> None:
        self.to_server = asyncio.StreamReader()
        self.from_server = asyncio.StreamReader()
        self.writer = _Writer(self.from_server)

    def send(self, data: bytes) -> None:
        self.to_server.feed_data(data)

    async def line(self) -> dict:
        return json.loads(await asyncio.wait_for(self.from_server.readline(), 2))


def _registry(**kwargs) -> RelayRegistry:
    quotas = kwargs.pop(
        "quotas",
        RelayQuotas(max_sessions=4, max_sessions_per_ip=2, max_sessions_per_bucket=4),
    )
    return RelayRegistry(
        enabled=kwargs.pop("enabled", True),
        quotas=quotas,
        stats=kwargs.pop("stats", None) or NodeStats(),
        idle_timeout=kwargs.pop("idle_timeout", 5.0),
        attach_timeout=kwargs.pop("attach_timeout", 1.0),
    )


def _listen(cid: str = CID) -> RelayHandoff:
    return RelayHandoff(
        RdvRelayListen(protocol_version="rdv/1", type="relay_listen", cid=cid, bucket=BUCKET)
    )


def _connect(target_cid: str = CID) -> RelayHandoff:
    return RelayHandoff(
        RdvRelayConnect(
            protocol_version="rdv/1",
            type="relay_connect",
            cid=PEER_CID,
            bucket=BUCKET,
            target_cid=target_cid,
        )
    )


def _attach(cid: str, relay_id: str) -> RelayHandoff:
    return RelayHandoff(
        RdvRelayAttach(
            protocol_version="rdv/1",
            type="relay_attach",
            cid=cid,
            bucket=BUCKET,
            relay_id=relay_id,
        )
    )


async def _open_listener(registry: RelayRegistry) -> tuple[Side, asyncio.Task]:
    side = Side()
    task = asyncio.create_task(
        registry.run(_listen(), reader=side.to_server, writer=side.writer, peer_ip=LISTENER_IP)
    )
    await asyncio.sleep(0)
    await side.line()
    return side, task


async def test_a_paired_session_forwards_bytes_both_ways() -> None:
    """The node pairs listener and requester and pumps opaque bytes."""
    registry = _registry()
    listener, listener_task = await _open_listener(registry)
    assert registry.has_listener(CID, BUCKET)

    dialer = Side()
    connect_task = asyncio.create_task(
        registry.run(_connect(), reader=dialer.to_server, writer=dialer.writer, peer_ip=DIALER_IP)
    )
    incoming = await listener.line()
    assert incoming["type"] == "relay_incoming"
    assert incoming["cid"] == PEER_CID
    relay_id = incoming["relay_id"]
    assert (await dialer.line())["type"] == "relay_ok"

    acceptor = Side()
    attach_task = asyncio.create_task(
        registry.run(
            _attach(CID, relay_id),
            reader=acceptor.to_server,
            writer=acceptor.writer,
            peer_ip=LISTENER_IP,
        )
    )

    dialer.send(b"hello")
    assert await asyncio.wait_for(acceptor.from_server.readexactly(5), 2) == b"hello"
    acceptor.send(b"world")
    assert await asyncio.wait_for(dialer.from_server.readexactly(5), 2) == b"world"

    for task in (listener_task, connect_task, attach_task):
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_without_a_listener_the_requester_is_refused() -> None:
    """No listener for the target CID: ``relay_unavailable``, nothing allocated."""
    registry = _registry()
    dialer = Side()
    await registry.run(_connect(), reader=dialer.to_server, writer=dialer.writer, peer_ip=DIALER_IP)
    assert (await dialer.line())["error"] == "relay_unavailable"
    assert registry.sessions == 0


async def test_the_session_cap_answers_overloaded() -> None:
    """A node at its session ceiling refuses with ``overloaded``."""
    registry = _registry(
        quotas=RelayQuotas(max_sessions=1, max_sessions_per_ip=1, max_sessions_per_bucket=1)
    )
    listener, listener_task = await _open_listener(registry)
    assert registry._admit(DIALER_IP, BUCKET) is True
    dialer = Side()
    await registry.run(_connect(), reader=dialer.to_server, writer=dialer.writer, peer_ip=DIALER_IP)
    assert (await dialer.line())["error"] == "overloaded"
    assert listener is not None
    listener_task.cancel()
    await asyncio.gather(listener_task, return_exceptions=True)


async def test_an_expired_attach_closes_the_session() -> None:
    """A listener that never attaches makes the session expire, not hang."""
    registry = _registry(attach_timeout=0.05)
    listener, listener_task = await _open_listener(registry)
    dialer = Side()
    await registry.run(_connect(), reader=dialer.to_server, writer=dialer.writer, peer_ip=DIALER_IP)
    await listener.line()  # relay_incoming
    assert (await dialer.line())["type"] == "relay_ok"
    assert registry.sessions == 0  # released by the timeout path
    listener_task.cancel()
    await asyncio.gather(listener_task, return_exceptions=True)


async def test_an_attach_from_another_source_is_closed() -> None:
    """``relay_attach`` must come from the listener that was notified."""
    registry = _registry()
    listener, listener_task = await _open_listener(registry)
    dialer = Side()
    connect_task = asyncio.create_task(
        registry.run(_connect(), reader=dialer.to_server, writer=dialer.writer, peer_ip=DIALER_IP)
    )
    relay_id = (await listener.line())["relay_id"]
    assert (await dialer.line())["type"] == "relay_ok"
    intruder = Side()
    await registry.run(
        _attach(CID, relay_id),
        reader=intruder.to_server,
        writer=intruder.writer,
        peer_ip="192.0.2.77",
    )
    assert intruder.writer.closed is True
    connect_task.cancel()
    listener_task.cancel()
    await asyncio.gather(connect_task, listener_task, return_exceptions=True)


async def test_a_disabled_relay_refuses_every_frame() -> None:
    """A node started with ``--no-relay`` creates no state; the answer is uniform."""
    registry = _registry(enabled=False)
    dialer = Side()
    await registry.run(_connect(), reader=dialer.to_server, writer=dialer.writer, peer_ip=DIALER_IP)
    assert (await dialer.line())["error"] == "relay_unavailable"
    assert registry.has_listener(CID, BUCKET) is False


async def test_a_ping_keeps_the_listener_and_eof_drops_it() -> None:
    """The keepalive keeps the listener alive; a clean EOF withdraws it."""
    registry = _registry()
    listener, listener_task = await _open_listener(registry)
    listener.to_server.feed_data(
        json.dumps(
            {"protocol_version": "rdv/1", "type": "relay_ping", "cid": CID, "bucket": BUCKET}
        ).encode()
        + b"\n"
    )
    await asyncio.sleep(0.05)
    assert listener_task.done() is False
    assert registry.has_listener(CID, BUCKET)
    listener.to_server.feed_eof()
    await asyncio.wait_for(listener_task, 2)
    assert registry.has_listener(CID, BUCKET) is False


async def test_an_unknown_relay_id_attaches_to_nothing() -> None:
    """An unknown ``relay_id`` closes the stream without touching state."""
    registry = _registry()
    side = Side()
    await registry.run(
        _attach(CID, "0" * 32), reader=side.to_server, writer=side.writer, peer_ip=LISTENER_IP
    )
    assert side.writer.closed is True
    assert registry.sessions == 0


def test_the_ping_model_carries_no_optional_fields() -> None:
    """``relay_ping`` stays a bare keepalive (nothing to smuggle on it)."""
    assert set(RdvRelayPing.__annotations__) == {"type", "cid", "bucket"}
    assert "bucket_token" not in RdvRelayPing.model_fields


async def test_a_pipelined_prefix_is_not_lost() -> None:
    """Bytes read past the handshake newline must reach the bridge.

    Regression: the NDJSON frame reader may consume the first opaque bytes
    together with the ``relay_attach`` line; dropping them truncated the relayed
    TLS of any client that pipelined its first record.
    """
    underlying = asyncio.StreamReader()
    underlying.feed_data(b"tail-bytes")
    underlying.feed_eof()
    reader = PrefixedReader(b"head-", underlying)
    assert await reader.read(5) == b"head-"
    assert await reader.read(64) == b"tail-bytes"
    assert await reader.read(64) == b""
    empty = PrefixedReader(b"", underlying)
    assert await empty.read(64) == b""


async def test_an_idle_session_is_dropped_by_the_watchdog() -> None:
    """A session that stalls past the idle timeout closes itself (never hangs).

    The forwarding loop carries no per-chunk timer: the per-session idle watch
    must close both streams after ``idle_timeout`` without traffic, so the two
    pump tasks end and the session is released on their own.
    """
    registry = _registry(idle_timeout=0.2)
    listener, listener_task = await _open_listener(registry)
    dialer = Side()
    connect_task = asyncio.create_task(
        registry.run(_connect(), reader=dialer.to_server, writer=dialer.writer, peer_ip=DIALER_IP)
    )
    incoming = await listener.line()
    assert incoming["type"] == "relay_incoming"
    relay_id = incoming["relay_id"]
    assert (await dialer.line())["type"] == "relay_ok"

    acceptor = Side()
    attach_task = asyncio.create_task(
        registry.run(
            _attach(CID, relay_id),
            reader=acceptor.to_server,
            writer=acceptor.writer,
            peer_ip=LISTENER_IP,
        )
    )

    # Confirm the bridge is live, then stall: no more traffic in either
    # direction, so the idle watchdog must close both streams and end the pump.
    dialer.send(b"hello")
    assert await asyncio.wait_for(acceptor.from_server.readexactly(5), 2) == b"hello"
    await asyncio.wait_for(connect_task, 3.0)
    await asyncio.wait_for(attach_task, 3.0)
    assert registry.sessions == 0
    listener_task.cancel()
    await asyncio.gather(listener_task, return_exceptions=True)
