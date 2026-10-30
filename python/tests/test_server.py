"""QUIC transport tests: identity/config units + real loopback rdv/1 exchanges.

The loopback tests spin up a real aioquic server on 127.0.0.1:0 and talk to it
with a real aioquic client (TLS 1.3, RETRY for the server side): they exercise
the full public contract (register→ack with STUN-echo, query→response,
protected-bucket refusal) exactly as a remote peer would.
"""

from __future__ import annotations

import asyncio
import json
import re
import ssl

import pytest
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from pydantic import SecretStr

from hsync_rendezvous.handler import RendezvousHandler
from hsync_rendezvous.server import (
    RDV_ALPN,
    ConnectionGuard,
    RendezvousQuicProtocol,
    build_quic_configuration,
    make_identity,
    start_server,
    start_servers,
)
from hsync_rendezvous.tokens import derive_bucket_token

CID = "A1b2C3d4E5f6G7h8I9j0K"
FP = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"


def test_make_identity_produces_self_signed_fingerprint() -> None:
    identity = make_identity(host="127.0.0.1")
    assert re.fullmatch(r"[0-9a-f]{64}", str(identity.fingerprint))
    config = build_quic_configuration(identity)
    assert config.alpn_protocols == [RDV_ALPN]
    assert config.certificate is not None
    assert config.private_key is not None


def test_connection_guard_budget_eviction_and_release_are_exact() -> None:
    """ConnectionGuard unit behaviour on an injected clock (deterministic).

    The handshake budget is a plain token bucket: two admissions per burst, the
    third refused until a token refills. Released connections free their
    active-count slot (idempotently), but never their handshake tokens; a quiet
    IP with zero open connections is forgotten once fully refilled.
    """
    guard = ConnectionGuard(handshake_rate=1.0, handshake_burst=2, active_max=10)
    assert guard.admit("10.0.0.1", now=100.0) is True
    assert guard.admit("10.0.0.1", now=100.0) is True
    assert guard.open_count("10.0.0.1") == 2
    # burst exhausted: the third attempt has no handshake token (refusals are
    # still stamped for eviction) and do not touch the active count
    assert guard.admit("10.0.0.1", now=100.1) is False
    assert guard.open_count("10.0.0.1") == 2

    # both connections close: the active count drops (idempotent releases)
    guard.release("10.0.0.1", now=100.5)
    guard.release("10.0.0.1", now=100.6)
    assert guard.open_count("10.0.0.1") == 0
    guard.release("10.0.0.1", now=100.7)  # extra release: no underflow
    assert guard.open_count("10.0.0.1") == 0

    # the handshake bucket keeps refilling (1 token/s): one has refilled by now,
    # so a new connection is admitted while the active count stays released
    assert guard.admit("10.0.0.1", now=101.0) is True
    assert guard.open_count("10.0.0.1") == 1
    guard.release("10.0.0.1", now=102.3)

    # a quiet, empty-and-refilled IP is forgettable: horizon is burst/rate = 2 s
    assert guard.evict_stale(now=103.0) == 0  # last seen 102.3 → too recent
    assert guard.evict_stale(now=104.5) == 1  # quiet ≥ 2 s and empty → forgotten
    assert guard.open_count("10.0.0.1") == 0
    assert guard.admit("10.0.0.1", now=200.0) is True  # fresh start, full bucket


@pytest.mark.asyncio
async def test_loopback_connection_guard_refuses_and_releases() -> None:
    """The guard is enforced on real connections before any handshake work.

    Two connections from 127.0.0.1 fill the (test-sized) active cap; a third is
    refused at transport level; after one closes and releases its slot, another
    connection is admitted again. No frame/handshake of any refused connection
    reaches the handler.
    """
    handler = RendezvousHandler()
    guard = ConnectionGuard(handshake_rate=10_000.0, handshake_burst=10_000, active_max=2)
    server, port, _identity = await start_server(
        "127.0.0.1", 0, handler, retry=True, connection_guard=guard
    )
    try:
        client_config = QuicConfiguration(
            is_client=True, alpn_protocols=[RDV_ALPN], verify_mode=ssl.CERT_NONE
        )

        async def _wait_open(expected: int, timeout: float = 5.0) -> None:
            async def _poll() -> None:
                while guard.open_count("127.0.0.1") != expected:
                    await asyncio.sleep(0.02)

            await asyncio.wait_for(_poll(), timeout)

        # The first two connections fill the active cap; the third is refused.
        async with connect("127.0.0.1", port, configuration=client_config):
            await _wait_open(1)
            async with connect("127.0.0.1", port, configuration=client_config):
                await _wait_open(2)
                with pytest.raises((ConnectionError, TimeoutError, OSError)):
                    async with connect("127.0.0.1", port, configuration=client_config):
                        pass  # the refusal prevents this from completing

            # second's termination reached the server → one slot released
            await _wait_open(1)

        # every termination released its slot
        await _wait_open(0)
        # …so a fresh connection is admitted again
        async with connect("127.0.0.1", port, configuration=client_config) as third:
            await _wait_open(1)
            assert third is not None
    finally:
        server.close()


@pytest.mark.asyncio
async def test_loopback_register_query_and_protected_refusal() -> None:
    handler = RendezvousHandler(
        protected_buckets=("shared",),
        group_keys={"shared": SecretStr("kshared")},
    )
    server, port, _identity = await start_server("127.0.0.1", 0, handler, retry=True)
    try:
        client_config = QuicConfiguration(
            is_client=True, alpn_protocols=[RDV_ALPN], verify_mode=ssl.CERT_NONE
        )
        token = derive_bucket_token(b"kshared", "shared")
        async with connect("127.0.0.1", port, configuration=client_config) as protocol:
            # register on a protected bucket without token → token_required
            response = await _exchange(protocol, _register_frame(None))
            assert response["type"] == "response"
            assert response["error"] == "token_required"

            # register with the correct token → ack with STUN-echo (loopback src)
            response = await _exchange(protocol, _register_frame(token))
            assert response["type"] == "ack"
            assert response["observed_endpoint"]["ip"] == "127.0.0.1"
            assert response["observed_endpoint"]["proto"] == "udp"
            assert response["ttl"] == 60

            # anonymous query → uniform refusal
            response = await _exchange(protocol, _query_frame(None))
            assert response["error"] == "token_required"

            # correct-token query → the peer shows up (advertised endpoint)
            response = await _exchange(protocol, _query_frame(token))
            assert response["error"] is None
            assert response["count"] == 1
            assert response["peers"][0]["cid"] == CID
            assert response["peers"][0]["endpoints"][0]["host"] == "198.51.100.7"
    finally:
        server.close()


@pytest.mark.asyncio
async def test_loopback_multi_port_shares_one_routing_table() -> None:
    """One process, N ports, ONE routing table: a peer registered via one port
    is visible to a query on another port (decision #21 — no sharding)."""
    handler = RendezvousHandler()
    servers, ports, _identity, failures = await start_servers(
        "127.0.0.1", [0, 0], handler, retry=True
    )
    assert len(servers) == 2
    assert len(ports) == 2
    assert ports[0] != ports[1]
    assert failures == []
    try:
        client_config = QuicConfiguration(
            is_client=True, alpn_protocols=[RDV_ALPN], verify_mode=ssl.CERT_NONE
        )
        # register via the FIRST port
        async with connect("127.0.0.1", ports[0], configuration=client_config) as protocol:
            response = await _exchange(protocol, _register_frame(None))
            assert response["type"] == "ack"
        # query via the SECOND port → the peer registered on the first is visible
        async with connect("127.0.0.1", ports[1], configuration=client_config) as protocol:
            response = await _exchange(protocol, _query_frame(None))
            assert response["error"] is None
            assert response["count"] == 1
            assert response["peers"][0]["cid"] == CID
    finally:
        for server in servers:
            server.close()


@pytest.mark.asyncio
async def test_loopback_garbage_frame_is_dropped() -> None:
    handler = RendezvousHandler()
    server, port, _identity = await start_server("127.0.0.1", 0, handler, retry=True)
    try:
        client_config = QuicConfiguration(
            is_client=True, alpn_protocols=[RDV_ALPN], verify_mode=ssl.CERT_NONE
        )
        async with connect("127.0.0.1", port, configuration=client_config) as protocol:
            reader, writer = await protocol.create_stream()
            writer.write(b"{this is not json}\n")
            await writer.drain()
            # the server must drop the malformed frame and NOT answer
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(reader.readline(), timeout=1.0)
            writer.close()
    finally:
        server.close()


async def _exchange(protocol: QuicConnectionProtocol, frame: dict) -> dict:
    reader, writer = await protocol.create_stream()
    writer.write((json.dumps(frame) + "\n").encode("utf-8"))
    await writer.drain()
    raw = await reader.readline()
    writer.close()
    return json.loads(raw)


@pytest.mark.asyncio
async def test_loopback_pipelined_frames_on_one_stream() -> None:
    """Two frames sent back-to-back on one stream each get their own reply."""
    handler = RendezvousHandler()
    server, port, _identity = await start_server("127.0.0.1", 0, handler, retry=True)
    try:
        client_config = QuicConfiguration(
            is_client=True, alpn_protocols=[RDV_ALPN], verify_mode=ssl.CERT_NONE
        )
        async with connect("127.0.0.1", port, configuration=client_config) as protocol:
            reader, writer = await protocol.create_stream()
            payload = (json.dumps(_register_frame(None)) + "\n") + (
                json.dumps(_query_frame(None)) + "\n"
            )
            writer.write(payload.encode("utf-8"))
            await writer.drain()
            first = json.loads(await asyncio.wait_for(reader.readline(), timeout=5.0))
            second = json.loads(await asyncio.wait_for(reader.readline(), timeout=5.0))
            writer.close()
            assert first["type"] == "ack"
            assert second["type"] == "response"
            assert second["count"] == 1
            assert second["peers"][0]["cid"] == CID
    finally:
        server.close()


@pytest.mark.asyncio
async def test_loopback_private_node_requires_token_on_every_bucket() -> None:
    """A private node gates every bucket, not only the declared protected set.

    The handler declares NO protected bucket: the private flag alone must make
    the refusal uniform on the wire.
    """
    handler = RendezvousHandler(private=True, group_keys={"shared": SecretStr("kshared")})
    server, port, _identity = await start_server("127.0.0.1", 0, handler, retry=True)
    try:
        client_config = QuicConfiguration(
            is_client=True, alpn_protocols=[RDV_ALPN], verify_mode=ssl.CERT_NONE
        )
        token = derive_bucket_token(b"kshared", "shared")
        async with connect("127.0.0.1", port, configuration=client_config) as protocol:
            # no token → uniform refusal on register and query
            response = await _exchange(protocol, _register_frame(None))
            assert response["type"] == "response"
            assert response["error"] == "token_required"
            assert response["count"] == 0
            response = await _exchange(protocol, _query_frame(None))
            assert response["error"] == "token_required"

            # valid token → ack (STUN-echo) and peers
            response = await _exchange(protocol, _register_frame(token))
            assert response["type"] == "ack"
            assert response["observed_endpoint"]["proto"] == "udp"
            response = await _exchange(protocol, _query_frame(token))
            assert response["error"] is None
            assert response["count"] == 1
            assert response["peers"][0]["cid"] == CID

            # an unkeyed bucket on the same node is refused like a wrong token
            response = await _exchange(protocol, _query_frame(token, bucket="unkeyed"))
            assert response["error"] == "token_required"
            assert response["count"] == 0
    finally:
        server.close()


@pytest.mark.asyncio
async def test_unexpected_session_failure_is_reported_peer_free(capsys) -> None:
    """A session error is isolated AND visible, without leaking the peer identity.

    The listener must survive (isolation), but the operator has to see the
    failure on the always-on channel — and that channel never carries the peer
    address, even though the failing session knows it.
    """

    protocol = object.__new__(RendezvousQuicProtocol)
    protocol.peer_addr = ("203.0.113.9", 51000)
    protocol.boot_handler = RendezvousHandler()

    class _FailingReader:
        async def read(self, _size: int) -> bytes:
            raise ValueError("boom")

    class _Writer:
        def __init__(self) -> None:
            self.closed = False

        def is_closing(self) -> bool:
            return False

        def write(self, _data: bytes) -> None:
            pass

        async def drain(self) -> None:
            pass

        def close(self) -> None:
            self.closed = True

    writer = _Writer()
    await protocol._serve_stream(_FailingReader(), writer)

    assert writer.closed is True
    err = capsys.readouterr().err
    assert "error: session failed exc=ValueError" in err
    assert "203.0.113.9" not in err
    assert "51000" not in err


@pytest.mark.asyncio
async def test_unexpected_session_failure_detail_is_debug_only(capsys, monkeypatch) -> None:
    """The exception message reaches the operator only on the opt-in debug sink.

    The always-on error line must stay class-only (peer-free by construction);
    ``--debug`` adds the sanitized failure detail that makes the failure
    actionable.
    """
    from collections import deque

    from hsync_rendezvous import diagnostics

    monkeypatch.setattr(diagnostics, "_dedup", {})
    monkeypatch.setattr(diagnostics, "_dedup_order", deque())

    protocol = object.__new__(RendezvousQuicProtocol)
    protocol.peer_addr = ("203.0.113.9", 51000)
    protocol.boot_handler = RendezvousHandler()

    class _FailingReader:
        async def read(self, _size: int) -> bytes:
            raise ValueError("boom detail")

    class _Writer:
        def is_closing(self) -> bool:
            return False

        def write(self, _data: bytes) -> None:
            pass

        async def drain(self) -> None:
            pass

        def close(self) -> None:
            pass

    # Debug off: only the class-only always-on line, no detail.
    monkeypatch.setattr(diagnostics, "_enabled", False)
    await protocol._serve_stream(_FailingReader(), _Writer())
    plain = capsys.readouterr().err
    assert "error: session failed exc=ValueError" in plain
    assert "session failure detail" not in plain
    assert "boom detail" not in plain

    # Debug on: the peer-aware sink carries the sanitized message.
    monkeypatch.setattr(diagnostics, "_enabled", True)
    await protocol._serve_stream(_FailingReader(), _Writer())
    debugged = capsys.readouterr().err
    assert (
        "debug: session failure detail exc=ValueError error=ValueError('boom detail')" in debugged
    )


def _register_frame(token: str | None) -> dict:
    frame = {
        "protocol_version": "rdv/1",
        "type": "register",
        "cid": CID,
        "bucket": "shared",
        "group": "home",
        "cert_fp": FP,
        "version": "1.0.0",
        "endpoints": [{"proto": "tcp", "host": "198.51.100.7", "port": 443}],
    }
    if token is not None:
        frame["bucket_token"] = token
    return frame


def _query_frame(token: str | None, bucket: str = "shared") -> dict:
    frame = {
        "protocol_version": "rdv/1",
        "type": "query",
        "bucket": bucket,
        "group": "home",
    }
    if token is not None:
        frame["bucket_token"] = token
    return frame


def test_build_quic_configuration_bounds_receive_windows() -> None:
    """The server advertises small flow-control windows (bounded recv buffering)."""
    from hsync_rendezvous.server import MAX_DATA_BYTES, MAX_STREAM_DATA_BYTES

    config = build_quic_configuration(make_identity(host="127.0.0.1"))
    assert config.is_client is False
    assert config.max_stream_data == MAX_STREAM_DATA_BYTES
    assert config.max_data == MAX_DATA_BYTES


def test_connection_guard_global_cap_and_release() -> None:
    """A process-wide cap bounds total open connections, independent of per-IP."""
    guard = ConnectionGuard(
        handshake_rate=1000.0, handshake_burst=1000, active_max=10, global_max=2
    )
    assert guard.admit("10.0.0.1", now=0.0) is True
    assert guard.admit("10.0.0.2", now=0.0) is True
    assert guard.admit("10.0.0.3", now=0.0) is False  # global ceiling reached
    assert guard.total_count() == 2
    guard.release("10.0.0.1", now=0.1)
    assert guard.total_count() == 1
    assert guard.admit("10.0.0.3", now=0.1) is True
    assert guard.total_count() == 2


def test_a_connection_cannot_pin_more_sessions_than_the_cap() -> None:
    """Streams beyond the per-connection rendezvous budget are closed, not spawned."""
    from hsync_rendezvous.server import MAX_SESSIONS_PER_CONNECTION

    protocol = object.__new__(RendezvousQuicProtocol)
    protocol.peer_addr = ("203.0.113.9", 51000)
    protocol._relay_streams = 0
    protocol._stream_tasks = {object() for _ in range(MAX_SESSIONS_PER_CONNECTION)}

    class _Writer:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    writer = _Writer()
    protocol._spawn_stream(object(), writer)
    assert writer.closed is True
    assert len(protocol._stream_tasks) == MAX_SESSIONS_PER_CONNECTION


def test_the_relay_headroom_is_a_separate_budget() -> None:
    """Relay streams never extend the rendezvous budget, and have their own cap."""
    from hsync_rendezvous.server import (
        MAX_RELAY_STREAMS_PER_CONNECTION,
        MAX_SESSIONS_PER_CONNECTION,
        MAX_STREAMS_PER_CONNECTION,
    )

    assert MAX_STREAMS_PER_CONNECTION == (
        MAX_SESSIONS_PER_CONNECTION + MAX_RELAY_STREAMS_PER_CONNECTION
    )

    class _Writer:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    # A listener holds one control stream plus one stream per relayed session:
    # the rendezvous budget is untouched by them...
    listener = object.__new__(RendezvousQuicProtocol)
    listener.peer_addr = ("203.0.113.9", 51000)
    listener._stream_tasks = {object() for _ in range(MAX_SESSIONS_PER_CONNECTION)}
    listener._relay_streams = MAX_SESSIONS_PER_CONNECTION
    over_relay_budget = object.__new__(RendezvousQuicProtocol)
    over_relay_budget.peer_addr = ("203.0.113.9", 51000)
    over_relay_budget._stream_tasks = {object() for _ in range(MAX_RELAY_STREAMS_PER_CONNECTION)}
    over_relay_budget._relay_streams = MAX_RELAY_STREAMS_PER_CONNECTION

    # ...but its own ceiling still refuses further streams.
    writer = _Writer()
    over_relay_budget._spawn_stream(object(), writer)
    assert writer.closed is True
    assert listener._relay_streams == MAX_SESSIONS_PER_CONNECTION
