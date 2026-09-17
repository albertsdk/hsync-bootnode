"""QUIC transport tests: identity/config units + real loopback boot/1 exchanges.

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

from hsync_bootnode.handler import BootHandler
from hsync_bootnode.server import (
    BOOT_ALPN,
    build_quic_configuration,
    make_identity,
    start_server,
)
from hsync_bootnode.tokens import derive_bucket_token

CID = "A1b2C3d4E5f6G7h8I9j0K"
FP = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"


def test_make_identity_produces_self_signed_fingerprint() -> None:
    identity = make_identity(host="127.0.0.1")
    assert re.fullmatch(r"[0-9a-f]{64}", str(identity.fingerprint))
    assert identity.is_ca is False
    config = build_quic_configuration(identity)
    assert config.alpn_protocols == [BOOT_ALPN]
    assert config.certificate is not None
    assert config.private_key is not None


@pytest.mark.asyncio
async def test_loopback_register_query_and_protected_refusal() -> None:
    handler = BootHandler(
        protected_buckets=("shared",),
        group_keys={"shared": SecretStr("kshared")},
    )
    server, port, _identity = await start_server("127.0.0.1", 0, handler, retry=True)
    try:
        client_config = QuicConfiguration(
            is_client=True, alpn_protocols=[BOOT_ALPN], verify_mode=ssl.CERT_NONE
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
            assert response["peers"][0]["ip"] == "198.51.100.7"
    finally:
        server.close()


@pytest.mark.asyncio
async def test_loopback_garbage_frame_is_dropped() -> None:
    handler = BootHandler()
    server, port, _identity = await start_server("127.0.0.1", 0, handler, retry=True)
    try:
        client_config = QuicConfiguration(
            is_client=True, alpn_protocols=[BOOT_ALPN], verify_mode=ssl.CERT_NONE
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
    handler = BootHandler()
    server, port, _identity = await start_server("127.0.0.1", 0, handler, retry=True)
    try:
        client_config = QuicConfiguration(
            is_client=True, alpn_protocols=[BOOT_ALPN], verify_mode=ssl.CERT_NONE
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
    handler = BootHandler(private=True, group_keys={"shared": SecretStr("kshared")})
    server, port, _identity = await start_server("127.0.0.1", 0, handler, retry=True)
    try:
        client_config = QuicConfiguration(
            is_client=True, alpn_protocols=[BOOT_ALPN], verify_mode=ssl.CERT_NONE
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


def _register_frame(token: str | None) -> dict:
    frame = {
        "protocol_version": "boot/1",
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
        "protocol_version": "boot/1",
        "type": "query",
        "bucket": bucket,
        "group": "home",
    }
    if token is not None:
        frame["bucket_token"] = token
    return frame
