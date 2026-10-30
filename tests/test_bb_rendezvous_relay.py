"""Black-box data-relay tests over the ``rdv/1`` wire protocol.

Drives the real node process through the public frames only: a listener registers
its control stream, a requester pairs with it, the listener attaches a fresh
stream, and opaque bytes flow both ways. Nothing here knows about the registry
internals, so the suite keeps testing the contract if the implementation is
rewritten.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from harness import RdvClient, random_cid, register_frame


def _listen(cid: str, bucket: str) -> dict:
    return {"protocol_version": "rdv/1", "type": "relay_listen", "cid": cid, "bucket": bucket}


def _connect(cid: str, target_cid: str, bucket: str) -> dict:
    return {
        "protocol_version": "rdv/1",
        "type": "relay_connect",
        "cid": cid,
        "bucket": bucket,
        "target_cid": target_cid,
    }


def _attach(cid: str, bucket: str, relay_id: str) -> dict:
    return {
        "protocol_version": "rdv/1",
        "type": "relay_attach",
        "cid": cid,
        "bucket": bucket,
        "relay_id": relay_id,
    }


async def _read_json(reader) -> dict:
    return json.loads(await asyncio.wait_for(reader.readline(), timeout=5.0))


def _write(writer, frame: dict) -> None:
    writer.write((json.dumps(frame) + "\n").encode("utf-8"))


@pytest.mark.asyncio
async def test_a_relayed_session_carries_bytes_both_ways(rendezvous_factory, bucket, rng) -> None:
    # Given: a node with the relay enabled and a registered listener
    handle = rendezvous_factory(args=("--relay",))
    listener_cid = random_cid(rng)
    requester_cid = random_cid(rng)
    async with RdvClient(handle.port) as listener:
        await listener.exchange(register_frame(listener_cid, bucket))
        control_reader, control_writer = await listener.open_stream()
        _write(control_writer, _listen(listener_cid, bucket))
        await control_writer.drain()
        assert (await _read_json(control_reader))["type"] == "relay_listening"

        async with RdvClient(handle.port) as requester:
            data_reader, data_writer = await requester.open_stream()
            _write(data_writer, _connect(requester_cid, listener_cid, bucket))
            await data_writer.drain()

            # When: the node announces the session and the requester gets its ok
            incoming = await _read_json(control_reader)
            assert incoming["type"] == "relay_incoming"
            assert incoming["cid"] == requester_cid
            relay_id = incoming["relay_id"]
            assert (await _read_json(data_reader))["type"] == "relay_ok"

            acceptor_reader, acceptor_writer = await listener.open_stream()
            _write(acceptor_writer, _attach(listener_cid, bucket, relay_id))
            await acceptor_writer.drain()

            data_writer.write(b"requester-bytes")
            await data_writer.drain()
            acceptor_writer.write(b"listener-bytes")
            await acceptor_writer.drain()

            # Then: both directions arrive verbatim (the node never parses them)
            assert (
                await asyncio.wait_for(acceptor_reader.readexactly(15), timeout=5.0)
                == b"requester-bytes"
            )
            assert (
                await asyncio.wait_for(data_reader.readexactly(14), timeout=5.0)
                == b"listener-bytes"
            )


@pytest.mark.asyncio
async def test_a_node_without_the_relay_refuses_the_session(
    rendezvous_factory, bucket, rng
) -> None:
    # Given: a node started without --relay
    handle = rendezvous_factory()
    cid = random_cid(rng)
    target = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))
        # When: a relay session is requested
        reply = await client.exchange(_connect(cid, target, bucket))
    # Then: the uniform refusal names the missing capability
    assert reply["type"] == "relay_error"
    assert reply["error"] == "relay_unavailable"


@pytest.mark.asyncio
async def test_a_listener_is_required_before_a_session_can_start(
    rendezvous_factory, bucket, rng
) -> None:
    # Given: a relay-enabled node and a peer that never opened a listener
    handle = rendezvous_factory(args=("--relay",))
    cid = random_cid(rng)
    target = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))
        # When: a session towards that peer is requested
        reply = await client.exchange(_connect(cid, target, bucket))
    # Then: no listener means relay_unavailable, never a hang
    assert reply["type"] == "relay_error"
    assert reply["error"] == "relay_unavailable"
