"""Black-box register/refresh tests over the ``boot/1`` wire protocol."""

from __future__ import annotations

import json

import pytest
from harness import (
    BootClient,
    RawOutcome,
    query_frame,
    random_cid,
    refresh_frame,
    register_frame,
)


@pytest.mark.asyncio
async def test_register_ack_carries_stun_echo(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    async with BootClient(handle.port) as client:
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"
    assert ack["observed_endpoint"]["proto"] == "udp"
    assert ack["observed_endpoint"]["ip"] == "127.0.0.1"
    assert ack["ttl"] == 60
    assert ack["server_time"].endswith("Z")


@pytest.mark.asyncio
async def test_query_returns_advertised_endpoint(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    cid = random_cid(rng)
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket, host="198.51.100.7", port=8443))
        response = await client.exchange(query_frame(bucket))
    assert response["type"] == "response"
    assert response["count"] == 1
    peer = response["peers"][0]
    assert peer["cid"] == cid
    assert peer["endpoints"] == [{"proto": "tcp", "host": "198.51.100.7", "port": 8443}]


@pytest.mark.asyncio
async def test_query_falls_back_to_observed_source(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    cid = random_cid(rng)
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket, endpoints=False))
        response = await client.exchange(query_frame(bucket))
    assert response["type"] == "response"
    assert response["count"] == 1
    peer = response["peers"][0]
    assert peer["endpoints"][0]["host"] == "127.0.0.1"  # observed loopback source
    assert peer["endpoints"][0]["proto"] == "udp"


@pytest.mark.asyncio
async def test_refresh_acks_and_updates_connected(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    cid = random_cid(rng)
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))
        ack = await client.exchange(refresh_frame(cid, bucket, connected=7))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_refresh_unknown_cid_is_dropped(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    async with BootClient(handle.port) as client:
        result = await client.send_raw(
            (json.dumps(refresh_frame(random_cid(rng), bucket)) + "\n").encode("utf-8")
        )
    assert result.outcome is RawOutcome.SILENT
