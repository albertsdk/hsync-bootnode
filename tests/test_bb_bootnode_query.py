"""Black-box query/sample/group tests over the ``boot/1`` wire protocol."""

from __future__ import annotations

import pytest
from harness import BootClient, query_frame, random_cid, register_frame


@pytest.mark.asyncio
async def test_query_returns_registered_peers(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    cid_a = random_cid(rng)
    cid_b = random_cid(rng)
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid_a, bucket))
        await client.exchange(register_frame(cid_b, bucket))
        response = await client.exchange(query_frame(bucket))
    assert response["type"] == "response"
    assert response["error"] is None
    assert response["count"] == 2
    cids = {p["cid"] for p in response["peers"]}
    assert cids == {cid_a, cid_b}


@pytest.mark.asyncio
async def test_query_relays_capacity_hint(bootnode_factory, bucket, rng) -> None:
    """The advisory capacity hint is relayed verbatim in the query peer list."""
    handle = bootnode_factory()
    cid_serving = random_cid(rng)
    cid_slave = random_cid(rng)
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid_serving, bucket, capacity=7))
        await client.exchange(register_frame(cid_slave, bucket, capacity=0))
        response = await client.exchange(query_frame(bucket))
    assert response["type"] == "response"
    assert response["error"] is None
    assert response["count"] == 2
    capacities = {p["cid"]: p["capacity"] for p in response["peers"]}
    assert capacities == {cid_serving: 7, cid_slave: 0}


@pytest.mark.asyncio
async def test_query_marks_reachability_by_advertised_endpoint(
    bootnode_factory, bucket, rng
) -> None:
    """reachable is true only for peers that advertised a listen endpoint."""
    handle = bootnode_factory()
    cid_master = random_cid(rng)
    cid_slave = random_cid(rng)
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid_master, bucket))
        await client.exchange(register_frame(cid_slave, bucket, endpoints=False))
        response = await client.exchange(query_frame(bucket))
    assert response["type"] == "response"
    assert response["count"] == 2
    reachable = {p["cid"]: p["reachable"] for p in response["peers"]}
    assert reachable == {cid_master: True, cid_slave: False}
    slave = next(p for p in response["peers"] if p["cid"] == cid_slave)
    assert slave["proto"] == "udp"


@pytest.mark.asyncio
async def test_query_group_filter(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    home_cid = random_cid(rng)
    ungrouped_cid = random_cid(rng)
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(home_cid, bucket, group="home"))
        await client.exchange(register_frame(ungrouped_cid, bucket, group=None))
        response = await client.exchange(query_frame(bucket, group="home"))
    assert response["type"] == "response"
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == home_cid


@pytest.mark.asyncio
async def test_query_limit_bounds_sample(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    async with BootClient(handle.port) as client:
        for _ in range(3):
            await client.exchange(register_frame(random_cid(rng), bucket))
        response = await client.exchange(query_frame(bucket, limit=1))
    assert response["type"] == "response"
    assert response["count"] == 1
    assert len(response["peers"]) == 1


@pytest.mark.asyncio
async def test_pipelined_frames_answered_in_order(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    cid = random_cid(rng)
    async with BootClient(handle.port) as client:
        first, second = await client.pipeline([register_frame(cid, bucket), query_frame(bucket)])
    assert first["type"] == "ack"
    assert second["type"] == "response"
    assert second["count"] == 1
    assert second["peers"][0]["cid"] == cid
