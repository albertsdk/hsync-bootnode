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
