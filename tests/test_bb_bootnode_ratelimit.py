"""Black-box rate-limit tests: burst then ``rate_limited`` + ``retry_after``.

Each limiter's burst is reachable without waiting: the query (IP,bucket) limiter
bursts at 10, the register bucket limiter bursts at 10 and the failed-token
limiter bursts at 5. Per-IP isolation between *different* source IPs cannot be
exercised on loopback (every client is 127.0.0.1) and is covered by the
white-box unit suite instead.
"""

from __future__ import annotations

import pytest
from harness import BootClient, query_frame, random_cid, register_frame


@pytest.mark.asyncio
async def test_query_rate_limited_after_burst(bootnode_factory, bucket) -> None:
    handle = bootnode_factory()
    async with BootClient(handle.port) as client:
        for _ in range(10):
            response = await client.exchange(query_frame(bucket))
            assert response["error"] is None
        limited = await client.exchange(query_frame(bucket))
    assert limited["type"] == "response"
    assert limited["error"] == "rate_limited"
    assert limited["peers"] == []
    assert limited["retry_after"] >= 1


@pytest.mark.asyncio
async def test_register_rate_limited_after_burst(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    async with BootClient(handle.port) as client:
        for _ in range(10):
            ack = await client.exchange(register_frame(random_cid(rng), bucket))
            assert ack["type"] == "ack"
        limited = await client.exchange(register_frame(random_cid(rng), bucket))
    assert limited["type"] == "response"
    assert limited["error"] == "rate_limited"
    assert limited["retry_after"] >= 1


@pytest.mark.asyncio
async def test_bad_token_rate_limited_after_burst(bootnode_factory, bucket, group_key) -> None:
    handle = bootnode_factory(protected=[bucket], keys={bucket: group_key})
    async with BootClient(handle.port) as client:
        for _ in range(5):
            refused = await client.exchange(query_frame(bucket, token="0" * 64))
            assert refused["error"] == "token_required"
        limited = await client.exchange(query_frame(bucket, token="0" * 64))
    assert limited["error"] == "rate_limited"
    assert limited["retry_after"] >= 1


@pytest.mark.asyncio
async def test_no_rate_limit_seam_disables_throttling(bootnode_factory, bucket) -> None:
    handle = bootnode_factory(no_rate_limit=True)
    async with BootClient(handle.port) as client:
        # 15 queries exceed the query pair burst (10); with the seam off the
        # limiter must never trigger.
        for _ in range(15):
            response = await client.exchange(query_frame(bucket))
            assert response["error"] is None
