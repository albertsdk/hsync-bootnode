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
    # Given: a node with rate limits on
    handle = bootnode_factory()
    async with BootClient(handle.port) as client:
        # When: the query burst is exhausted
        for _ in range(10):
            response = await client.exchange(query_frame(bucket))
            assert response["error"] is None
        limited = await client.exchange(query_frame(bucket))
    # Then: the next query is rate_limited with a retry hint
    assert limited["type"] == "response"
    assert limited["error"] == "rate_limited"
    assert limited["peers"] == []
    assert limited["retry_after"] >= 1


@pytest.mark.asyncio
async def test_register_rate_limited_after_burst(bootnode_factory, bucket, rng) -> None:
    # Given: a node with rate limits on
    handle = bootnode_factory()
    async with BootClient(handle.port) as client:
        # When: the register burst is exhausted
        for _ in range(10):
            ack = await client.exchange(register_frame(random_cid(rng), bucket))
            assert ack["type"] == "ack"
        limited = await client.exchange(register_frame(random_cid(rng), bucket))
    # Then: the next register is rate_limited
    assert limited["type"] == "response"
    assert limited["error"] == "rate_limited"
    assert limited["retry_after"] >= 1


@pytest.mark.asyncio
async def test_bad_token_rate_limited_after_burst(bootnode_factory, bucket, group_key) -> None:
    # Given: a protected bucket and its key
    handle = bootnode_factory(protected=[bucket], keys={bucket: group_key})
    async with BootClient(handle.port) as client:
        # When: the failed-token burst is exhausted
        for _ in range(5):
            refused = await client.exchange(query_frame(bucket, token="0" * 64))
            assert refused["error"] == "token_required"
        limited = await client.exchange(query_frame(bucket, token="0" * 64))
    # Then: the next attempt is rate_limited (anti-abuse budget)
    assert limited["error"] == "rate_limited"
    assert limited["retry_after"] >= 1


@pytest.mark.asyncio
async def test_no_rate_limit_seam_disables_throttling(bootnode_factory, bucket) -> None:
    # Given: a node started with the --no-rate-limit seam
    handle = bootnode_factory(no_rate_limit=True)
    async with BootClient(handle.port) as client:
        # When: 15 queries exceed the query pair burst (10)
        # Then: with the seam off the limiter never triggers
        for _ in range(15):
            response = await client.exchange(query_frame(bucket))
            assert response["error"] is None
