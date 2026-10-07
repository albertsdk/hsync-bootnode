"""Black-box TTL convergence tests (uses the ``--ttl`` seam for fast expiry)."""

from __future__ import annotations

import asyncio

import pytest
from harness import BootClient, query_frame, random_cid, refresh_frame, register_frame


@pytest.mark.asyncio
async def test_expired_peer_disappears_from_queries(bootnode_factory, bucket, rng) -> None:
    # Given: a node with TTL=1 and a registered peer
    handle = bootnode_factory(ttl=1)
    cid = random_cid(rng)
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))
        before = await client.exchange(query_frame(bucket))
        assert before["count"] == 1

        # When: the TTL elapses
        await asyncio.sleep(1.6)  # past the 1 s TTL

        # Then: the peer disappears from queries
        after = await client.exchange(query_frame(bucket))
    assert after["count"] == 0


@pytest.mark.asyncio
async def test_refresh_keeps_peer_alive(bootnode_factory, bucket, rng) -> None:
    # Given: a node with TTL=2 and a registered peer
    handle = bootnode_factory(ttl=2)
    cid = random_cid(rng)
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))

        # When: the peer refreshes before the original expiry
        await asyncio.sleep(1.0)  # before the original expiry (t+2)
        await client.exchange(refresh_frame(cid, bucket))
        await asyncio.sleep(1.2)  # past the original expiry, before the renewed one

        # Then: the peer is still advertised
        after = await client.exchange(query_frame(bucket))
    assert after["count"] == 1
    assert after["peers"][0]["cid"] == cid
