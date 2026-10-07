"""Black-box protected-bucket tests: uniform refusal, token auth, no oracle."""

from __future__ import annotations

import pytest
from harness import (
    BootClient,
    derive_bucket_token,
    query_frame,
    random_cid,
    register_frame,
)


@pytest.mark.asyncio
async def test_anonymous_query_is_uniformly_refused(bootnode_factory, bucket, group_key) -> None:
    # Given: a protected bucket provisioned with a group key
    handle = bootnode_factory(protected=[bucket], keys={bucket: group_key})
    # When: an anonymous query is sent
    async with BootClient(handle.port) as client:
        response = await client.exchange(query_frame(bucket, token=None))
    # Then: uniform token_required, empty peer list (no oracle)
    assert response["type"] == "response"
    assert response["error"] == "token_required"
    assert response["peers"] == []
    assert response["count"] == 0


@pytest.mark.asyncio
async def test_wrong_token_is_refused_like_missing(bootnode_factory, bucket, group_key) -> None:
    # Given: a protected bucket provisioned with a group key
    handle = bootnode_factory(protected=[bucket], keys={bucket: group_key})
    # When: a wrong token is sent
    async with BootClient(handle.port) as client:
        response = await client.exchange(query_frame(bucket, token="0" * 64))
    # Then: indistinguishable from a missing token
    assert response["error"] == "token_required"
    assert response["count"] == 0


@pytest.mark.asyncio
async def test_correct_token_returns_peers(bootnode_factory, bucket, group_key, rng) -> None:
    # Given: a protected bucket, its key, and a registered peer
    handle = bootnode_factory(protected=[bucket], keys={bucket: group_key})
    token = derive_bucket_token(group_key.encode("utf-8"), bucket)
    cid = random_cid(rng)
    # When: an authenticated register + query are sent
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket, token=token))
        response = await client.exchange(query_frame(bucket, token=token))
    # Then: the peer is listed
    assert response["error"] is None
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == cid


@pytest.mark.asyncio
async def test_register_without_token_creates_nothing(
    bootnode_factory, bucket, group_key, rng
) -> None:
    # Given: a protected bucket and its key
    handle = bootnode_factory(protected=[bucket], keys={bucket: group_key})
    token = derive_bucket_token(group_key.encode("utf-8"), bucket)
    # When: an anonymous register is refused
    async with BootClient(handle.port) as client:
        refused = await client.exchange(register_frame(random_cid(rng), bucket, token=None))
        assert refused["error"] == "token_required"
        # Then: a subsequent authenticated query still sees zero peers
        response = await client.exchange(query_frame(bucket, token=token))
    assert response["error"] is None
    assert response["count"] == 0
