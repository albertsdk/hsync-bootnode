"""Black-box private-node tests: ``--private`` closes every bucket.

The scenarios drive the real binary through public behaviour only: the CLI
(``--private`` / ``HSYNC_RENDEZVOUS_PRIVATE``, exit codes, banner) and the
``rdv/1`` wire protocol. They must stay true for any implementation of the
protocol (the future ``c/`` port runs this file unchanged).
"""

from __future__ import annotations

import json

import pytest
from harness import (
    RdvClient,
    derive_bucket_token,
    leave_frame,
    query_frame,
    random_cid,
    register_frame,
    run_cli,
)


def test_private_without_keys_fails_fast() -> None:
    """A private node with no group key has nothing to authorize against."""
    # Given: no keys
    # When: --private is set with no group keys
    result = run_cli(["run", "--private"])
    # Then: fail-fast configuration error (exit 2)
    assert result.returncode == 2
    assert "configuration error" in result.stderr
    assert "private node without any group key" in result.stderr


def test_private_banner_announces_the_mode(rendezvous_factory, bucket, group_key) -> None:
    # Given: a private node with one provisioned key
    handle = rendezvous_factory(private=True, keys={bucket: group_key})
    # Then: the banner announces the mode
    assert handle.proc.poll() is None
    assert "private" in handle.stdout_text()


@pytest.mark.asyncio
async def test_every_frame_requires_a_token(rendezvous_factory, bucket, group_key, rng) -> None:
    # Given: a private node with a provisioned bucket key
    handle = rendezvous_factory(private=True, keys={bucket: group_key})
    token = derive_bucket_token(group_key.encode("utf-8"), bucket)
    cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        # When: register/query are attempted without a token
        refused = await client.exchange(register_frame(cid, bucket))
        assert refused["type"] == "response"
        assert refused["error"] == "token_required"
        assert refused["count"] == 0
        assert (await client.exchange(query_frame(bucket)))["error"] == "token_required"

        # When: the valid token is presented
        ack = await client.exchange(register_frame(cid, bucket, token=token))
        assert ack["type"] == "ack"
        response = await client.exchange(query_frame(bucket, token=token))
    # Then: the peer is listed
    assert response["error"] is None
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == cid


@pytest.mark.asyncio
async def test_unkeyed_bucket_is_refused_like_a_wrong_token(
    rendezvous_factory, bucket, group_key
) -> None:
    """No bucket-existence oracle: an unkeyed bucket answers like a bad token."""
    # Given: a private node with one provisioned key
    handle = rendezvous_factory(private=True, keys={bucket: group_key})
    # When: an unprovisioned bucket is queried anonymously, with a wrong token,
    #       and a keyed bucket with a wrong token
    async with RdvClient(handle.port) as client:
        anonymous = await client.exchange(query_frame("bb-unkeyed", token=None))
        wrong = await client.exchange(query_frame("bb-unkeyed", token="0" * 64))
        keyed_wrong = await client.exchange(query_frame(bucket, token="0" * 64))
    # Then: every refusal is the same uniform token_required
    for response in (anonymous, wrong, keyed_wrong):
        assert response["type"] == "response"
        assert response["error"] == "token_required"
        assert response["peers"] == []
        assert response["count"] == 0


@pytest.mark.asyncio
async def test_private_leave_requires_the_token(rendezvous_factory, bucket, group_key, rng) -> None:
    """An anonymous leave must not evict a registered peer on a private node."""
    # Given: a private node with a provisioned key and a registered peer
    handle = rendezvous_factory(private=True, keys={bucket: group_key})
    token = derive_bucket_token(group_key.encode("utf-8"), bucket)
    cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket, token=token))
        # When: an anonymous leave is sent
        await client.send_raw((json.dumps(leave_frame(cid, bucket)) + "\n").encode())
        # Then: the peer survives (silent drop)
        response = await client.exchange(query_frame(bucket, token=token))
        assert response["count"] == 1
        # When: an authenticated leave is sent
        await client.send_raw((json.dumps(leave_frame(cid, bucket, token=token)) + "\n").encode())
        # Then: the peer is gone
        response = await client.exchange(query_frame(bucket, token=token))
        assert response["count"] == 0


@pytest.mark.asyncio
async def test_envvar_enables_private_mode(rendezvous_factory, bucket, group_key, rng) -> None:
    """The envvar form (what the service units set) is equivalent to the flag."""
    # Given: a node started with HSYNC_RENDEZVOUS_PRIVATE=1 and a provisioned key
    handle = rendezvous_factory(
        keys={bucket: group_key},
        env_extra={"HSYNC_RENDEZVOUS_PRIVATE": "1"},
    )
    token = derive_bucket_token(group_key.encode("utf-8"), bucket)
    cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        # When: an anonymous query and an authenticated register are sent
        # Then: the query is refused, the register accepted
        assert (await client.exchange(query_frame(bucket)))["error"] == "token_required"
        ack = await client.exchange(register_frame(cid, bucket, token=token))
        assert ack["type"] == "ack"
