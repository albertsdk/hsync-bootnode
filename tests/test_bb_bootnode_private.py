"""Black-box private-node tests: ``--private`` closes every bucket.

The scenarios drive the real binary through public behaviour only: the CLI
(``--private`` / ``HSYNC_BOOTNODE_PRIVATE``, exit codes, banner) and the
``boot/1`` wire protocol. They must stay true for any implementation of the
protocol (the future ``rust/``/``c/`` ports run this file unchanged).
"""

from __future__ import annotations

import json

import pytest
from harness import (
    BootClient,
    derive_bucket_token,
    leave_frame,
    query_frame,
    random_cid,
    register_frame,
    run_cli,
)


def test_private_without_keys_fails_fast() -> None:
    """A private node with no group key has nothing to authorize against."""
    result = run_cli(["run", "--private"])
    assert result.returncode == 2
    assert "configuration error" in result.stderr
    assert "private node without any group key" in result.stderr


def test_private_banner_announces_the_mode(bootnode_factory, bucket, group_key) -> None:
    handle = bootnode_factory(private=True, keys={bucket: group_key})
    assert handle.proc.poll() is None
    assert "private" in handle.stdout_text()


@pytest.mark.asyncio
async def test_every_frame_requires_a_token(bootnode_factory, bucket, group_key, rng) -> None:
    handle = bootnode_factory(private=True, keys={bucket: group_key})
    token = derive_bucket_token(group_key.encode("utf-8"), bucket)
    cid = random_cid(rng)
    async with BootClient(handle.port) as client:
        # no bucket is declared protected: the private flag alone refuses
        refused = await client.exchange(register_frame(cid, bucket))
        assert refused["type"] == "response"
        assert refused["error"] == "token_required"
        assert refused["count"] == 0
        assert (await client.exchange(query_frame(bucket)))["error"] == "token_required"

        # the valid token unlocks register and query
        ack = await client.exchange(register_frame(cid, bucket, token=token))
        assert ack["type"] == "ack"
        response = await client.exchange(query_frame(bucket, token=token))
        assert response["error"] is None
        assert response["count"] == 1
        assert response["peers"][0]["cid"] == cid


@pytest.mark.asyncio
async def test_unkeyed_bucket_is_refused_like_a_wrong_token(
    bootnode_factory, bucket, group_key
) -> None:
    """No bucket-existence oracle: an unkeyed bucket answers like a bad token."""
    handle = bootnode_factory(private=True, keys={bucket: group_key})
    async with BootClient(handle.port) as client:
        anonymous = await client.exchange(query_frame("bb-unkeyed", token=None))
        wrong = await client.exchange(query_frame("bb-unkeyed", token="0" * 64))
        keyed_wrong = await client.exchange(query_frame(bucket, token="0" * 64))
    for response in (anonymous, wrong, keyed_wrong):
        assert response["type"] == "response"
        assert response["error"] == "token_required"
        assert response["peers"] == []
        assert response["count"] == 0


@pytest.mark.asyncio
async def test_private_leave_requires_the_token(bootnode_factory, bucket, group_key, rng) -> None:
    """An anonymous leave must not evict a registered peer on a private node."""
    handle = bootnode_factory(private=True, keys={bucket: group_key})
    token = derive_bucket_token(group_key.encode("utf-8"), bucket)
    cid = random_cid(rng)
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket, token=token))
        # anonymous leave: silently dropped, the peer survives
        await client.send_raw((json.dumps(leave_frame(cid, bucket)) + "\n").encode())
        response = await client.exchange(query_frame(bucket, token=token))
        assert response["count"] == 1
        # authenticated leave: the peer is gone
        await client.send_raw((json.dumps(leave_frame(cid, bucket, token=token)) + "\n").encode())
        response = await client.exchange(query_frame(bucket, token=token))
        assert response["count"] == 0


@pytest.mark.asyncio
async def test_envvar_enables_private_mode(bootnode_factory, bucket, group_key, rng) -> None:
    """The envvar form (what the service units set) is equivalent to the flag."""
    handle = bootnode_factory(
        keys={bucket: group_key},
        env_extra={"HSYNC_BOOTNODE_PRIVATE": "1"},
    )
    token = derive_bucket_token(group_key.encode("utf-8"), bucket)
    cid = random_cid(rng)
    async with BootClient(handle.port) as client:
        assert (await client.exchange(query_frame(bucket)))["error"] == "token_required"
        ack = await client.exchange(register_frame(cid, bucket, token=token))
        assert ack["type"] == "ack"
