"""Black-box negative/robustness tests: silent drops, no oracle, leave semantics."""

from __future__ import annotations

import json

import pytest
from harness import (
    BootClient,
    RawOutcome,
    leave_frame,
    query_frame,
    random_cid,
    register_frame,
)


@pytest.mark.asyncio
async def test_malformed_json_is_dropped(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    async with BootClient(handle.port) as client:
        result = await client.send_raw(b"{this is not json}\n")
        assert result.outcome is RawOutcome.SILENT
        # the server must remain healthy after the drop
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_unknown_type_is_dropped(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    async with BootClient(handle.port) as client:
        raw = json.dumps({"protocol_version": "boot/1", "type": "pwn"}) + "\n"
        result = await client.send_raw(raw.encode("utf-8"))
        assert result.outcome is RawOutcome.SILENT
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_oversized_frame_closes_stream(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    async with BootClient(handle.port) as client:
        result = await client.send_raw(b"x" * 9000 + b"\n")
        assert result.outcome is RawOutcome.CLOSED
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_targeted_field_is_rejected(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    async with BootClient(handle.port) as client:
        frame = register_frame(random_cid(rng), bucket)
        frame["file_search"] = "photo.jpg"
        result = await client.send_raw((json.dumps(frame) + "\n").encode("utf-8"))
        assert result.outcome is RawOutcome.SILENT
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_invalid_cid_is_rejected(bootnode_factory, bucket) -> None:
    handle = bootnode_factory()
    async with BootClient(handle.port) as client:
        frame = register_frame("too-short", bucket)
        result = await client.send_raw((json.dumps(frame) + "\n").encode("utf-8"))
        assert result.outcome is RawOutcome.SILENT


@pytest.mark.asyncio
async def test_wrong_protocol_version_is_rejected(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    async with BootClient(handle.port) as client:
        frame = register_frame(random_cid(rng), bucket)
        frame["protocol_version"] = "boot/9"
        result = await client.send_raw((json.dumps(frame) + "\n").encode("utf-8"))
        assert result.outcome is RawOutcome.SILENT


@pytest.mark.asyncio
async def test_leave_removes_record_anonymously(bootnode_factory, bucket, rng) -> None:
    handle = bootnode_factory()
    cid = random_cid(rng)
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))
        # leave carries no response frame and keeps the stream open (silent)
        result = await client.send_raw((json.dumps(leave_frame(cid, bucket)) + "\n").encode())
        assert result.outcome is RawOutcome.SILENT
        response = await client.exchange(query_frame(bucket))
    assert response["type"] == "response"
    assert response["count"] == 0
