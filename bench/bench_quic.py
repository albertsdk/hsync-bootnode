"""L2 — QUIC loopback load benchmark (real transport, language-neutral).

Spawns the bootnode binary (``HSYNC_BOOTNODE_BIN``, default Python build) and
drives it with a real aioquic client over the ``boot/1`` wire protocol. This
benchmark is independent of the implementation language: it measures the QUIC
handshake cost separately from per-frame cost on an established connection,
plus end-to-end register/query throughput, against whatever binary is selected.

Loopback numbers are comparative (v1 vs future ports), not production SLAs:
localhost removes real network latency but keeps the full TLS 1.3 + QUIC stack.

Usage:
    cd hsync-bootnode && python/.venv/bin/python bench/bench_quic.py \
        [--connections N] [--frames N] [--concurrency C] [--peers P] \
        [--json-out FILE]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from aioquic.asyncio import connect  # noqa: E402
from common import (  # noqa: E402
    BenchResult,
    add_json_out,
    make_cids,
    maybe_write_json,
    print_table,
)
from harness import (  # noqa: E402
    client_config,
    query_frame,
    register_frame,
    start_bootnode,
    terminate,
)


async def _bench_handshakes(port: int, count: int) -> BenchResult:
    """Time the QUIC handshake only (``connect`` up to handshake completion).

    The teardown is deliberately left OUTSIDE the timed region: the
    context-manager exit calls ``wait_closed()``, which blocks on the QUIC
    closing-period drain timer (``_close_at = now + 3 * PTO``) instead of
    measuring handshake work. Timing the whole ``async with`` therefore reported
    a ~10x inflated "handshake" (mostly idle timer on loopback) — see
    ``bench/profile_handshake.py``.
    """
    config = client_config()
    for _ in range(5):
        async with connect("127.0.0.1", port, configuration=config):
            pass
    samples: list[float] = []
    for _ in range(count):
        cm = connect("127.0.0.1", port, configuration=config)
        start = time.perf_counter()
        await cm.__aenter__()
        samples.append(time.perf_counter() - start)
        await cm.__aexit__(None, None, None)  # closing drain, not handshake work
    return BenchResult("quic-handshake(sequential)", samples, count)


async def _bench_frames_on_one_connection(port: int, frames: int, peers: int) -> BenchResult:
    """Register+query round-trips over a single established connection."""
    cids = make_cids(peers, start=5_000_000)
    config = client_config()
    async with connect("127.0.0.1", port, configuration=config) as protocol:
        for cid in cids:
            reader, writer = await protocol.create_stream()
            writer.write((json.dumps(register_frame(cid, "shared")) + "\n").encode())
            await writer.drain()
            await asyncio.wait_for(reader.readline(), timeout=5.0)
            writer.close()
        query = (json.dumps(query_frame("shared", limit=20)) + "\n").encode()
        for _ in range(10):
            reader, writer = await protocol.create_stream()
            writer.write(query)
            await writer.drain()
            await asyncio.wait_for(reader.readline(), timeout=5.0)
            writer.close()
        samples: list[float] = []
        for _ in range(frames):
            reader, writer = await protocol.create_stream()
            start = time.perf_counter()
            writer.write(query)
            await writer.drain()
            raw = await asyncio.wait_for(reader.readline(), timeout=5.0)
            samples.append(time.perf_counter() - start)
            writer.close()
            parsed = json.loads(raw)
            assert parsed["type"] == "response"
            assert parsed["error"] is None  # must measure real queries, not rate limits
    return BenchResult(f"query-rtt-1conn(peers={peers})", samples, frames)


async def _bench_concurrent_queries(port: int, connections: int, per_conn: int) -> BenchResult:
    """N concurrent connections each doing per_conn query round-trips."""

    async def worker() -> list[float]:
        config = client_config()
        samples: list[float] = []
        async with connect("127.0.0.1", port, configuration=config) as c:
            query = (json.dumps(query_frame("shared", limit=20)) + "\n").encode()
            for _ in range(per_conn):
                reader, writer = await c.create_stream()
                start = time.perf_counter()
                writer.write(query)
                await writer.drain()
                raw = await asyncio.wait_for(reader.readline(), timeout=10.0)
                samples.append(time.perf_counter() - start)
                writer.close()
                parsed = json.loads(raw)
                assert parsed["type"] == "response"
                assert parsed["error"] is None
        return samples

    await worker()
    started = time.perf_counter()
    results = await asyncio.gather(*[worker() for _ in range(connections)])
    wall = time.perf_counter() - started
    total = connections * per_conn
    print(f"  wall: {wall:.2f}s for {total} queries over {connections} conns")
    merged: list[float] = []
    for samples in results:
        merged.extend(samples)
    return BenchResult(f"query-rtt({connections}x{per_conn}-concurrent)", merged, total)


async def _amain(args: argparse.Namespace, port: int) -> list[BenchResult]:
    return [
        await _bench_handshakes(port, args.connections),
        await _bench_frames_on_one_connection(port, args.frames, args.peers),
        await _bench_concurrent_queries(port, args.concurrency, args.per_conn),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connections", type=int, default=50)
    parser.add_argument("--frames", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--per-conn", type=int, default=25)
    parser.add_argument("--peers", type=int, default=200)
    add_json_out(parser)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="bootnode-bench-") as tmp:
        handle = start_bootnode(Path(tmp), no_rate_limit=True)
        try:
            results = asyncio.run(_amain(args, handle.port))
        finally:
            terminate(handle)

    print("QUIC loopback load (localhost; comparative, not an SLA)")
    print_table(results)
    maybe_write_json(args.json_out, results)


if __name__ == "__main__":
    main()
