"""L1 — pure-handler micro-benchmark (no sockets, deterministic, Python-only).

This is the ONLY benchmark that is implementation-specific: it measures
``BootHandler.handle`` throughput/latency directly (pydantic validation, routing
scan/sample, pydantic replies) with the routing table pre-populated at several
sizes. The transport cost is isolated in ``bench_quic.py`` (language-neutral).

Usage:
    cd hsync-bootnode && python/.venv/bin/python bench/bench_handler.py \
        [--count N] [--json-out FILE]

A fresh handler per scenario keeps the per-IP/per-bucket token buckets full:
every scenario measures the steady-state fast path, never the rate limiter.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "python" / "src"))
sys.path.insert(0, str(_REPO_ROOT / "tests"))

from common import (  # noqa: E402
    add_json_out,
    make_cids,
    maybe_write_json,
    measure,
    print_table,
)
from harness import (  # noqa: E402
    leave_frame,
    query_frame,
    refresh_frame,
    register_frame,
)
from hsync_bootnode.handler import BootHandler  # noqa: E402

_PEER_IP = "198.51.100.7"
_PEER_PORT = 54321


def _populate(handler: BootHandler, bucket: str, count: int, start: int = 0) -> list[str]:
    """Register ``count`` peers into ONE bucket, bypassing the rate limiter.

    The register limiter is 10/min per bucket on a shared handler, so setup
    rotates the source IP past the per-IP burst AND clears the limiter state
    via fresh handler pools per chunk. Population is not what we measure:
    only the final routing-table contents matter.
    """
    from hsync_bootnode.handler import REGISTER_BUCKET_LIMIT

    cids = make_cids(count, start=start)
    chunk = REGISTER_BUCKET_LIMIT  # ledger-safe: never hit the per-bucket cap
    for base in range(0, count, chunk):
        pool = BootHandler()
        for offset in range(min(chunk, count - base)):
            index = base + offset
            octet = index % 250 + 1
            response = pool.handle(
                register_frame(
                    cids[index],
                    bucket=bucket,
                    host=f"10.1.{(index // 250) % 250}.{octet}",
                ),
                peer_ip=f"10.9.{(index // 250) % 250}.{octet}",
                peer_port=_PEER_PORT,
            )
            assert response is not None and response.get("type") == "ack", response
        # move this chunk's records into the target handler's table
        for record in pool.routing._records.values():
            handler.routing.upsert(record)
    assert handler.routing.count(bucket=bucket) == count
    return cids


def _bench_register(count: int):  # -> BenchResult
    # One handler per 40 ops: the per-IP admission bucket holds burst 50, so
    # rotating handlers keeps every measured op on the unthrottled fast path
    # (a single handler would rate-limit after 50 registers from one IP).
    handlers = [BootHandler() for _ in range(max(1, (count + 200 + 39) // 40))]
    cids = make_cids(count + 200, start=1_000_000)
    state = {"i": 0}

    def op() -> None:
        i = state["i"]
        state["i"] += 1
        handlers[i // 40].handle(
            register_frame(cids[i], "shared"), peer_ip=_PEER_IP, peer_port=_PEER_PORT
        )

    return measure("register", op, count=count)


def _bench_query(table_size: int, limit: int, count: int):  # -> BenchResult
    # Query limiters are 5/min per (IP, bucket) burst 10 and 30/min per
    # bucket: one handler serves 8 measured queries, then we rotate to a
    # fresh handler with the SAME table contents (records are cheap to move).
    # Every measured op stays on the unthrottled fast path.
    tables: list[BootHandler] = []
    for _ in range(max(1, (count + 200 + 7) // 8)):
        handler = BootHandler()
        _populate(handler, "shared", table_size)
        tables.append(handler)
    query = query_frame("shared", limit=limit)
    state = {"i": 0}

    def op() -> None:
        i = state["i"]
        state["i"] += 1
        tables[i // 8].handle(query, peer_ip="10.0.0.9", peer_port=1111)

    return measure(f"query(table={table_size},limit={limit})", op, count=count)


def _bench_refresh(table_size: int, count: int):  # -> BenchResult
    # Same rotation as query: 8 measured refreshes per handler (the
    # register/refresh bucket limiter is 10/min), tables shared by moves.
    tables: list[tuple[BootHandler, list[str]]] = []
    for _ in range(max(1, (count + 200 + 7) // 8)):
        handler = BootHandler()
        cids = _populate(handler, "shared", table_size)
        tables.append((handler, cids))
    state = {"i": 0}

    def op() -> None:
        i = state["i"]
        state["i"] += 1
        handler, cids = tables[i // 8]
        handler.handle(refresh_frame(cids[0], "shared"), peer_ip=_PEER_IP, peer_port=_PEER_PORT)

    return measure(f"refresh(table={table_size})", op, count=count)


def _bench_leave(count: int):  # -> BenchResult
    # leave removes; rebuild the table each cycle so every op removes one row.
    cids = make_cids(count, start=2_000_000)
    state = {"i": 0}
    handler = BootHandler()
    # leave carries no group: populate the exact CIDs into the default group.
    for cid in cids:
        handler.routing.upsert(
            __import__("hsync_bootnode.routing", fromlist=["PeerRecord"]).PeerRecord(
                cid=cid,
                bucket="shared",
                group="home",
                ip=_PEER_IP,
                port=_PEER_PORT,
                proto="udp",
                cert_fp="FP",
                version="1.0.0",
                endpoints=[],
            )
        )

    def op() -> None:
        i = state["i"]
        state["i"] += 1
        if i < count:
            handler.handle(leave_frame(cids[i], "shared"), peer_ip=_PEER_IP, peer_port=1)

    # no warmup effect wanted here (each op is one-shot); measure() warmup
    # would drain the table, so run with warmup=0 via direct call below.
    samples: list[float] = []
    for _ in range(count):
        start = time.perf_counter()
        op()
        samples.append(time.perf_counter() - start)
    from common import BenchResult

    return BenchResult("leave", samples, count)


def _bench_prune(table_size: int) -> object:  # -> BenchResult
    # prune cost: expire the whole table once per timing sample is too coarse;
    # instead time single prune() calls over an expired table of table_size.
    from common import BenchResult

    samples: list[float] = []
    for _ in range(20):
        handler = BootHandler()
        _populate(handler, "shared", table_size)
        # force expiry without sleeping: backdate every record.
        now_backdated = time.monotonic() - 61.0
        for record in handler.routing._records.values():
            record.expires_at = now_backdated
        start = time.perf_counter()
        removed = handler.prune()
        samples.append(time.perf_counter() - start)
        assert removed == table_size
    return BenchResult(f"prune(expired={table_size})", samples, 20)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=2000)
    add_json_out(parser)
    args = parser.parse_args()

    count = args.count
    results = [
        _bench_register(count),
        _bench_query(100, 20, count),
        _bench_query(1_000, 20, count),
        _bench_query(10_000, 20, min(count, 500)),
        _bench_refresh(1_000, count),
        _bench_leave(min(count, 500)),
        _bench_prune(1_000),
    ]
    print(f"handler micro-benchmark (ops={count}, open buckets, steady state)")
    print_table(results)
    maybe_write_json(args.json_out, results)


if __name__ == "__main__":
    main()
