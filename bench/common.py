"""Shared benchmark helpers (L1/L2/L3): deterministic CIDs + measurement.

Stdlib only. Deterministic counter-based CIDs keep every benchmark run
reproducible without ``random`` seed juggling. Frame builders live in
``tests/harness.py`` (single source, language-neutral) and are imported by the
benchmark scripts. This module never imports ``hsync_bootnode``.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from collections.abc import Callable, Sequence

__all__ = [
    "ALPHABET",
    "make_cid",
    "make_cids",
    "measure",
    "BenchResult",
    "print_table",
    "add_json_out",
    "maybe_write_json",
]

# CID alphabet (spec: ^[A-Za-z0-9]{21}$).
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def make_cid(n: int) -> str:
    """Deterministic 21-char CID for counter value ``n``."""
    base = len(ALPHABET)
    chars = []
    value = n
    for _ in range(21):
        chars.append(ALPHABET[value % base])
        value //= base
    return "".join(reversed(chars))


def make_cids(count: int, start: int = 0) -> list[str]:
    return [make_cid(start + i) for i in range(count)]


class BenchResult:
    """One measured operation: name, sample count and latency stats (ms)."""

    def __init__(self, name: str, samples: Sequence[float], count: int) -> None:
        lat_ms = [s * 1000.0 for s in samples]
        self.name = name
        self.count = count
        self.total_s = sum(samples)
        self.ops = count / self.total_s if self.total_s > 0 else 0.0
        self.p50 = statistics.median(lat_ms) if lat_ms else 0.0
        self.p99 = _percentile(lat_ms, 99.0)
        self.mean = statistics.fmean(lat_ms) if lat_ms else 0.0

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "count": self.count,
            "total_s": round(self.total_s, 4),
            "ops_per_s": round(self.ops, 1),
            "mean_ms": round(self.mean, 4),
            "p50_ms": round(self.p50, 4),
            "p99_ms": round(self.p99, 4),
        }


def _percentile(data: Sequence[float], pct: float) -> float:
    if not data:
        return 0.0
    ordered = sorted(data)
    rank = min(len(ordered) - 1, max(0, int(len(ordered) * pct / 100.0)))
    return ordered[rank]


def measure(
    name: str,
    func: Callable[[], None],
    *,
    count: int,
    warmup: int = 200,
) -> BenchResult:
    """Run ``func`` ``count`` times (after ``warmup``) and time each call."""
    for _ in range(warmup):
        func()
    samples: list[float] = []
    for _ in range(count):
        start = time.perf_counter()
        func()
        samples.append(time.perf_counter() - start)
    return BenchResult(name, samples, count)


def print_table(results: Sequence[BenchResult]) -> None:
    header = f"{'operation':<28}{'ops/s':>12}{'mean_ms':>10}{'p50_ms':>10}{'p99_ms':>10}{'n':>8}"
    print(header)
    print("-" * len(header))
    for result in results:
        print(
            f"{result.name:<28}{result.ops:>12.1f}{result.mean:>10.4f}"
            f"{result.p50:>10.4f}{result.p99:>10.4f}{result.count:>8}"
        )


def add_json_out(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json-out",
        default=None,
        help="Write the results as JSON to the given path (besides stdout).",
    )


def maybe_write_json(path: str | None, results: Sequence[BenchResult]) -> None:
    if not path:
        return
    with open(path, "w", encoding="utf-8") as handle:
        json.dump([r.as_dict() for r in results], handle, indent=2)
        handle.write("\n")
    print(f"wrote {path}")
