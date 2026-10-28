# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Alberto Basso

"""Compare two benchmark runs and flag regressions over a noise floor.

Every ``bench/bench_*.py`` script can dump its results as one JSON array via
``--json-out`` (``bench_handler.py``, ``bench_quic.py``, ``soak.py``). This tool
pairs two such inputs (a file, or a directory of ``*.json`` merged) by operation
name and reports the per-operation delta — the language-neutral way to quantify a
regression or the Python→C port, on the same metrics the tiers emit.

Regression signal (robust to timer noise): an operation is flagged only when its
**median** (``p50_ms``) grew by more than ``--threshold`` **and** its before-run
mean sat at or above ``--min-mean-ms``. The noise floor exists because many
handled operations are sub-microsecond; at that scale ``perf_counter``
resolution alone can move the numbers by tens of percent, so a raw ratio is a
false positive. Operations present in ``before`` but absent from ``after`` are
always flagged (a removed scenario must never go unnoticed).

The exit code is 1 when at least one regression is flagged, 0 otherwise, so the
tool can gate a CI/PR check without being collected by pytest (it is dev
tooling, not a test). It never imports ``hsync_bootnode`` (language-neutral).

Usage:
    cd hsync-bootnode

    # L1 handler A/B (or L2/L3 with the same flags)
    python/.venv/bin/python bench/bench_handler.py --count 2000 --json-out /tmp/h1.json
    # ... apply a change ...
    python/.venv/bin/python bench/bench_handler.py --count 2000 --json-out /tmp/h2.json
    python/.venv/bin/python bench/compare.py /tmp/h1.json /tmp/h2.json

    # Python build vs a different implementation (C), same tier + count
    HSYNC_BOOTNODE_BIN=/path/to/c/binary \\
        python/.venv/bin/python bench/bench_quic.py --json-out /tmp/c.json
    python/.venv/bin/python bench/compare.py /tmp/py.json /tmp/c.json --threshold 1.15
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

__all__ = ["CompareEntry", "compare"]


@dataclass
class CompareEntry:
    """One operation compared across two runs, with its regression verdict."""

    name: str
    before_mean_ms: float
    after_mean_ms: float
    before_p50_ms: float
    after_p50_ms: float
    p50_ratio: float | None
    missing: bool
    regressed: bool


def compare(
    before: Sequence[dict],
    after: Sequence[dict],
    *,
    threshold: float = 1.10,
    min_mean_ms: float = 0.001,
) -> list[CompareEntry]:
    """Pair ``before``/``after`` result dicts (as emitted by ``BenchResult.as_dict``).

    Returns one :class:`CompareEntry` per operation in ``before``, in the input
    order. ``regressed`` is true when the operation's median grew beyond
    ``threshold`` while its before-run mean met ``min_mean_ms``, or when the
    operation is missing entirely from ``after``.
    """
    before_by_name = {entry["name"]: entry for entry in before}
    after_by_name = {entry["name"]: entry for entry in after}

    entries: list[CompareEntry] = []
    for name, before_entry in before_by_name.items():
        after_entry = after_by_name.get(name)
        if after_entry is None:
            entries.append(
                CompareEntry(
                    name=name,
                    before_mean_ms=before_entry["mean_ms"],
                    after_mean_ms=0.0,
                    before_p50_ms=before_entry["p50_ms"],
                    after_p50_ms=0.0,
                    p50_ratio=None,
                    missing=True,
                    regressed=True,
                )
            )
            continue

        before_p50 = before_entry["p50_ms"]
        after_p50 = after_entry["p50_ms"]
        ratio = (after_p50 / before_p50) if before_p50 > 0 else None
        eligible = before_entry["mean_ms"] >= min_mean_ms
        regressed = bool(eligible and ratio is not None and after_p50 > before_p50 * threshold)
        entries.append(
            CompareEntry(
                name=name,
                before_mean_ms=before_entry["mean_ms"],
                after_mean_ms=after_entry["mean_ms"],
                before_p50_ms=before_p50,
                after_p50_ms=after_p50,
                p50_ratio=ratio,
                missing=False,
                regressed=regressed,
            )
        )
    return entries


def _load(path: str) -> list[dict]:
    """Load one JSON array file, or every ``*.json`` in a directory (merged)."""
    base = Path(path)
    if base.is_dir():
        merged: list[dict] = []
        for child in sorted(base.glob("*.json")):
            merged.extend(json.loads(child.read_text(encoding="utf-8")))
        return merged
    return json.loads(base.read_text(encoding="utf-8"))


def _print_report(entries: list[CompareEntry]) -> None:
    header = (
        f"{'operation':<28}{'before_mean':>12}{'after_mean':>12}{'p50_ratio':>12}{'status':>10}"
    )
    print(header)
    print("-" * len(header))
    for entry in entries:
        ratio = "—" if entry.p50_ratio is None else f"{entry.p50_ratio:>10.3f}x"
        status = "REGRESSED" if entry.regressed else ("missing" if entry.missing else "ok")
        print(
            f"{entry.name:<28}{entry.before_mean_ms:>12.4f}{entry.after_mean_ms:>12.4f}"
            f"{ratio:>12}{status:>10}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", help="JSON file or directory of *.json (the baseline).")
    parser.add_argument("after", help="JSON file or directory of *.json (the candidate).")
    parser.add_argument(
        "--threshold",
        type=float,
        default=1.10,
        help="Median slowdown ratio that counts as a regression (default: 1.10).",
    )
    parser.add_argument(
        "--min-mean-ms",
        type=float,
        default=0.001,
        help="Noise floor: ops with a before-run mean below this are not flagged "
        "(default: 0.001 ms).",
    )
    args = parser.parse_args()

    entries = compare(
        _load(args.before),
        _load(args.after),
        threshold=args.threshold,
        min_mean_ms=args.min_mean_ms,
    )
    _print_report(entries)

    regressions = [entry for entry in entries if entry.regressed]
    if regressions:
        names = ", ".join(entry.name for entry in regressions)
        print(f"\n{len(regressions)} regression(s) flagged: {names}")
        sys.exit(1)
    print("\nno regressions flagged")


if __name__ == "__main__":
    main()
