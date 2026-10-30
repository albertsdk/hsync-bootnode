"""Coverage-guided Python fuzzer for the rdv/1 decoder (arc feedback, in-process).

How it works: every iteration executes one fuzzed frame through the SAME
security invariants as ``fuzz/fuzz_boot.py`` (:func:`fuzz_boot.handle_one` —
never raises, shaped reply, no cross-record/cross-bucket leak) while a
``coverage.Coverage`` tracer measures the executed branch arcs of the
``hsync_rendezvous`` package. An input whose arc signature contains arcs never
seen before is kept as a corpus seed, and later generations are derived by
byte-mutating corpus members (AFL-style greedy guidance, at Python-branch
granularity instead of machine edges).

Why not Atheris/libFuzzer: the environment has no clang and Atheris publishes
no Python 3.14 wheels, so an in-process ``coverage.py`` feedback loop is the
only applicable coverage-guided engine for the Python v1 (it trades execution
speed for portability; the CI burst stays tiny, long sessions are standalone).
libFuzzer (``clang -fsanitize=fuzzer``) remains the hard requirement for the C
port (repo rule for network-facing C code) — it needs its own clang toolchain and
the ``c/`` tree, which is not started.

The harness is deterministic for a given seed; ``coverage.py`` is an optional
dev dependency (installed in the project virtualenv; add it permanently with
``poetry add --group dev coverage``).

Run:
    .venv/bin/python fuzz/fuzz_guided.py --seconds 60
    .venv/bin/python fuzz/fuzz_guided.py --iterations 50000 --seed 7
    .venv/bin/python fuzz/fuzz_guided.py --seconds 300 --corpus-out /tmp/corpus.hex
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path
from typing import Any

try:
    import coverage
except ImportError as exc:  # pragma: no cover - dev-environment guidance
    raise SystemExit(
        "coverage-guided fuzzing needs coverage.py in the project virtualenv:\n"
        "  pip install coverage    (or: poetry add --group dev coverage)"
    ) from exc

import fuzz_boot
from fuzz_boot import (
    Finding,
    depth_bombs,
    frame_batch,
    fresh_handler,
    handle_one,
    mutate_bytes,
    random_lines,
    raw_garbage,
    seed_corpus,
    template_mutations,
)

__all__ = ["run_guided"]

# Arc feedback targets the daemon package only (never the harness itself).
_INCLUDE = ["*/hsync_rendezvous/*"]
# A 512-member evolving corpus bounds memory and keeps the seed mix fresh;
# eviction is FIFO (deterministic), unlike libFuzzer's energy schedule.
_CORPUS_CAP = 512
# Fresh handler window (same cadence as the static fuzz: budgets reset).
_WINDOW = 250


class _ArcMeter:
    """Per-iteration arc signature from one reusable coverage tracer."""

    def __init__(self) -> None:
        self._cov = coverage.Coverage(branch=True, data_file=None, include=_INCLUDE)

    def arcs(self, fn: Any) -> frozenset[tuple[str, tuple[int, int]]]:
        """Run ``fn`` traced; return the frozenset of (file, arc) tuples."""
        self._cov.erase()
        self._cov.start()
        try:
            fn()
        finally:
            self._cov.stop()
        data = self._cov.get_data()
        signature: set[tuple[str, tuple[int, int]]] = set()
        for filename in data.measured_files():
            for arc in data.arcs(filename) or ():
                signature.add((filename, arc))
        return frozenset(signature)


def _guided_frame(rng: random.Random, dynamic: list[bytes], static: list[bytes]) -> bytes:
    """One candidate input: mostly corpus mutation, plus the static families."""
    pick = rng.random()
    if dynamic and pick < 0.45:
        single = mutate_bytes(rng, rng.choice(dynamic))
    elif pick < 0.70:
        single = next(template_mutations(rng))
    elif pick < 0.80:
        single = next(depth_bombs(rng))
    elif pick < 0.90:
        single = next(random_lines(rng))
    else:
        single = next(raw_garbage(rng))
    return frame_batch(rng, single, static)


def run_guided(
    *,
    iterations: int | None = None,
    seconds: float = 0.0,
    seed: int = 0,
    handler: Any = None,
    corpus_out: Path | None = None,
    corpus_in: Path | None = None,
) -> dict[str, int]:
    """Run the coverage-guided loop; raises ``Finding`` on a violated invariant.

    Returns ``{"iterations": n, "arcs": unique_arcs, "corpus": kept_seeds,
    "findings": 0}`` — ``findings`` is 0 on the clean-exit path by definition.
    """
    deadline = (time.monotonic() + seconds) if seconds > 0 else None
    if iterations is None and deadline is None:
        iterations = 10000  # never an unbounded run by accident

    rng = random.Random(seed)
    static = seed_corpus()
    # Evolving corpus: spec fixtures + templates rendered once, plus every
    # arc-expanding input discovered along the way.
    dynamic: list[bytes] = list(static)
    dynamic_set: set[bytes] = set(dynamic)
    if corpus_in is not None:
        for line in corpus_in.read_text("utf-8").splitlines():
            if line.strip():
                raw = bytes.fromhex(line.strip())
                if raw not in dynamic_set:
                    dynamic.append(raw)
                    dynamic_set.add(raw)

    known_arcs: set[frozenset[tuple[str, tuple[int, int]]]] = set()
    meter = _ArcMeter()
    if handler is None:
        handler = fresh_handler()
    total_arcs: set[tuple[str, tuple[int, int]]] = set()

    count = 0
    while iterations is None or count < iterations:
        if deadline is not None and time.monotonic() >= deadline:
            break
        raw = _guided_frame(rng, dynamic, static)
        try:
            signature = meter.arcs(lambda: handle_one(handler, raw))  # noqa: B023
        except Finding:
            print(
                f"GUIDED FINDING seed={seed} iteration={count} input={fuzz_boot.render(raw)}",
                file=sys.stderr,
            )
            raise
        count += 1
        total_arcs |= signature
        if signature not in known_arcs:
            known_arcs.add(signature)
            if raw not in dynamic_set:
                dynamic.append(raw)
                dynamic_set.add(raw)
                if len(dynamic) > _CORPUS_CAP:  # deterministic FIFO eviction
                    evicted = dynamic.pop(0)
                    dynamic_set.discard(evicted)
        if count % _WINDOW == 0:
            handler = fresh_handler()  # fresh budgets/records, fresh accept paths

    if corpus_out is not None:
        corpus_out.write_text("\n".join(raw.hex() for raw in dynamic) + "\n", encoding="utf-8")
    return {
        "iterations": count,
        "arcs": len(total_arcs),
        "corpus": len(dynamic),
        "findings": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--iterations", type=int, default=0, help="iteration budget (0 = default/time only)"
    )
    parser.add_argument(
        "--seconds", type=float, default=0.0, help="wall-time budget (default: off)"
    )
    parser.add_argument("--seed", type=int, default=0, help="deterministic seed (default 0)")
    parser.add_argument(
        "--corpus-out", type=Path, default=None, help="write the evolved corpus (hex per line)"
    )
    parser.add_argument(
        "--corpus-in", type=Path, default=None, help="resume from a saved corpus (hex per line)"
    )
    args = parser.parse_args(argv)
    begin = time.monotonic()
    try:
        report = run_guided(
            iterations=args.iterations if args.iterations > 0 else None,
            seconds=args.seconds,
            seed=args.seed,
            corpus_out=args.corpus_out,
            corpus_in=args.corpus_in,
        )
    except Finding as exc:
        print(f"guided fuzz: FINDING after {time.monotonic() - begin:.1f}s", file=sys.stderr)
        print(f"guided fuzz: {exc}", file=sys.stderr)
        return 1
    took = time.monotonic() - begin
    print(
        f"guided fuzz: clean (iterations={report['iterations']}, arcs={report['arcs']}, "
        f"corpus={report['corpus']}, seed={args.seed}, {took:.1f}s, "
        f"{report['iterations'] / max(took, 1e-9):.0f} it/s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
