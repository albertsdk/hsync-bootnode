# Benchmarks — hsync-bootnode

Three tiers, split by language-dependence:

| Tier | Script | Transport | Language-neutral? |
|---|---|---|---|
| L1 | `bench_handler.py` | none (calls `BootHandler.handle`) | **No** — Python-internal micro-benchmark |
| L2 | `bench_quic.py` | real QUIC/UDP loopback | **Yes** — spawns the binary, wire-only |
| L3 | `soak.py` | real QUIC/UDP loopback (sustained) | **Yes** — spawns the binary, wire-only |

L2/L3 launch the bootnode executable (`HSYNC_BOOTNODE_BIN`, default Python
build) and drive it only through the `boot/1` wire protocol, so the same
benchmark runs unchanged against the future `rust/` and `c/` ports. L1 measures
the Python handler in isolation and is not meant to be portable.

## Running

```bash
cd hsync-bootnode

# L1 — handler micro-benchmark (Python-only)
python/.venv/bin/python bench/bench_handler.py --count 2000

# L2 — QUIC loopback load (language-neutral)
python/.venv/bin/python bench/bench_quic.py --connections 50 --frames 200

# L3 — soak (language-neutral)
python/.venv/bin/python bench/soak.py --duration 600 --peers 500 --qps 20

# Against a different implementation
HSYNC_BOOTNODE_BIN=/path/to/hsync-bootnode python/.venv/bin/python bench/bench_quic.py
```

`--json-out FILE` writes machine-readable results on every tier.

## Shared helpers

- `bench/common.py` — deterministic CIDs + timing/stats (stdlib only).
- `tests/harness.py` — wire frame builders, process lifecycle, QUIC client
  (single source shared with the black-box suite).
