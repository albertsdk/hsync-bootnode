# Contributing to hsync-bootnode

Thanks for your interest in contributing! This guide covers the development
workflow for the HSYNC bootnode — the optional, stateless `boot/1` discovery node
for P2P topologies.

`hsync-bootnode` is a **multi-language** repository: one wire protocol with
several implementations of the *same* contract. `python/` is the reference (v1);
`rust/` is the planned v2. The specification and the fixtures are shared, so a
wire change must keep every implementation byte-identical.

## Prerequisites

### Python implementation (`python/`, v1)

- Python `>=3.12,<3.15` (lint/type target: **3.13**)
- [Poetry](https://python-poetry.org/) to create the in-project virtualenv
  (`.venv/` is local and **not** committed)

### Rust implementation (`rust/`, planned v2)

- Stable Rust **1.98+** (`rustup` stable channel) — the crate does not exist yet

### Packaging and black-box tests

- `dpkg-deb` (dpkg-dev); Docker + `qemu-user-static` for `deb-all`
- `fakeroot` (optional) for `.deb` assembly

## Repository Layout

| Path | Content |
|---|---|
| `protocol-spec/boot-1.md` | Wire-protocol specification — the **single source of truth (SSOT)** |
| `fixtures/bootnode-*.json` | Shared protocol fixtures (single source for every language) |
| `tests/` | **Language-neutral** black-box suite (spawns the binary, wire-only) |
| `bench/` | Benchmarks; L2/L3 are language-neutral, L1/L4/L5 are Python-internal |
| `python/` | v1 implementation — Python + aioquic, with its white-box unit suite |
| `rust/` | v2 implementation — Rust + quinn (planned, not started) |
| `packaging/` | OS service units (systemd / launchd / WinSW) and the `.deb` payload |
| `compile_deb.sh` | Root `.deb` assembler (`-l/--language`, `deb`/`deb-all`) |
| `llm-wiki/` | Internal agent knowledge base |
| `docs/` | End-user documentation |
| `AGENTS.md` | Coding rules for AI agents — a useful checklist for humans too |

Each implementation is built, linted and tested from **its own** directory; the
root scripts only dispatch and assemble packages.

## Setup

```bash
# Python (v1): creates the in-project .venv from pyproject.toml + poetry.lock
cd hsync-bootnode/python && poetry install
```

## Building

```bash
# Python standalone binary (PyInstaller)
cd hsync-bootnode/python && ./compile.sh                  # host OS/arch
cd hsync-bootnode/python && ./compile.sh -t onedir -o build/onedir

# .deb package (root assembler; python is the only language implemented today)
cd hsync-bootnode && ./compile_deb.sh -t deb              # host architecture
cd hsync-bootnode && ./compile_deb.sh -t deb-all          # amd64, arm64, armhf (Docker)
cd hsync-bootnode && ./compile_deb.sh -l python -t deb
```

`-l/--language` defaults to `python` and rejects `rust` until that port exists;
`-v/--version` overrides the version read from `python/pyproject.toml`.

## Code Style

### Python

[ruff](https://docs.astral.sh/ruff/) for linting and formatting (line length 100,
target `py313`), plus mypy:

```bash
cd hsync-bootnode/python && .venv/bin/python -m ruff check .
cd hsync-bootnode/python && .venv/bin/python -m ruff format --check .
cd hsync-bootnode/python && .venv/bin/python -m mypy src/hsync_bootnode
```

`ruff` is **not** on `PATH`: always invoke it through the virtualenv as
`.venv/bin/python -m ruff`. `ruff check` exits non-zero when violations remain —
fix them, never mask them with `|| true`.

The language-neutral code at the repository root (`tests/`, `bench/`) is linted
with the root `ruff.toml`:

```bash
cd hsync-bootnode && python/.venv/bin/python -m ruff check tests bench
```

### Rust (once `rust/` lands)

```bash
cd hsync-bootnode/rust && cargo fmt --check
cd hsync-bootnode/rust && cargo clippy --all-targets -- -D warnings
```

`unwrap()`, `expect()` and `panic!()` are not allowed in production code, and
`unsafe` is not allowed by default. A component that decodes untrusted input must
ship `cargo fuzz` targets; a change that needs `unsafe` must document its
invariants and be covered by `cargo miri test`.

## Tests

### Python unit suite (white-box)

```bash
# full suite, or a single test
cd hsync-bootnode/python && .venv/bin/python -m pytest -q
cd hsync-bootnode/python && .venv/bin/python -m pytest -q tests/test_handler.py::test_name
```

### Black-box suite (language-neutral)

Gated by `HSYNC_BB_BOOTNODE=1`; the Python virtualenv acts only as the *test
runner* (pytest + aioquic for the wire client). The tests spawn the executable and
observe only the public surface — the CLI and the `boot/1` wire — so they must
pass unchanged against another implementation.

```bash
cd hsync-bootnode && HSYNC_BB_BOOTNODE=1 python/.venv/bin/python -m pytest -q tests/

# run the same suite against the future Rust binary
cd hsync-bootnode && HSYNC_BB_BOOTNODE=1 HSYNC_BOOTNODE_BIN=/path/to/binary \
    python/.venv/bin/python -m pytest -q tests/
```

The opt-in stress suite adds `HSYNC_BB_STRESS=1` on top, with scale knobs read at
import time (`HSYNC_BB_BOOTNODE_STRESS_CONNECTIONS`, `…_ROUNDS`, `…_PEERS`,
`…_MAX_P99_MS`).

### Benchmarks

```bash
# L1 — handler micro-benchmark (Python-internal)
cd hsync-bootnode && python/.venv/bin/python bench/bench_handler.py --count 2000

# L2 — QUIC loopback load (language-neutral)
cd hsync-bootnode && python/.venv/bin/python bench/bench_quic.py --connections 50 --frames 200
```

L2/L3 drive the binary through the wire protocol only (path via
`HSYNC_BOOTNODE_BIN`, default the Python build), so they run unchanged against the
Rust port. See [`bench/README.md`](bench/README.md) for the full tier table and
the measurement methodology.

> From the workspace root, `make lint` (both ruff surfaces), `make test-python`
> (unit tests) and `make test-bb-bootnode` (black-box suite) run the same checks;
> the commands above are the single-repository form.

## Contract Discipline

`protocol-spec/boot-1.md` is the single source of truth: never fork it inside an
implementation, and never let one implementation drift from it.

- Every frame model rejects unknown fields (pydantic `extra="forbid"` in Python).
  A malformed or targeted frame is silently dropped, never reinterpreted.
- A protocol change updates the spec, the committed `fixtures/`, the frame models
  of **every** implementation and the language-neutral suite in the same change.
- These hard invariants must survive every change:
  - **No-log** — no peer data (IPs, CIDs, timestamps) is ever written to disk,
    enforced by `python/tests/test_nolog.py` under a read-only filesystem.
  - **RAM only** — the routing table, keys and rate-limit windows have no
    persistence layer.
  - **Rigid schema** and **protected buckets** — constant-time token compare and
    uniform refusals that reveal nothing about bucket existence.
  - **Zero backward compatibility** — a breaking contract change is a protocol
    version bump, with no shim and no migration phase.

## Cross-Project Impact

The `boot/1` contract is mirrored outside this repository, so a wire change must
update the consumers and their parity tests atomically:

- `hsync-common` — `hsync_common/protocol/bootnode.py` (frames + validators) and
  the committed fixtures
- `hsync-client` — `BootnodeClient` / the bootnode discovery plan
- `hsync-android` — the Kotlin `BootnodeProtocol` mirror

## Documentation

Two sets, both updated within the same change:

- `llm-wiki/` — internal agent knowledge base (architecture, data models, decisions)
- `docs/` — end-user documentation (welcome page, usage reference)

Any user-visible change — CLI flags, `HSYNC_BOOTNODE_*` variables, defaults or
behavior — must also keep these in sync:

- `packaging/deb/usr/share/man/man1/hsync-bootnode.1` (man page: `OPTIONS`,
  `ENVIRONMENT`, `EXIT STATUS`, examples)
- the OS service units in `packaging/` and the `--help` text of
  `python/compile.sh` / `compile_deb.sh`
- `README.md` (layout table, quick start, documentation index)

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):
`type(scope): summary` (`feat`, `fix`, `docs`, `refactor`, `test`, `chore`, …).

## Pull Requests

- `hsync-bootnode` is its own git repository: verify it with
  `git rev-parse --git-dir` before any git command, and make **one commit per
  repository**.
- Inspect what you are about to commit (`git status --short`,
  `git diff --cached`) and prefer explicit paths over `git add -A`.
- **Never stage build outputs or secrets**: `dist/`, `build/`, `target/`,
  `*.deb`, `*.o`/`*.a`/`*.so`, `*.env`, and any local `group-keys` file.
- Keep changes focused, covered by a test that fails before the fix, and free of
  speculative behavior, silent fallbacks or weakened assertions.
- Before opening a PR, run the Python unit suite, the lint/format/mypy checks and
  the black-box suite (`HSYNC_BB_BOOTNODE=1`); when the change touches the wire
  contract, add the cross-project updates listed above.