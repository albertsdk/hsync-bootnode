# Black-box tests — hsync-bootnode

Language-neutral functional tests for the `boot/1` bootstrap node. They are
**independent of the implementation language** (D13): the same suite will
validate the future `rust/` and `c/` ports unchanged.

## Contract

The tests spawn the bootnode executable and observe **only** its public
surface:

- the CLI (`run`, `--version`, `--private`, fail-fast exit codes);
- the `boot/1` wire protocol over QUIC/UDP (`hsync-boot/1` ALPN, NDJSON frames).

They never import `hsync_bootnode` or touch internal state. If the whole
implementation were rewritten while keeping the same CLI + wire contract, the
suite would still pass.

## Running

The suite is gated by `HSYNC_BB_BOOTNODE=1` and uses the Python virtualenv only
as a *test runner* (pytest + aioquic for the wire client):

```bash
cd hsync-bootnode
HSYNC_BB_BOOTNODE=1 python/.venv/bin/python -m pytest -q tests/
```

### Stress suite (opt-in)

`tests/test_bb_bootnode_stress.py` is gated **in addition** by `HSYNC_BB_STRESS=1`
and proves the node stays correct and alive under sustained concurrent load,
bursts, churn, a garbage storm and a TTL sweep under load. Scale is bounded by
environment knobs (read at import time):

```bash
cd hsync-bootnode
HSYNC_BB_BOOTNODE=1 HSYNC_BB_STRESS=1 python/.venv/bin/python -m pytest -q tests/test_bb_bootnode_stress.py
```

| Knob | Default | Meaning |
|---|---|---|
| `HSYNC_BB_BOOTNODE_STRESS_CONNECTIONS` | 4 | concurrent QUIC clients |
| `HSYNC_BB_BOOTNODE_STRESS_ROUNDS` | 4 | register/query/refresh/leave rounds per client |
| `HSYNC_BB_BOOTNODE_STRESS_PEERS` | 50 | peers registered for the discovery/TTL/garbage scenarios |
| `HSYNC_BB_BOOTNODE_STRESS_MAX_P99_MS` | 1000 | p99 latency budget for the mixed-load scenario |

Without `HSYNC_BB_STRESS=1` the module is skipped, so the default suite stays
fast.

## Language selection

The executable under test is resolved from `HSYNC_BOOTNODE_BIN` (a path to the
`hsync-bootnode` binary); it defaults to the Python build
(`python/.venv/bin/hsync-bootnode`). To run the suite against a different
implementation, point the variable at its binary — the CLI contract is the
same:

```bash
HSYNC_BB_BOOTNODE=1 HSYNC_BOOTNODE_BIN=/path/to/hsync-bootnode \
  python/.venv/bin/python -m pytest -q tests/
```

## Readiness and isolation

- Readiness is signalled through the `HSYNC_BOOTNODE_READY_FILE` seam: the
  process writes its PID there once the QUIC listener is bound, and removes it
  on graceful shutdown (`SIGTERM`). The suite keys readiness on the file
  **appearing with a PID**, not on that PID equalling the launcher's: a
  onefile-packaged binary (PyInstaller, the `.deb` payload) runs the app in a
  child process, so the two PIDs differ.
- Each test starts a fresh subprocess with an environment scrubbed of every
  `HSYNC_*` variable and tears it down in a `finally`/fixture, so there are no
  orphan processes or cross-test contamination.
- Protected-bucket keys are provisioned via `--keys-fd` (a pipe, never a file).
- Test data (CIDs, buckets, group keys) is randomized per run; the RNG seed is
  logged (`[seed] <n>`) for reproducible failures.

## Coverage

| Module | Scenarios |
|---|---|
| `test_bb_bootnode_lifecycle.py` | `--version`, fail-fast config, readiness, graceful shutdown, debug mode (peer-aware stderr log) |
| `test_bb_bootnode_register.py` | STUN-echo ack, advertised/observed endpoints, refresh, unknown-CID refresh drop |
| `test_bb_bootnode_query.py` | peer listing, group filter, limit bounds, pipelined frames |
| `test_bb_bootnode_d11.py` | uniform `token_required`, correct/wrong token, no oracle |
| `test_bb_bootnode_private.py` | `--private`/envvar: every bucket gated, unkeyed bucket, gated `leave`, fail-fast without keys, banner |
| `test_bb_bootnode_ratelimit.py` | burst → `rate_limited` + `retry_after` (query/register/bad-token) |
| `test_bb_bootnode_negative.py` | malformed/unknown/oversized/forbidden frames, leave |
| `test_bb_bootnode_ttl.py` | TTL expiry convergence, refresh keeps peer alive |
| `test_bb_bootnode_stress.py` | **opt-in** (`HSYNC_BB_STRESS=1`): sustained mixed load, full-bucket discovery, rate-limit burst + recovery, garbage storm, TTL sweep under query load |

Per-IP rate-limit isolation between *distinct* source IPs is not exercised here
(loopback forces a single source address); it is covered by the white-box unit
suite in `python/tests/test_handler.py`.
