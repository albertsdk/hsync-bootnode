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
| `test_bb_bootnode_lifecycle.py` | `--version`, fail-fast config, readiness, graceful shutdown, debug mode (non-PII) |
| `test_bb_bootnode_register.py` | STUN-echo ack, advertised/observed endpoints, refresh, unknown-CID refresh drop |
| `test_bb_bootnode_query.py` | peer listing, group filter, limit bounds, pipelined frames |
| `test_bb_bootnode_d11.py` | uniform `token_required`, correct/wrong token, no oracle |
| `test_bb_bootnode_private.py` | `--private`/envvar: every bucket gated, unkeyed bucket, gated `leave`, fail-fast without keys, banner |
| `test_bb_bootnode_ratelimit.py` | burst → `rate_limited` + `retry_after` (query/register/bad-token) |
| `test_bb_bootnode_negative.py` | malformed/unknown/oversized/forbidden frames, leave |
| `test_bb_bootnode_ttl.py` | TTL expiry convergence, refresh keeps peer alive |

Per-IP rate-limit isolation between *distinct* source IPs is not exercised here
(loopback forces a single source address); it is covered by the white-box unit
suite in `python/tests/test_handler.py`.
