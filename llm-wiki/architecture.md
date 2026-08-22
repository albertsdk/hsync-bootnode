# Architecture — hsync-bootnode

One QUIC/UDP listener, in-memory state, no persistence, no logs. The v1
implementation is Python (aioquic); the Rust and C implementations planned in
the repo root `README.md` will share the same wire protocol SSOT
(`protocol-spec/boot-1.md`) and the same fixtures.

## Layers

```
UDP :443
  └─ server.py    QUIC transport (aioquic): TLS 1.3 in-memory identity,
                  mandatory RETRY + address-validation tokens, ALPN
                  "hsync-boot/1", NDJSON frames on one bidi stream
       └─ handler.py   BootHandler: transport-agnostic core — routing table,
                       D11 token authorization, rate limiters, STUN-echo
            ├─ routing.py    in-memory table keyed (cid, bucket, group)
            ├─ ratelimit.py  sliding-window limiters (spec §5)
            └─ tokens.py     bucket_token derivation + constant-time compare
  └─ protocol.py  pydantic models for every boot/1 frame (extra="forbid")
  └─ upnp.py      zero-touch UDP port mapping via SSDP + SOAP (best-effort)
  └─ cli.py       Typer CLI: `hsync-bootnode run [OPTIONS]`, `--version`
```

## Module map

| Module | Responsibility | Key symbols |
|---|---|---|
| `python/src/hsync_bootnode/protocol.py` | `boot/1` frames; CID `^[A-Za-z0-9]{21}$`; 64-hex bucket token | `BootRegister`, `BootRefresh`, `BootLeave`, `BootQuery`, `BootAck`, `BootResponse`, `BootPeer`, `Endpoint`, `ObservedEndpoint` |
| `python/src/hsync_bootnode/routing.py` | RAM-only table, TTL/prune/sample, group-agnostic `leave` | `PeerRecord`, `RoutingTable` (`upsert`, `remove`, `prune`, `sample`, `count`) |
| `python/src/hsync_bootnode/handler.py` | Request pipeline: validate → authorize (D11) → rate-limit → mutate → reply | `BootHandler.handle`, `BootConfigError`, `OP_IP_BURST`, `WINDOW_SECONDS` |
| `python/src/hsync_bootnode/ratelimit.py` | Sliding windows | `TokenBucketLimiter` (`allow`, `retry_after`) |
| `python/src/hsync_bootnode/tokens.py` | D11 derivation `HMAC-SHA256(key, "boot/1" || bucket)[:32]` | `derive_bucket_token`, `verify_bucket_token` |
| `python/src/hsync_bootnode/server.py` | QUIC adapter: in-memory self-signed TLS identity (`hsync_common.ssl_utils`), RETRY, frame IO bound to 8 KiB | `start_server`, `NodeIdentity`, `make_identity`, `BootQuicProtocol` |
| `python/src/hsync_bootnode/upnp.py` | SSDP IGD discovery + SOAP `AddPortMapping`/`DeletePortMapping`; stateless when no IGD | `UpnpManager.run`, `add_port_mapping`, `discover_igd` |
| `python/src/hsync_bootnode/debug.py` | Opt-in stderr diagnostics (non-PII); off by default (no-log D7) | `configure_debug`, `debug_log` |
| `python/src/hsync_bootnode/cli.py` | Typer multi-command app; group keys from `--keys-fd` / `HSYNC_BOOTNODE_KEYS_FD` (read once); fail-fast config; `--ttl`/`--debug`/`--ready-file` seams | `run`, `main` (`--version`), `_load_keys` |

## Request flow (per datagram/stream frame)

1. `server.py` reads one newline-terminated JSON frame (≤ 8 KiB); malformed →
   silently dropped (no-log, no oracle).
2. `BootHandler.handle` (`python/src/hsync_bootnode/handler.py:125`) checks the
   generic per-IP admission (~10 req/s, burst 50).
3. Frame validated by its pydantic model; `ValidationError` → drop.
4. Type-specific limits: register/refresh 10/min per bucket; query 5/min per
   (IP, bucket) and 30/min per bucket.
5. D11: if the bucket is protected, `verify_bucket_token` decides; failures
   are rate-limited after 5/min per IP and answered uniformly with
   `token_required` / `rate_limited` (+ `retry_after`).
6. Mutation: `register` upserts (STUN-echo source `ip:port`), `refresh` touches
   TTL and never creates, `leave` removes every `(cid, bucket)` entry
   regardless of group and returns no frame.
7. Reply: `ack` (register/refresh, carries `observed_endpoint`) or `response`
   (query, random sample up to `limit`, prefer advertised endpoints).

## Security model

- **No-log**: nothing peer-related is written to disk; TLS identity is
  generated per process and never persisted. Verified by
  `python/tests/test_nolog.py` under a read-only filesystem.
- **Anti-amplification**: QUIC RETRY + address-validation before connection
  state (`start_server(..., retry=True)`, `python/src/hsync_bootnode/server.py:168`).
- **D11**: the group key never enters any record; only the derived token.
  Protected buckets are declared by the operator (`--protected-bucket`,
  repeatable) and fail fast at startup if declared without a key
  (`BootConfigError`, exit code 2).
- **Sandboxed deployment**: hardened systemd unit
  (`packaging/systemd/hsync-bootnode.service`: DynamicUser, protect*,
  SystemCallFilter), launchd plist (`packaging/launchd/it.hsync.bootnode.plist`),
  WinSW service definition (`packaging/windows/hsync-bootnode-service.xml`).

## Target matrix (D12)

| Target | Deployment unit | Status |
|---|---|---|
| Linux | `packaging/systemd/hsync-bootnode.service` | v1 |
| macOS | `packaging/launchd/it.hsync.bootnode.plist` | v1 |
| Windows | `packaging/windows/hsync-bootnode-service.xml` (WinSW) | v1 |
| Linux `.deb` (amd64/arm64/armhf) | `../compile_deb.sh` (`-l/--language`, default `python`; `rust`/`c` rejected until those ports exist) + `packaging/deb/` (control, maintainer scripts, deb unit, man page) | v1 |

## Packaging (Fase 1-bis)

- `python/compile.sh` builds binaries only (`native` host standalone,
  `onedir` bundle consumed by the root assembler). `python/dist/` and
  `python/build/` are git-ignored build outputs.
- `../compile_deb.sh -t deb` embeds the selected language's payload
  (today `python/compile.sh -t onedir`) as `/usr/lib/hsync-bootnode/` with a
  `/usr/bin/hsync-bootnode` symlink, the hardened deb systemd unit, and the
  gzipped man page; `DEBIAN/postinst` creates `/etc/hsync-bootnode/` (0750)
  for the out-of-package group-keys file and never enables the service.
- `rust/`/`c` ports plug in by extending `validate_language()`,
  `_build_binary()` and `_container_build_cmd()` in `../compile_deb.sh`
  (dispatch points, fail-fast contract) — never by adding `deb` logic inside
  the per-language script.

## Tests

| Suite | Scope |
|---|---|
| `python/tests/test_handler.py` | Routing, TTL (frozen clock), D11, rate limits, STUN-echo, frame rejection |
| `python/tests/test_scaffold.py` | Fixtures / spec contract + frame schema positives/negatives (rigid D3) |
| `python/tests/test_server.py` | QUIC loopback: register/query/protected refusal, garbage frames, pipelined frames on one stream |
| `python/tests/test_nolog.py` | Zero-write invariant under read-only fs |
| `python/tests/test_upnp.py` | SSDP/SOAP shapes, error downgrade, stateless no-IGD |
| `python/tests/test_cli.py` | CLI version/fail-fast/keys-fd contract |
| `tests/` (repo root) | **Black-box** suite (language-neutral): spawns the real binary (`HSYNC_BOOTNODE_BIN`), speaks only `boot/1` over QUIC, gated by `HSYNC_BB_BOOTNODE=1` |

### Black-box (language-neutral) tests

The root `tests/` directory holds the functional black-box suite. It is
deliberately **independent of any implementation language**: it launches the
bootnode executable (path via `HSYNC_BOOTNODE_BIN`, defaulting to the Python
build) as a subprocess, waits for the `HSYNC_BOOTNODE_READY_FILE` readiness
seam, and drives it **only** through the public CLI + `boot/1` wire protocol
(QUIC/UDP, NDJSON, ALPN `hsync-boot/1`). It never imports
`hsync_bootnode`. The same suite will validate the future `rust/` and `c/`
ports unchanged. Benchmarks (`bench/`) follow the same rule for L2/L3
(`bench_quic.py`, `soak.py` spawn the binary); only L1 (`bench/bench_handler.py`)
is Python-internal.

## Known gaps / next phases (per `PIANO-hsync-bootnode-p2p.md`)

- Fase 2: move `PROTOCOL_VERSION_BOOT`, frame models, token derivation and D11
  rules into `hsync-common` (`protocol/bootnode.py`) + fixtures drift tests +
  capabilities v3.
- Fase 3+: client `hsync p2p`, desktop mode, Android mirror (`quiche`).
- Rust (quinn) and C implementations: not started.
