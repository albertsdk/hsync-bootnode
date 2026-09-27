# Architecture — hsync-bootnode

One QUIC/UDP listener, in-memory state, no persistence, no logs. The v1
implementation is Python (aioquic); the Rust and C implementations planned in
the repo root `README.md` will share the same wire protocol SSOT
(`protocol-spec/boot-1.md`) and the same fixtures.

## Layers

```
UDP :443
  └─ server.py    QUIC transport (aioquic): TLS 1.3 identity (in-memory by
                  default, opt-in persisted via --identity), mandatory RETRY +
                  address-validation tokens, ALPN "hsync-boot/1", NDJSON frames
                  on one bidi stream
       └─ handler.py   BootHandler: transport-agnostic core — routing table,
                       token authorization (declared protected buckets or
                       every bucket in node-wide private mode), rate limiters,
                       STUN-echo
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
| `python/src/hsync_bootnode/protocol.py` | `boot/1` frames; CID `^[A-Za-z0-9]{21}$`; 64-hex bucket token; client→server discriminated union; server→client `bytes` serializers | `BootRegister`, `BootRefresh`, `BootLeave`, `BootQuery`, `BootAck`, `BootResponse`, `BootPeer`, `Endpoint`, `ObservedEndpoint`, `BootFrame`, `BOOT_FRAME_ADAPTER`, `BOOT_ACK_ADAPTER`, `BOOT_RESPONSE_ADAPTER` |
| `python/src/hsync_bootnode/routing.py` | RAM-only table, TTL/prune/sample, group-agnostic `leave`; secondary indexes (`_by_group`/`_by_cid`/`_pos`) + materialized `PeerRecord.wire` projection | `PeerRecord`, `RoutingTable` (`upsert`, `remove`, `prune`, `sample`, `count`) |
| `python/src/hsync_bootnode/handler.py` | Request pipeline: rate-limit → validate (single pass) → authorize (protected-bucket policy: declared protected buckets, or every bucket when `private=True`) → mutate → reply | `BootHandler.handle`, `BootConfigError`, `OP_IP_BURST`, `WINDOW_SECONDS` |
| `python/src/hsync_bootnode/ratelimit.py` | Sliding windows; `evict_stale` bounds memory (evicts fully-refilled buckets, behaviour-identical) | `TokenBucketLimiter` (`allow`, `retry_after`, `evict_stale`) |
| `python/src/hsync_bootnode/tokens.py` | token derivation `HMAC-SHA256(key, "boot/1" || bucket)[:32]` | `derive_bucket_token`, `verify_bucket_token` |
| `python/src/hsync_bootnode/server.py` | QUIC adapter: self-signed TLS identity (`hsync_common.ssl_utils`, Ed25519), RETRY, frame IO bound to 8 KiB (framing only — parsing/validation lives in `handler.py`); opt-in persistent identity (ADR-0034) | `start_server`, `NodeIdentity`, `make_identity`, `load_or_create_identity`, `load_identity`, `rotate_identity`, `IdentityError`, `BootQuicProtocol` |
| `python/src/hsync_bootnode/upnp.py` | SSDP IGD discovery + SOAP `AddPortMapping`/`DeletePortMapping`; stateless when no IGD | `UpnpManager.run`, `add_port_mapping`, `discover_igd` |
| `python/src/hsync_bootnode/debug.py` | Opt-in **full operation log** on stderr, peer identity included (decision #25); off by default, never on disk (no-log invariant) | `configure_debug`, `debug_enabled`, `debug_log`, `debug_event` |
| `python/src/hsync_bootnode/cli.py` | Typer multi-command app; group keys from `--keys-fd` / `HSYNC_BOOTNODE_KEYS_FD` (read once); fail-fast config; `--ttl`/`--debug`/`--ready-file` seams; `--identity`/`--public-host` + `identity show`/`rotate` | `run`, `identity_show`, `identity_rotate`, `main` (`--version`), `_load_keys` |

## Request flow (per datagram/stream frame)

1. `server.py` reads one newline-terminated frame (≤ 8 KiB, checked on the frame
   length itself so an oversized frame always closes the stream); a frame longer
   than 8 KiB closes the session silently (no-log).
2. `BootHandler.handle` (`python/src/hsync_bootnode/handler.py:150`) validates the
   raw frame in a single pass via the `BootFrame` discriminated union
   (`BOOT_FRAME_ADAPTER.validate_json`). `ValidationError` → silent drop
   (no-log, no oracle, no admission token consumed); only a *valid* frame then
   charges the generic per-IP admission (~10 req/s, burst 50), so a garbage
   sender cannot throttle neighbours behind a shared NAT IP.
3. Type-specific limits: register/refresh 10/min per bucket; query 5/min per
   (IP, bucket) and 30/min per bucket.
4. Protected-bucket check: if the bucket is gated — declared `--protected-bucket` on an open node,
   or *any* bucket on a private node — `verify_bucket_token` decides; failures
   are rate-limited after 5/min per IP and answered uniformly with
   `token_required` / `rate_limited` (+ `retry_after`). A private node answers a
   bucket with no key loaded exactly like a wrong token (no provisioned-set
   oracle).
5. Mutation: `register` upserts (STUN-echo source `ip:port`), `refresh` touches
   TTL and never creates, `leave` removes every `(cid, bucket)` entry
   regardless of group and returns no frame (in private mode it is token-gated
   too, and a refusal is a silent drop — the spec has no `leave` response).
6. Reply: `ack` (register/refresh, carries `observed_endpoint`) or `response`
   (query, random sample up to `limit`, prefer advertised endpoints); returned
   as already-serialized JSON **bytes** (Pydantic `TypeAdapter.dump_json`),
   written verbatim by the transport.

## Security model

- **No-log**: nothing peer-related is written to disk; the TLS identity is
  generated per process by default and persisted only with the opt-in
  `--identity PATH` (the operator's own key+cert, ADR-0034 — not peer data).
  Verified by `python/tests/test_nolog.py` under a read-only filesystem.
- **Anti-amplification**: QUIC RETRY + address-validation before connection
  state (`start_server(..., retry=True)`, `python/src/hsync_bootnode/server.py:168`).
- **Protected buckets**: the group key never enters any record; only the derived token.
  Protected buckets are declared by the operator (`--protected-bucket`,
  repeatable) and fail fast at startup if declared without a key
  (`BootConfigError`, exit code 2).
- **Private node** (`--private` / `HSYNC_BOOTNODE_PRIVATE=1`): the protected-bucket check
  applies to every bucket, `leave` included, and a node started without any
  group key fails fast (`BootConfigError`, exit code 2). It is a policy on the
  same wire contract — no new frame field, no protocol bump. Operator-facing
  procedure (provisioning, rotation, trade-offs) is in `docs/usage.md`.
- **Sandboxed deployment**: hardened systemd unit
  (`packaging/systemd/hsync-bootnode.service`: DynamicUser, protect*,
  SystemCallFilter), launchd plist (`packaging/launchd/it.hsync.bootnode.plist`),
  WinSW service definition (`packaging/windows/hsync-bootnode-service.xml`).

## Target matrix

| Target | Deployment unit | Status |
|---|---|---|
| Linux | `packaging/systemd/hsync-bootnode.service` | v1 |
| macOS | `packaging/launchd/it.hsync.bootnode.plist` | v1 |
| Windows | `packaging/windows/hsync-bootnode-service.xml` (WinSW) | v1 |
| Linux `.deb` (amd64/arm64/armhf) | `../compile_deb.sh` (`-l/--language`, default `python`; `rust`/`c` rejected until those ports exist) + `packaging/deb/` (control, maintainer scripts, deb unit, man page) | v1 |

## Packaging

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
| `python/tests/test_handler.py` | Routing, TTL (frozen clock), protected buckets, private policy (every bucket gated, unkeyed bucket, gated `leave`), rate limits, STUN-echo, frame rejection |
| `python/tests/test_scaffold.py` | Fixtures / spec contract + frame schema positives/negatives (rigid schema) |
| `python/tests/test_server.py` | QUIC loopback: register/query/protected refusal, private-node refusal, garbage frames, pipelined frames on one stream |
| `python/tests/test_identity.py` | Opt-in persistent identity: create/load/rotate, `0600`/`0700` permissions, Ed25519, SAN from bind + `--public-host` |
| `python/tests/test_nolog.py` | Zero-write invariant under read-only fs |
| `python/tests/test_upnp.py` | SSDP/SOAP shapes, error downgrade, stateless no-IGD |
| `python/tests/test_cli.py` | CLI version/fail-fast/keys-fd contract |
| `tests/` (repo root) | **Black-box** suite (language-neutral): spawns the real binary (`HSYNC_BOOTNODE_BIN`), speaks only `boot/1` over QUIC, gated by `HSYNC_BB_BOOTNODE=1` |

### Black-box (language-neutral) tests

The root `tests/` directory holds the functional black-box suite. It is
deliberately **independent of any implementation language**: it launches the
bootnode executable (path via `HSYNC_BOOTNODE_BIN`, defaulting to the Python
build) as a subprocess, waits for the `HSYNC_BOOTNODE_READY_FILE` readiness
seam (keyed on the ready file appearing with a PID, not on PID equality with the
launcher — a onefile-packaged binary runs the app in a child process), and
drives it **only** through the public CLI + `boot/1` wire protocol
(QUIC/UDP, NDJSON, ALPN `hsync-boot/1`). It never imports
`hsync_bootnode`. The same suite will validate the future `rust/` and `c/`
ports unchanged. Benchmarks (`bench/`) follow the same rule for L2/L3
(`bench_quic.py`, `soak.py` spawn the binary); L1 (`bench/bench_handler.py`) and
the diagnostics (L4 `bench/profile_handshake.py` — handshake vs `aioquic`
closing drain; L5 `bench/cpu_saturation.py` — load vs node CPU%) are
Python-internal.

## Known gaps / next phases

The monorepo `p2p`/bootnode migration is **complete**:

- **Done**: `hsync-common` mirror (`protocol/bootnode.py`, fixtures, drift test,
  capabilities v3); the advisory `capacity` hint (`0..32`) and the derived
  `reachable` flag relayed `register` → record → `query` (decisions 23–24); the
  bootnode's opt-in **debug operation log** (decision 25); client `hsync p2p`
  with both discovery plans and its black-box suite; desktop mode, wd-os5
  packaging; the peer data-plane protocol is `p2p/1`.
- **Open**: **Android client for `boot/1`** (deferred; the QUIC stack is decided:
  `quiche` via JNI). Resumption document: the Android project's
  [`quic-jni`](https://github.com/albertsdk/hsync-android/blob/main/llm-wiki/modules/quic-jni.md)
  page.
- **Not started (v2)**: Rust (`quinn`) and optional C implementations.
