# Architecture — hsync-bootnode

One QUIC/UDP listener, in-memory routing state, no logs; the only persisted
artifact is the node's own TLS identity. The v1
implementation is Python (aioquic); the Rust implementation planned in
the repo root `README.md` will share the same wire protocol SSOT
(`protocol-spec/boot-1.md`) and the same fixtures.

## Layers

```
UDP :443
  └─ server.py    QUIC transport (aioquic): TLS 1.3 identity (ECDSA P-256,
                  persisted by default, in-memory via --ephemeral), mandatory RETRY
                  + address-validation tokens, ALPN "hsync-boot/1", NDJSON frames
                  on one bidi stream
       └─ handler.py   BootHandler: transport-agnostic core — routing table,
                       token authorization (declared protected buckets or
                       every bucket in node-wide private mode), rate limiters,
                       STUN-echo
             ├─ routing.py    in-memory table keyed (cid, bucket, group), bounded
             ├─ ratelimit.py  bounded sliding-window limiters (peek + eviction)
             ├─ resources.py  host RAM/CPU-derived ceilings for table + limiters
             └─ tokens.py     bucket_token derivation + constant-time compare
  └─ protocol.py  pydantic models for every boot/1 frame (extra="forbid")
  └─ upnp.py      zero-touch UDP port mapping via SSDP + SOAP (best-effort)
  └─ cli.py       Typer CLI: `hsync-bootnode run [OPTIONS]`, `--version`
```

## Module map

| Module | Responsibility | Key symbols |
|---|---|---|
| `python/src/hsync_bootnode/protocol.py` | `boot/1` frames; CID `^[A-Za-z0-9]{21}$`; 64-hex bucket token; client→server discriminated union; server→client `bytes` serializers | `BootRegister`, `BootRefresh`, `BootLeave`, `BootQuery`, `BootAck`, `BootResponse`, `BootPeer`, `Endpoint`, `ObservedEndpoint`, `BootFrame`, `BOOT_FRAME_ADAPTER`, `BOOT_ACK_ADAPTER`, `BOOT_RESPONSE_ADAPTER` |
| `python/src/hsync_bootnode/routing.py` | RAM-only table, TTL/prune/sample, source-IP ownership on mutation, bounded by a `max_records` ceiling; secondary indexes (`_by_group`/`_by_cid`/`_pos`) + materialized `PeerRecord.wire` projection | `PeerRecord`, `RoutingTable` (`upsert` → `bool`, `remove`, `prune`, `sample`, `count`, `source_ips`) |
| `python/src/hsync_bootnode/handler.py` | Request pipeline: malformed-frame pre-parse gate → validate (single pass) → per-IP admission → per-IP/per-(IP,bucket) limits → authorize (constant-time; declared protected buckets, or every bucket when `private=True`) → ownership check → mutate → reply | `BootHandler.handle`, `BootConfigError`, `OP_IP_BURST`, `WINDOW_SECONDS`, `_may_replace`, `_authorize` |
| `python/src/hsync_bootnode/ratelimit.py` | Thin facade over the `hsync_common.ratelimit.TokenBucketLimiter` SSOT (shared with `hsync-client`); keeps the import path used by the boot server/handler/tests | `TokenBucketLimiter` (`allow`, `has_tokens`, `retry_after`, `evict_stale`) |
| `python/src/hsync_bootnode/resources.py` | Read-only host detection (available/total RAM, cgroup limit, CPU count) → `ResourceLimits` ceilings for the routing table, limiter maps and connection guard; conservative fallback when `/proc` is hidden | `ResourceLimits` (`detect`, `as_fields`), `available_memory_bytes`, `total_memory_bytes`, `cpu_count` |
| `python/src/hsync_bootnode/tokens.py` | token derivation `HMAC-SHA256(key, "boot/1" || bucket)[:32]` | `derive_bucket_token`, `verify_bucket_token` |
| `python/src/hsync_bootnode/server.py` | QUIC adapter: self-signed TLS identity (`hsync_common.ssl_utils`, ECDSA P-256), RETRY, bounded receive windows (≤32 KiB/stream, ≤128 KiB/connection), frame IO bound to 8 KiB (framing only — parsing/validation lives in `handler.py`), per-IP/global connection guard; persistent identity by default, in-memory via `--ephemeral` (ADR-0034/ADR-0037), atomic unique-temp write + on-load key/cert consistency check (decision 54) | `start_server`, `NodeIdentity`, `make_identity`, `load_or_create_identity`, `load_identity`, `rotate_identity`, `IdentityError`, `_atomic_write_identity`, `_key_matches_certificate`, `BootQuicProtocol`, `ConnectionGuard` |
| `python/src/hsync_bootnode/upnp.py` | Facade over the SSRF-hardened `hsync_common.upnp` SSOT (shared with `hsync-client`): adds the async `UpnpManager`; stateless when no IGD. Opt-in (`--upnp`) | `UpnpManager.run`, `add_port_mapping`, `discover_igd` |
| `python/src/hsync_bootnode/diagnostics.py` | Two stderr channels: **always-on `warn`/`error`** node health (peer-free by construction, field allow-list, error dedup with `suppressed=<n>`) and the opt-in **full operation log** (decisions #25, #35, #36); never on disk (no-log invariant); line format `<ISO-8601 UTC Z> - hsync-bootnode[<pid>] <level>: …` | `configure_debug`, `debug_enabled` (cheap predicate hot paths use to skip building `debug_event` fields when the opt-in sink is off), `debug_log`, `debug_event`, `warn_event`, `error_event`, `_emit`, `_sanitize`, `_PUBLIC_FIELDS` |
| `python/src/hsync_bootnode/cli.py` | Typer multi-command app; group keys from `--keys-fd` / `HSYNC_BOOTNODE_KEYS_FD` (read once, size- and time-bounded — decision 54); fail-fast config; `--ttl`/`--debug`/`--ready-file` seams; `--identity`/`--public-host` + `identity show`/`rotate` | `run`, `identity_show`, `identity_rotate`, `main` (`--version`), `_load_keys`, `_read_fd`, `_fd_readable_before` |
| `python/fuzz/fuzz_boot.py` | Deterministic stdlib fuzz harness (decoder + SSDP/token validators; security invariants, not just crash-freedom; CI burst in `python/tests/test_fuzz_harness.py`) | `run_fuzz`, `Finding`, targets `handle`/`ssdp`/`token` |
| `python/fuzz/fuzz_guided.py` | Coverage-guided driver on the same generators/invariants: per-iteration branch-arc signatures via `coverage.Coverage` (branch=True), evolving FIFO-capped corpus (cap 512), deterministic seeds, corpus persistence (`--corpus-out/--corpus-in`); ~140 it/s (tracing) vs ~20 000 it/s static | `run_guided`, `_ArcMeter.arcs`, `_guided_frame` |

## Request flow (per datagram/stream frame)

1. `server.py` reads one newline-terminated frame (≤ 8 KiB, checked on the frame
   length itself so an oversized frame always closes the stream); a frame longer
   than 8 KiB closes the session silently (no-log).
2. `BootHandler.handle` (`python/src/hsync_bootnode/handler.py::BootHandler.handle`) first consults
   the malformed-frame budget: an IP that has exhausted it is dropped before the
   parser runs, so a parse flood costs no event-loop CPU. Otherwise the raw frame
   is validated in a single pass via the `BootFrame` discriminated union
   (`BOOT_FRAME_ADAPTER.validate_json`). `ValidationError` → silent drop
   (no-log, no oracle); it charges only the malformed-frame budget, never the
   valid-frame admission, so a garbage sender cannot throttle valid neighbours
   behind a shared NAT IP. Only a *valid* frame then charges the generic per-IP
   admission (~10 req/s, burst 50).
3. Type-specific limits (every limiter keyed by source IP): register/refresh
   10/min per (IP, bucket); query 5/min per (IP, bucket) plus an aggregate
   20/min per IP across buckets (anti-enumeration). The routing table and the
   limiter maps are bounded by `ResourceLimits` (host RAM/CPU), so per-IP/bucket
   churn cannot grow them without limit.
4. Protected-bucket check: if the bucket is gated — declared `--protected-bucket` on an open node,
   or *any* bucket on a private node — a constant-time compare decides, running
   on the same 64-byte shapes whether or not the bucket has a key (no timing
   side-channel on the provisioned set); failures are rate-limited after 5/min
   per IP and answered uniformly with `token_required` / `rate_limited`
   (+ `retry_after`).
5. Mutation: `register` upserts (STUN-echo source `ip:port`) and copies the
   advisory fields onto the record (`capacity`, `reachable`, and the election
   advertisement `server_ready`/`force_master`/`never_master`/`startup_time`/
   `sync_direction` — decision 31); `refresh` touches TTL only and never creates
   or mutates them. `register`, `refresh` and `leave` all enforce **record
   ownership**: a source other than the record's observed IP is silently refused
   unless the frame was token-authorized on a private/protected bucket, so a
   learned `(cid, bucket, group)` cannot hijack, keep alive, or evict another
   peer's record. Creating a record above the host-derived table ceiling, or
   above the per-`(bucket, group)` ceiling that keeps one sample from being
   saturated, is refused with `overloaded` (capacity backpressure), never by growing RAM.
6. Reply: `ack` (register/refresh, carries `observed_endpoint`) or `response`
   (query, random sample up to `limit`, every advertised endpoint relayed as the
   peer's candidate list, every advisory field relayed verbatim); returned
   as already-serialized JSON **bytes** (Pydantic `TypeAdapter.dump_json`),
   written verbatim by the transport.

## Security model

- **No-log**: nothing peer-related is written to disk; the node's TLS identity
  (the operator's own key+cert, ADR-0034/ADR-0037 — not peer data) is kept by
  default as a stable, pin-able, rotatable identity, and `--ephemeral` keeps it
  in memory instead. A persisted identity is written atomically through a unique
  temp file (a crash cannot wedge the next start) and is loaded only when its
  private key matches its certificate (decision 54). Verified by
  `python/tests/test_nolog.py` under a read-only filesystem.
- **Anti-amplification**: QUIC RETRY + address-validation before connection
  state (`start_server(..., retry=True)`, `python/src/hsync_bootnode/server.py`),
  and a node-side **transport guard** (`ConnectionGuard`,
  `python/src/hsync_bootnode/server.py`): a per-IP handshake budget (~30/s,
  burst 100), a per-IP cap and a process-wide cap on simultaneously-open
  connections, all sized by `ResourceLimits` from host RAM/CPU, checked in
  `BootQuicProtocol.datagram_received` before any handshake work; released on
  `ConnectionTerminated`, lazily forgetting quiet/empty IPs. QUIC receive windows
  are bounded (≤32 KiB per stream, ≤128 KiB per connection). The guard shares
  the rate-limit seam (`--no-rate-limit`) so benchmarks stay unthrottled.
- **Malformed-frame budget**: invalid/unknown frames charge a separate ~30/min
  per IP budget (burst 60, `handler.py` `_bad_parse_ip`), and once an IP exhausts
  it that IP's frames are dropped **before** validation — so a parse storm costs
  no validation CPU — without adding any oracle (the drop stays silent) and
  without draining a NAT neighbour's valid-frame admission.
- **Frame-domain tightness**: `bucket_token` must be 64 lowercase hex chars
  (`BucketToken` annotation, `protocol.py`) and `connected` is bounded to
  `0..2^53` (`CONNECTED_MAX`), so a token that cannot be a derivable HMAC output
  or an absurd counter is an invalid frame, not a per-IP accounting event.
- **Protected buckets**: the group key never enters any record; only the derived token.
  Protected buckets are declared by the operator (`--protected-bucket`,
  repeatable) and fail fast at startup if declared without a key
  (`BootConfigError`, exit code 2). The client derives the same token from its p2p
  shared key (`HSYNC_P2P_KEY` → `derive_bucket_token`), so one client key
  authenticates to any bucket whose group key equals it; the user-facing model is
  `docs/usage.md` ("Privacy and anonymity model").
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
| Windows installer (x64) | `packaging/windows/hsync-bootnode.iss` (Inno Setup, built in CI) + `hsync-bootnode-service-frozen.xml`; per-machine, registers the WinSW service | v1 |
| Linux `.deb` (amd64/arm64/armhf) | `../compile.sh -t deb`/`deb-all` (`-l/--language`, default `python`; `rust` rejected until that port exists) + `packaging/deb/` (control, maintainer scripts, deb unit, man page) | v1 |
| Linux `.rpm` (x86_64/aarch64) | `../compile.sh -t rpm`/`rpm-all` + `packaging/rpm/` (`.spec`, Rocky Linux 9 builder); `python/compile.sh -t onedir` payload staged for `/usr/lib/hsync-bootnode` | v1 |
| Raspberry Pi OS (armhf/arm64) | `../compile.sh -t rpi` (Docker + qemu, reuses `packaging/deb/Dockerfile.builder`) → `dist/rpi/<arch>/hsync-bootnode` | v1 |

## Packaging

- `python/compile.sh` builds binaries only (`native` host standalone into
  `-o/--output-dir`, `onedir` bundle consumed by the root entry point).
  `python/dist/` and `python/build/` are git-ignored build outputs.
- `../compile.sh -t native` wraps `python/compile.sh -t native` and places the
  host executable at `dist/<os>-<arch>/hsync-bootnode`.
- `../compile.sh -t rpi` cross-builds the onefile executable for Raspberry Pi
  OS 32-bit (armhf/armv7) and 64-bit (arm64/aarch64) inside an emulated
  debian:bookworm container, reusing `packaging/deb/Dockerfile.builder`; output
  `dist/rpi/<arch>/hsync-bootnode`. PyInstaller's `build/` and `*.spec`
  intermediates are redirected to `/tmp/work` (via `HSYNC_PYINSTALLER_WORKPATH`)
  so nothing is written into the mounted host tree.
- `../compile.sh -t deb` embeds the selected language's payload
  (today `python/compile.sh -t onedir`) as `/usr/lib/hsync-bootnode/` with a
  `/usr/bin/hsync-bootnode` symlink, the hardened deb systemd unit, and the
  gzipped man page; `DEBIAN/postinst` creates `/etc/hsync-bootnode/` (0750)
  for the out-of-package group-keys file and never enables the service.
- `../compile.sh -t rpm` builds a `.rpm` from a staged buildroot
  (`_stage_rpm_buildroot`) reusing the deb man page + unit, and runs `rpmbuild`
  with an absolute `_topdir` and a writable `_dbpath` (a relative `_topdir`
  breaks `%{buildroot}`, and non-root rpmbuild cannot open `/var/lib/rpm`).
  `packaging/rpm/Dockerfile.builder` (Rocky Linux 9) provides the cross-build;
  the spec uses `DynamicUser` (no system user) and creates `/etc/hsync-bootnode`
  (0750) in `%post`.
- The Windows installer (`packaging/windows/hsync-bootnode.iss`, built in CI on
  `windows-latest`) is per-machine: it installs the frozen `.exe` + WinSW (as
  `hsync-bootnode-service.exe`) + `hsync-bootnode-service-frozen.xml`, grants
  LocalService modify on `%ProgramData%\hsync-bootnode`, then installs and starts
  the service. Uninstall stops and removes it.
- The release workflow (`../.github/workflows/release.yml`) also publishes
  fixed-name `latest` aliases (e.g. `hsync-bootnode-x86_64.rpm`,
  `hsync-bootnode-amd64.deb`, `hsync-bootnode-windows-amd64-setup.exe`) so the
  docs can link `releases/latest/download/<name>` without a version
  (`RELEASES.md` §5.8); guarded by `python/tests/test_compile_script.py`.
- **Binary portability floor**: `native` and `deb` build on the host, so their
  executable embeds the build machine's CPython + glibc (incompatible with any
  machine carrying an older glibc); `deb-all`/`rpi` build inside
  `python:3.12-bookworm` (glibc 2.36) and `rpm-all` inside `rockylinux:9`
  (glibc 2.34), so those are the portable artifacts — measured on a produced
  amd64 bundle: CPython 3.12, floor `libc6 (>= 2.35)` (`libpython3.12.so.1.0`,
  `libgcc_s.so.1`), while the base image itself is glibc 2.36. `BASE_IMAGE` is a
  Dockerfile `ARG` only — no CLI flag selects an older base. The `.deb`'s
  `Depends: libc6` covers the launcher only, never the bundled Python.
  Operator-facing procedure: `docs/faq.md`.
- `rust/` port plugs in by extending `validate_language()`, `_build_native()`,
  `_build_onedir()`, `_container_native_cmd()` and `_container_build_cmd()` in
  `../compile.sh` (dispatch points, fail-fast contract) — never by adding
  packaging logic inside the per-language script.

### Distribution & install entry points

Four consumer-facing ways to run a node, kept identical in shape to
`hsync-server` (decisions #41):

| Method | Files | Notes |
|---|---|---|
| Installer script | `install.sh` | Resolves the latest release (or a pinned `--version`/`--image-digest`), writes `.env` + a self-contained `compose.yaml` under `~/.local/share/hsync-bootnode`, verifies the image's Sigstore signature (keyless cosign; `--no-verify` opts out), runs `docker compose up -d` and waits for the readiness PID. Docker Compose only; never `sudo`. |
| Docker / Compose | `Dockerfile`, `Dockerfile.dockerignore`, `python/entrypoint.sh`, `compose.yaml`, `docker.sh` | Build context = repo parent (needs the sibling `hsync-common`); the entrypoint opens the mounted group-keys file as fd 3; the container binds the unprivileged UDP 8443, the host maps `HSYNC_BOOTNODE_PORT` (default 443); no new env vars. `docker.sh` builds/runs from source. |
| Debian package | `packaging/deb/` (see above) | Hardened systemd unit, `DynamicUser`, `CAP_NET_BIND_SERVICE`, group keys as a systemd credential. |
| From source | `run.sh` | Uniform clone-and-run: checks `../hsync-common`, creates `python/.venv` via Poetry, `exec hsync-bootnode`. Mirrors `hsync-server/run.sh`. |

## Tests

| Suite | Scope |
|---|---|
| `python/tests/test_handler.py` | Routing, TTL (frozen clock), protected buckets, private policy (every bucket gated, unkeyed bucket, gated `leave`), rate limits, STUN-echo, frame rejection |
| `python/tests/test_scaffold.py` | Fixtures / spec contract + frame schema positives/negatives (rigid schema) |
| `python/tests/test_fuzz_harness.py` | Bounded deterministic fuzz burst (decoder/SSDP/token invariant targets; long runs via `python/fuzz/fuzz_boot.py --seconds N`, decision #47) + coverage-guided burst (decision #48) |
| `python/tests/test_server.py` | QUIC loopback: register/query/protected refusal, private-node refusal, garbage frames, pipelined frames on one stream, per-IP connection guard (cap + release), session-failure diagnostics (peer-free always-on line + opt-in debug detail) |
| `python/tests/test_identity.py` | Persistent identity (default): create/load/rotate, `0600`/`0700` permissions, ECDSA P-256 only, key/cert consistency, stale-temp recovery, SAN from bind + `--public-host`, 20-year validity, on-load permission hardening |
| `python/tests/test_nolog.py` | Zero-write invariant under read-only fs |
| `python/tests/test_upnp.py` | SSDP/SOAP shapes, error downgrade, stateless no-IGD, LOCATION/source/redirect hardening |
| `python/tests/test_cli.py` | CLI version/fail-fast/keys-fd contract (size + time bounds, fd 1/2 refused) |
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
`hsync_bootnode`. The same suite will validate the future `rust/`
port unchanged. Benchmarks (`bench/`) follow the same rule for L2/L3
(`bench_quic.py`, `soak.py` spawn the binary); L1 (`bench/bench_handler.py`) and
the diagnostics (L4 `bench/profile_handshake.py` — handshake vs `aioquic`
closing drain; L5 `bench/cpu_saturation.py` — load vs node CPU%) are
Python-internal.

## Known gaps / next phases

The monorepo `p2p`/bootnode migration is **complete**:

- **Done**: `hsync-common` mirror (`protocol/bootnode.py`, fixtures, drift test,
  capabilities v3); the advisory `capacity` hint (`0..32`) and the derived
  `reachable` flag relayed `register` → record → `query` (decisions 23–24); the
  **election advertisement** (`server_ready`/`force_master`/`never_master`/
  `startup_time`/`sync_direction`) relayed the same way so a bootnode-discovered
  peer ranks in the client's master election exactly like an mDNS-discovered one
  (decision 31); the
  bootnode's opt-in **debug operation log** (decision 25); client `hsync p2p`
  with both discovery plans and its black-box suite; desktop mode, wd-os5
  packaging; the peer data-plane protocol is `p2p/1`.
- **Open**: **Android client for `boot/1`** (deferred; the QUIC stack is decided:
  `quiche` via JNI). Resumption document: the Android project's
  [`quic-jni`](https://github.com/albertsdk/hsync-android/blob/main/llm-wiki/modules/quic-jni.md)
  page.
- **Done / open (quality)**: a deterministic stdlib **fuzz harness** covers the
  decoder and the SSDP/token validators in CI (decision #47, `python/fuzz/
  fuzz_boot.py`), and a **coverage-guided in-process driver** (decision #48,
  `python/fuzz/fuzz_guided.py` — arc feedback via `coverage.py`) evolves the
  corpus the same way AFL does, at Python-branch granularity. Still open:
  Atheris (no Python 3.14 wheel) and `cargo fuzz` for the Rust port (hard
  requirement there, nightly toolchain, `rust/` not started).
- **Not started (v2)**: Rust (`quinn`) implementation — target toolchain stable
  Rust 1.98+.
