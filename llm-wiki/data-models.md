# Data models — `boot/1` frames

The `boot/1` wire contract is defined once in `protocol-spec/boot-1.md` and mirrored
by typed models in every implementation. The Python v1 models live in
`python/src/hsync_bootnode/protocol.py` (pydantic v2, all with `extra="forbid"` so
any unknown/targeted field makes the frame invalid — rigid schema). The future Rust crate
mirrors the same frames with `struct`s/`enum`s and deny-unknown-fields serde
attributes; do not fork the shapes here.

## Common header

Every frame carries `{protocol_version, type, ...}`. `_BootFrame`
(`python/src/hsync_bootnode/protocol.py:104`) is the shared base: mandatory `type`
discriminator plus `protocol_version` pinned to `boot/1`
(`PROTOCOL_VERSION_BOOT`, `protocol.py:45`). The server routes on `type` and never
guesses the frame kind from the payload shape.

## Frame inventory

| Frame | Direction | Model | Fields (beyond the header) |
|---|---|---|---|
| `register` | client → server | `BootRegister` (`protocol.py:113`) | `cid`, `bucket`, `group?`, `bucket_token?`, `cert_fp`, `version`, `capacity`, `endpoints[]`, `connected?` |
| `refresh` | client → server | `BootRefresh` (`protocol.py:134`) | `cid`, `bucket`, `group?`, `bucket_token?`, `connected?` |
| `leave` | client → server | `BootLeave` (`protocol.py:145`) | `cid`, `bucket`, `bucket_token?` |
| `query` | client → server | `BootQuery` (`protocol.py:159`) | `bucket`, `group?`, `bucket_token?`, `limit` (1–50, default 20) |
| `ack` | server → client | `BootAck` (`protocol.py:169`) | `observed_endpoint`, `ttl`, `server_time`, `retry_after?` |
| `response` | server → client | `BootResponse` (`protocol.py:202`) | `peers[]`, `count`, `ttl`, `error?` (`token_required`/`rate_limited`), `retry_after?` |

`capacity` (domain `0..32`, default `0`; `CAPACITY_MAX` at `protocol.py:63`) is the
**advisory service-capacity hint**: the number of concurrent peer-download reads the
peer declares it can serve (`0` = not a seeder). The handler copies it from
`register` onto the record and relays it in every `query` peer, but it is **not
authenticated and not authoritative** — the authoritative value is `serve_slots`
on the authenticated data-plane handshake (ADR 0030). `refresh` neither carries nor
mutates it, and the sample is never ordered by it.

`reachable` is derived from `bool(endpoints)` at `register` time: it is `true` only
for a peer that advertised at least one listen endpoint (a data-plane master). An
endpoint-less register (the first STUN register) is advertised with
`reachable=false` and its observed UDP source as the fallback endpoint. `refresh`
never changes it; a change requires a new `register`.

## Nested models

| Model | Owner | Fields |
|---|---|---|
| `Endpoint` (`protocol.py:84`) | `BootRegister.endpoints[]` | `proto` (`tcp`/`udp`), `host`, `port` |
| `ObservedEndpoint` (`protocol.py:94`) | `BootAck.observed_endpoint` | `proto`, `ip`, `port` (STUN-echo of the source) |
| `BootPeer` (`protocol.py:179`) | `BootResponse.peers[]` | `cid`, `ip`, `port`, `proto`, `cert_fp`, `bucket`, `group?`, `version`, `capacity`, `reachable` |

The client→server frames are dispatched in one pass by the discriminated union
`BootFrame = Annotated[BootRegister | BootRefresh | BootLeave | BootQuery,
Field(discriminator="type")]` (`protocol.py:216`) and validated from raw bytes via
`BOOT_FRAME_ADAPTER` (`protocol.py:220`, a `TypeAdapter[BootFrame]`). The
server→client frames (`BootAck`/`BootResponse`/`BootPeer`) are deliberately
excluded from the union: they are never validated on the input path.

## Shared validators

| Constant | Location | Rule |
|---|---|---|
| `CID_PATTERN` | imported from `hsync_common.models.event` (`protocol.py:17`) and re-exported | `^[A-Za-z0-9]{21}$` — **SSOT import** (hsync-common), pinned to the boot/1 spec value by `test_cid_pattern_matches_boot1_spec` |
| `BucketName` | `protocol.py:81` | canonical HSYNC bucket name via `hsync_common.path_validation.is_valid_bucket_name` (`[A-Za-z0-9]` with `-`/`_` in the middle, 1..63) — applied to every wire `bucket` |
| `BUCKET_TOKEN_LEN` | `protocol.py:54` | 64 (lowercase hex = `hex(32 bytes)`), derived as `HMAC-SHA256(key, "boot/1" || bucket)[:32]` |
| `BucketProto` | `protocol.py:57` | `Literal["tcp", "udp"]` |
| `CAPACITY_MAX` | `protocol.py:63` | 32 — upper bound of the advisory `capacity` hint (`0` = not a seeder); mirrors `serve_slots` |
| `BOOT_DEFAULT_PORT` | imported from `hsync_common.constants` (`cli.py`, `--port` default) | `443` — default UDP listener port (spec §Transport); single SSOT shared with `hsync-client` |

## Runtime (non-wire) structures

| Structure | Location | Role |
|---|---|---|
| `PeerRecord` | `python/src/hsync_bootnode/routing.py:31` | RAM-only routing entry keyed `(cid, bucket, group)`; carries `capacity` (advisory hint), `expires_at` (TTL) and a lazily-built materialized wire projection `wire` (`BootPeer | None`) |
| `RoutingTable` | `python/src/hsync_bootnode/routing.py:55` | In-memory registry (`upsert`/`remove`/`get`/`prune`/`sample`/`count`); never persisted. Backed by three secondary indexes — `_by_group` (bucket+group → keys, O(1) `sample`), `_by_cid` (cid+bucket → keys, O(1) `remove`), `_pos` (key → list position for O(1) swap-remove). `prune` rebuilds the indexes in bulk when ≥ 50% of records expire, else removes incrementally. |
| `TokenBucketLimiter` | `python/src/hsync_bootnode/ratelimit.py:22` | In-memory token bucket for the per-IP/per-bucket rate limits; `evict_stale` drops fully-refilled buckets (behaviour-identical, bounds memory) |
| `NodeIdentity` | `python/src/hsync_bootnode/server.py` | Self-signed TLS identity (cert + ECDSA P-256 / RSA / Ed25519 key). Ephemeral via `make_identity`, or persisted (`0600`/`0700`) via `load_or_create_identity`/`rotate_identity`. `fingerprint` is the leaf-DER SHA-256 (`sha256:<hex>`), the trust anchor for client pinning (ADR-0034) |
| `CertificateFingerprint` | `python/src/hsync_bootnode/handler.py:65` | 64-hex-char `str` subtype carried on the wire as `cert_fp` and shared with the trust fingerprint domain |

## Relationships

```
register/refresh ──► BootRegister / BootRefresh ──► BootAck (STUN-echo + ttl)
query           ──► BootQuery                    ──► BootResponse ──► BootPeer[]
leave           ──► BootLeave                    ──► (no reply frame)
```

`BootPeer` is projected from a `PeerRecord` (handler `_to_peer`,
`python/src/hsync_bootnode/handler.py:462`): the peer's advertised `endpoints[0]` is
preferred, falling back to the observed source endpoint. The projection is
materialized once on `PeerRecord.wire` and reused on later samples — valid for the
record's lifetime because `register` always builds a fresh `PeerRecord` and
`refresh` only mutates `connected`/`expires_at` (neither is part of `BootPeer`).
`capacity` **is** part of `BootPeer`, so it must never be mutated in place after the
projection is built; a changed value requires a fresh `register` (new `PeerRecord`).
The committed fixtures in `fixtures/bootnode-*.json` validate every one of these
models via the drift test in `python/tests/test_scaffold.py`.
