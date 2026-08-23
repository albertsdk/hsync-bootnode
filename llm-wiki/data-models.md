# Data models — `boot/1` frames

The `boot/1` wire contract is defined once in `protocol-spec/boot-1.md` and mirrored
by typed models in every implementation. The Python v1 models live in
`python/src/hsync_bootnode/protocol.py` (pydantic v2, all with `extra="forbid"` so
any unknown/targeted field makes the frame invalid — D3). The future Rust crate
mirrors the same frames with `struct`s/`enum`s and deny-unknown-fields serde
attributes; do not fork the shapes here.

## Common header

Every frame carries `{protocol_version, type, ...}`. `_BootFrame`
(`python/src/hsync_bootnode/protocol.py:71`) is the shared base: mandatory `type`
discriminator plus `protocol_version` pinned to `boot/1`
(`PROTOCOL_VERSION_BOOT`, `protocol.py:37`). The server routes on `type` and never
guesses the frame kind from the payload shape.

## Frame inventory

| Frame | Direction | Model | Fields (beyond the header) |
|---|---|---|---|
| `register` | client → server | `BootRegister` (`protocol.py:80`) | `cid`, `bucket`, `group?`, `bucket_token?`, `cert_fp`, `version`, `capacity`, `endpoints[]`, `connected?` |
| `refresh` | client → server | `BootRefresh` (`protocol.py:95`) | `cid`, `bucket`, `group?`, `bucket_token?`, `connected?` |
| `leave` | client → server | `BootLeave` (`protocol.py:106`) | `cid`, `bucket` |
| `query` | client → server | `BootQuery` (`protocol.py:114`) | `bucket`, `group?`, `bucket_token?`, `limit` (1–50, default 20) |
| `ack` | server → client | `BootAck` (`protocol.py:124`) | `observed_endpoint`, `ttl`, `server_time`, `retry_after?` |
| `response` | server → client | `BootResponse` (`protocol.py:150`) | `peers[]`, `count`, `ttl`, `error?` (`token_required`/`rate_limited`), `retry_after?` |

## Nested models

| Model | Owner | Fields |
|---|---|---|
| `Endpoint` (`protocol.py:51`) | `BootRegister.endpoints[]` | `proto` (`tcp`/`udp`), `host`, `port` |
| `ObservedEndpoint` (`protocol.py:61`) | `BootAck.observed_endpoint` | `proto`, `ip`, `port` (STUN-echo of the source) |
| `BootPeer` (`protocol.py:134`) | `BootResponse.peers[]` | `cid`, `ip`, `port`, `proto`, `cert_fp`, `bucket`, `group?`, `version`, `reachable` |

## Shared validators

| Constant | Location | Rule |
|---|---|---|
| `CID_PATTERN` | `protocol.py:41` | `^[A-Za-z0-9]{21}$` (local mirror of `hsync_common.models.event.CID_PATTERN`; Fase 2 swaps it for the SSOT import + drift test) |
| `BUCKET_TOKEN_LEN` | `protocol.py:45` | 64 (lowercase hex = `hex(32 bytes)`), derived as `HMAC-SHA256(key, "boot/1" || bucket)[:32]` |
| `BucketProto` | `protocol.py:48` | `Literal["tcp", "udp"]` |

## Runtime (non-wire) structures

| Structure | Location | Role |
|---|---|---|
| `PeerRecord` | `python/src/hsync_bootnode/routing.py:31` | RAM-only routing entry keyed `(cid, bucket, group)`; carries `expires_at` (TTL) |
| `RoutingTable` | `python/src/hsync_bootnode/routing.py:55` | In-memory registry (`upsert`/`remove`/`get`/`prune`/`sample`/`count`); never persisted (D7) |
| `TokenBucketLimiter` | `python/src/hsync_bootnode/ratelimit.py:22` | In-memory token bucket for the per-IP/per-bucket rate limits |

## Relationships

```
register/refresh ──► BootRegister / BootRefresh ──► BootAck (STUN-echo + ttl)
query           ──► BootQuery                    ──► BootResponse ──► BootPeer[]
leave           ──► BootLeave                    ──► (no reply frame)
```

`BootPeer` is projected from a `PeerRecord` (handler `_to_peer`,
`python/src/hsync_bootnode/handler.py:349`): the peer's advertised `endpoints[0]` is
preferred, falling back to the observed source endpoint. The committed fixtures in
`fixtures/bootnode-*.json` validate every one of these models via the drift test in
`python/tests/test_scaffold.py`.
