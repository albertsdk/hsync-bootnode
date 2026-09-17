# hsync-bootnode — wire protocol `boot/1`

> Single source of truth for the bootstrap wire protocol, shared by **all** language
> implementations (`python/`, future `rust/`, future `c/`). Do not fork this spec into
> any implementation directory.

## Transport

- QUIC/UDP, port **443** (single listener; no TCP fallback — zero legacy).
- TLS 1.3 inside QUIC: the exchanged peer list is not readable by ISPs.
- ALPN `hsync-boot/1`.
- NDJSON payloads (one JSON object per line) over bidirectional QUIC streams;
  a client may pipeline several frames back-to-back on one stream and the
  server answers each frame in order.
- **Every frame** carries the common header `{protocol_version, type, ...}`;
  the server routes on `type` and rejects anything else (rigid validator).

## Address validation

- Server requires QUIC `RETRY` + `address_validation_token` before allocating connection state (anti-amplification).
- Per-IP token bucket: ~10 req/s (burst 50). Additional per-bucket limits in §Auth.
- Idle connections are dropped after 30 s.

## Frames (client → server on one stream)

| Frame | Payload |
|---|---|
| `register` | `{protocol_version:"boot/1", type:"register", cid, bucket, group?, bucket_token?, cert_fp, version, capacity, endpoints:[{proto:"tcp"\|"udp", host, port}], connected?}` |
| `refresh` | `{protocol_version:"boot/1", type:"refresh", cid, bucket, group, bucket_token?, connected?}` |
| `leave` | `{protocol_version:"boot/1", type:"leave", cid, bucket, bucket_token?}` |
| `query` | `{protocol_version:"boot/1", type:"query", bucket, group?, bucket_token?, limit?}` |

## Frames (server → client)

| Frame | Payload |
|---|---|
| `ack` | `{protocol_version:"boot/1", type:"ack", observed_endpoint:{proto:"udp", ip, port}, ttl, server_time, retry_after?}` (STUN-echo) |
| `response` | `{protocol_version:"boot/1", type:"response", peers:[{cid, ip, port, proto, cert_fp, bucket, group, version, reachable}], count, ttl}` or `{peers: [], count: 0, error:"token_required"\|"rate_limited", retry_after?}` |

## Rules

- **No targeted requests**: schema rejects unknown fields (`extra="forbid"`); there is no field for a file path/hash. Agnostic by construction (D3).
- `type` is mandatory: the frame kind is declared, never guessed from the payload.
- **CID**: `^[A-Za-z0-9]{21}$` full-match.
- **Anonymous `query`**: on an open node anyone with bucket (+group) can list peers; privacy via optional `bucket_token` (D11). On a private node every query must carry a valid token (see §Auth).
- **No-log**: no timestamps/IPs written to disk anywhere in this path.
- Malformed, unknown-`type` or oversized frames are silently dropped (no oracle, no log).
- `refresh` never creates a record: an unknown CID is dropped so the client falls back to `register`.

## Auth — bucket tokens: protected buckets and private nodes (D11)

- `bucket_token = HMAC-SHA256(HSYNC_P2P_KEY, "boot/1" || bucket)[:32]` hex (64 chars), optional on register/refresh/query/leave.
- Server-side: operator declares protected buckets (`--protected-bucket`); token compared in constant time (`hmac.compare_digest` Python / `subtle::ConstantTimeEq` Rust).
- Matrix: protected bucket + missing/wrong token → `peers: []`, `error:"token_required"` (uniform — no bucket-existence oracle); correct token → full random `K` sample (default 20, `limit` 1..50). Open bucket: no token needed.
- **Private node** (`--private` / `HSYNC_BOOTNODE_PRIVATE=1`): the D11 check applies to *every* bucket, not only the declared protected set. A bucket with no key loaded is refused exactly like a wrong token (same `token_required` answer, same failed-token budget), so the set of provisioned buckets is not observable either. `leave` is gated in this mode too — an anonymous `leave` would let anyone who knows a `(cid, bucket)` pair spoof a departure; `leave` has no response frame, so a refusal is a silent drop. Startup fails fast (exit code 2) when `--private` is set with zero group keys. The wire format is unchanged: this is a server-side policy.
- Rate limits (in-memory sliding windows): `query` 5/min per `(IP, bucket)` (burst 10) and 30/min per bucket; `register`/`refresh` 10/min per bucket; failed-token attempts ~5/min per IP. On limit: respond `{error:"rate_limited", retry_after:<s>}` — never silently drop.

## In-memory routing table

- Key `(cid, bucket, group)` → `{ip_src, udp_port, cert_fp, version, protocol, endpoints[], connected, reachable, expires_at}`.
- TTL 60 s; client refresh every 30 s; prune every 15 s; response = random `K` sample.
- Responses advertise the peer's declared `endpoints[0]` (fallback: the observed source endpoint).