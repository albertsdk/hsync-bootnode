"""``boot/1`` request handling — pure logic, no network transport.

``BootHandler`` is the transport-agnostic core of the bootstrap node: it owns
the in-memory routing table, the D11 authorization policy (constant-time token
check for the buckets the operator declares protected, or for **every** bucket
when the node runs in node-wide private mode), the per-IP/per-bucket rate
limiters and the STUN-echo reply builder. It receives the raw frame bytes,
validates them in a single pass and
returns the serialized JSON reply (or ``None`` to drop); the QUIC layer
(``server.py``) only does framing and writes the reply back.

No-log invariant: nothing in this module ever opens a file for writing.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping
from typing import Literal, cast

from pydantic import SecretStr, ValidationError

from hsync_bootnode.debug import debug_event, debug_log
from hsync_bootnode.protocol import (
    BOOT_ACK_ADAPTER,
    BOOT_FRAME_ADAPTER,
    BOOT_RESPONSE_ADAPTER,
    PROTOCOL_VERSION_BOOT,
    BootAck,
    BootLeave,
    BootPeer,
    BootQuery,
    BootRefresh,
    BootRegister,
    BootResponse,
    ObservedEndpoint,
)
from hsync_bootnode.ratelimit import TokenBucketLimiter
from hsync_bootnode.routing import DEFAULT_TTL, PeerRecord, RoutingTable
from hsync_bootnode.tokens import derive_bucket_token, verify_bucket_token

__all__ = [
    "CertificateFingerprint",
    "BootHandler",
    "BootConfigError",
]

# D11 / spec rate limits (in-memory sliding windows).
OP_IP_RATE_PER_SECOND = 10.0  # per-IP admission: ~10 req/s, burst 50
OP_IP_BURST = 50
QUERY_PAIR_LIMIT = 5  # per (IP, bucket)
QUERY_PAIR_BURST = 10
QUERY_BUCKET_LIMIT = 30  # per bucket total
REGISTER_BUCKET_LIMIT = 10  # per bucket total
BAD_TOKEN_IP_LIMIT = 5  # failed-token attempts per IP
WINDOW_SECONDS = 60.0

# Internal authorization outcome used by register/refresh/query.
_AuthResult = Literal["ok", "token_required", "rate_limited"]

# TTL sweep cadence (spec: prune every 15 s).
_PRUNE_INTERVAL_SECONDS = 15.0


class CertificateFingerprint(str):
    """SHA-256 DER fingerprint of the node's TLS certificate (64 hex chars)."""


class BootConfigError(RuntimeError):
    """Invalid operator configuration (fail fast at startup, never silently)."""


def _utc_now_z() -> str:
    """UTC timestamp in the fixture format ``2026-10-09T10:00:00Z``."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class BootHandler:
    """Matchmaker core: routing + authorization (D11 / private) + anti-abuse limits."""

    def __init__(
        self,
        *,
        ttl: float = DEFAULT_TTL,
        protected_buckets: Iterable[str] = (),
        private: bool = False,
        group_keys: Mapping[str, SecretStr] | None = None,
        routing: RoutingTable | None = None,
        enforce_rate_limits: bool = True,
    ) -> None:
        self.ttl = ttl
        self.routing = routing if routing is not None else RoutingTable()
        # ``None`` sentinel forces the first handle() to sweep; a 0.0 seed would
        # skip the first sweep when monotonic() < prune_interval (recent boot).
        self._last_prune: float | None = None
        # Benchmark/test seam: disable every token bucket so measured ops stay
        # on the unthrottled fast path (--no-rate-limit).
        self._enforce_rate_limits = enforce_rate_limits

        self._protected: set[str] = set(protected_buckets)
        # Node-wide policy: with private mode every bucket is token-gated, so
        # every bucket the operator provisions a key for is authorized (the D11
        # rule applied to the whole node instead of to a declared subset).
        self._private = private
        keys = dict(group_keys or {})
        # Derive the expected per-bucket token once at startup: HMAC-SHA256(key,
        # "boot/1" || bucket)[:32], hex. The key itself never enters any record.
        self._tokens: dict[str, str] = {
            bucket: derive_bucket_token(key.get_secret_value().encode("utf-8"), bucket)
            for bucket, key in keys.items()
        }
        missing = self._protected - self._tokens.keys()
        if missing:
            names = ", ".join(sorted(missing))
            raise BootConfigError(
                f"protected bucket(s) without a group key: {names} "
                "(provide the key via HSYNC_BOOTNODE_KEYS_FD / --keys-fd)"
            )
        if self._private and not self._tokens:
            # Fail fast instead of serving a node that refuses every frame:
            # private mode is only meaningful with at least one group key.
            raise BootConfigError(
                "private node without any group key: every bucket would be "
                "refused (provide at least one 'bucket=<hex-key>' line via "
                "HSYNC_BOOTNODE_KEYS_FD / --keys-fd)"
            )

        # Generic per-IP admission (spec: ~10 req/s, burst 50).
        self._ops_ip = TokenBucketLimiter(
            capacity=OP_IP_BURST, refill=OP_IP_RATE_PER_SECOND, window=1.0
        )
        # Query: 5/min per (IP, bucket) burst 10; 30/min per bucket.
        self._query_pair = TokenBucketLimiter(
            capacity=QUERY_PAIR_BURST, refill=QUERY_PAIR_LIMIT, window=WINDOW_SECONDS
        )
        self._query_bucket = TokenBucketLimiter(
            capacity=QUERY_BUCKET_LIMIT, refill=QUERY_BUCKET_LIMIT, window=WINDOW_SECONDS
        )
        # Register/refresh: 10/min per bucket.
        self._register_bucket = TokenBucketLimiter(
            capacity=REGISTER_BUCKET_LIMIT,
            refill=REGISTER_BUCKET_LIMIT,
            window=WINDOW_SECONDS,
        )
        # Failed-token attempts: ~5/min per IP.
        self._bad_token_ip = TokenBucketLimiter(
            capacity=BAD_TOKEN_IP_LIMIT, refill=BAD_TOKEN_IP_LIMIT, window=WINDOW_SECONDS
        )
        debug_event(
            "handler ready",
            ttl=int(self.ttl),
            private=self._private,
            protected_buckets=len(self._protected),
            group_keys=len(self._tokens),
            rate_limits=self._enforce_rate_limits,
        )

    # ------------------------------------------------------------------ API

    def _maybe_prune(self) -> None:
        """Run a TTL sweep at most once per prune_interval."""
        now = time.monotonic()
        if self._last_prune is None or now - self._last_prune >= self.prune_interval:
            self.prune(now)
            self._last_prune = now

    def _limit_ok(self, limiter: TokenBucketLimiter, key: str) -> bool:
        """Consume one token, or always admit when rate limits are disabled."""
        return not self._enforce_rate_limits or limiter.allow(key)

    def handle(
        self,
        raw: bytes | str,
        *,
        peer_ip: str,
        peer_port: int,
    ) -> bytes | None:
        """Process one raw NDJSON frame; return the serialized response or ``None`` to drop.

        Malformed / unknown frames are silently dropped (no-log, no oracle).
        """
        try:
            frame = BOOT_FRAME_ADAPTER.validate_json(raw)
        except ValidationError:
            debug_event("drop invalid-frame", peer=f"{peer_ip}:{peer_port}", bytes=len(raw))
            return None
        # Admission is charged only for VALID frames: malformed/unknown frames
        # must stay silently dropped and must not drain the per-IP bucket (a
        # garbage sender behind a shared NAT must not throttle its neighbours).
        if not self._limit_ok(self._ops_ip, peer_ip):
            debug_event("rate_limited ip-admission", peer=f"{peer_ip}:{peer_port}")
            return self._rate_limited(self._ops_ip, peer_ip)

        # Prune expired records periodically (spec: every 15 s) so memory does
        # not grow unbounded under sustained load. Runs on the first handle()
        # (self._last_prune is None) and then once per prune_interval.
        self._maybe_prune()

        debug_event(
            f"frame {frame.type}",
            peer=f"{peer_ip}:{peer_port}",
            cid=getattr(frame, "cid", None),
            bucket=getattr(frame, "bucket", None),
            group=getattr(frame, "group", None),
        )
        if isinstance(frame, BootRegister):
            return self._register(frame, peer_ip, peer_port)
        if isinstance(frame, BootRefresh):
            return self._refresh(frame, peer_ip, peer_port)
        if isinstance(frame, BootLeave):
            self._leave(frame, peer_ip)
            return None
        return self._query(frame, peer_ip)

    def prune(self, now: float | None = None) -> int:
        """Drop expired records (TTL sweep); returns number removed."""
        removed = self.routing.prune(now)
        if now is None:
            # Background sweep only: also bound the rate-limiter state. Evicting
            # fully-refilled buckets is behaviour-identical to keeping them, and
            # keeping this off the request path avoids adding latency to a frame.
            for limiter in (
                self._ops_ip,
                self._query_pair,
                self._query_bucket,
                self._register_bucket,
                self._bad_token_ip,
            ):
                limiter.evict_stale()
            # Keep the request-side gating in sync so handle() does not
            # redundantly re-sweep right after this one.
            self._last_prune = time.monotonic()
        if removed:
            debug_log(f"prune removed {removed} expired record(s)")
        return removed

    @property
    def prune_interval(self) -> float:
        return _PRUNE_INTERVAL_SECONDS

    # ------------------------------------------------------------- register

    def _register(self, model: BootRegister, peer_ip: str, peer_port: int) -> bytes:
        if not self._limit_ok(self._register_bucket, model.bucket):
            debug_event(
                "register rate_limited bucket",
                cid=model.cid,
                bucket=model.bucket,
                peer=f"{peer_ip}:{peer_port}",
            )
            return self._rate_limited(self._register_bucket, model.bucket)
        result = self._authorize(model.bucket, model.bucket_token, peer_ip)
        if result != "ok":
            debug_event(
                "register refused",
                cid=model.cid,
                bucket=model.bucket,
                peer=f"{peer_ip}:{peer_port}",
                reason=result,
            )
            return self._refusal(result, peer_ip)

        record = PeerRecord(
            cid=model.cid,
            bucket=model.bucket,
            group=model.group,
            ip=peer_ip,
            port=peer_port,
            proto="udp",
            cert_fp=model.cert_fp,
            version=model.version,
            endpoints=list(model.endpoints),
            connected=model.connected or 0,
            reachable=bool(model.endpoints),
            capacity=model.capacity,
        )
        record.touch(self.ttl)
        self.routing.upsert(record)
        debug_event(
            "register ack",
            cid=model.cid,
            bucket=model.bucket,
            peer=f"{peer_ip}:{peer_port}",
            endpoints=len(model.endpoints),
            reachable=record.reachable,
            capacity=model.capacity,
            connected=record.connected,
            ttl=int(self.ttl),
        )
        return self._ack(peer_ip, peer_port)

    def _refresh(self, model: BootRefresh, peer_ip: str, peer_port: int) -> bytes | None:
        if not self._limit_ok(self._register_bucket, model.bucket):
            debug_event(
                "refresh rate_limited bucket",
                cid=model.cid,
                bucket=model.bucket,
                peer=f"{peer_ip}:{peer_port}",
            )
            return self._rate_limited(self._register_bucket, model.bucket)
        result = self._authorize(model.bucket, model.bucket_token, peer_ip)
        if result != "ok":
            debug_event(
                "refresh refused",
                cid=model.cid,
                bucket=model.bucket,
                peer=f"{peer_ip}:{peer_port}",
                reason=result,
            )
            return self._refusal(result, peer_ip)

        record = self.routing.get(model.cid, model.bucket, model.group)
        if record is None:
            # refresh must not create: an unknown CID is silently dropped so the
            # client falls back to a full register. Clean, anti-abuse.
            debug_event(
                "refresh dropped unknown-record",
                cid=model.cid,
                bucket=model.bucket,
                peer=f"{peer_ip}:{peer_port}",
            )
            return None
        record.touch(self.ttl)
        if model.connected is not None:
            record.connected = model.connected
        debug_event(
            "refresh ack",
            cid=model.cid,
            bucket=model.bucket,
            peer=f"{peer_ip}:{peer_port}",
            connected=record.connected,
        )
        return self._ack(peer_ip, peer_port)

    def _leave(self, model: BootLeave, peer_ip: str) -> None:
        """Remove the record; a private node also demands a valid token.

        Open mode keeps ``leave`` anonymous by design (it exposes nothing and
        the generic per-IP admission still applies). On a private node an
        anonymous leave would let anyone who knows a ``(cid, bucket)`` pair
        spoof a departure, so the D11 check applies here too. The spec has no
        response frame for ``leave``, so a refusal stays a silent drop — the
        same shape as the existing unknown-record drop — while the failed-token
        budget is charged exactly as for register/refresh/query.
        """
        if self._private and self._authorize(model.bucket, model.bucket_token, peer_ip) != "ok":
            debug_event("leave refused", cid=model.cid, bucket=model.bucket, peer=peer_ip)
            return None
        self.routing.remove(model.cid, model.bucket)
        debug_event("leave removed", cid=model.cid, bucket=model.bucket, peer=peer_ip)
        return None

    def _query(self, model: BootQuery, peer_ip: str) -> bytes:
        pair_key = f"{peer_ip}|{model.bucket}"
        if not self._limit_ok(self._query_pair, pair_key):
            debug_event("query rate_limited pair", bucket=model.bucket, peer=peer_ip)
            return self._rate_limited(self._query_pair, pair_key)
        if not self._limit_ok(self._query_bucket, model.bucket):
            debug_event("query rate_limited bucket", bucket=model.bucket, peer=peer_ip)
            return self._rate_limited(self._query_bucket, model.bucket)
        result = self._authorize(model.bucket, model.bucket_token, peer_ip)
        if result != "ok":
            debug_event("query refused", bucket=model.bucket, peer=peer_ip, reason=result)
            return self._refusal(result, peer_ip)

        records = self.routing.sample(model.bucket, model.group, model.limit)
        peers = [self._to_peer(record, model) for record in records]
        debug_event(
            "query response",
            bucket=model.bucket,
            group=model.group,
            peer=peer_ip,
            peers=len(peers),
            cids=[p.cid for p in peers],
        )
        return BOOT_RESPONSE_ADAPTER.dump_json(
            BootResponse(
                protocol_version=PROTOCOL_VERSION_BOOT,
                type="response",
                peers=peers,
                count=len(peers),
                ttl=int(self.ttl),
            )
        )

    # -------------------------------------------------------------- helpers

    def _authorize(self, bucket: str, token: str | None, peer_ip: str) -> _AuthResult:
        """D11: token-gated buckets are verified in constant time.

        Policy: an **open** node gates only the buckets the operator declared
        ``--protected-bucket``; a **private** node (``--private``) gates every
        bucket. The refusal is uniform (`token_required`) either way, so neither
        a wrong/missing token nor an unprovisioned bucket reveals that some
        other bucket exists or is provisioned.
        """
        if not (self._private or bucket in self._protected):
            return "ok"
        expected = self._tokens.get(bucket)
        if expected is not None and verify_bucket_token(expected, token):
            return "ok"
        # Failed authorization: same uniform answer, same per-IP budget. On a
        # private node a bucket with no key loaded lands here as well.
        if not self._enforce_rate_limits or self._bad_token_ip.allow(peer_ip):
            return "token_required"
        return "rate_limited"

    def _refusal(self, result: _AuthResult, peer_ip: str) -> bytes:
        error: Literal["token_required", "rate_limited"] = cast(
            Literal["token_required", "rate_limited"], result
        )
        return self._response(
            peers=[],
            error=error,
            retry_after=self._bad_token_ip.retry_after(peer_ip)
            if result == "rate_limited"
            else None,
        )

    def _rate_limited(self, limiter: TokenBucketLimiter, key: str) -> bytes:
        return self._response(
            peers=[],
            error="rate_limited",
            retry_after=limiter.retry_after(key),
        )

    def _response(
        self,
        *,
        peers: list[BootPeer],
        error: Literal["token_required", "rate_limited"] | None,
        retry_after: int | None,
    ) -> bytes:
        return BOOT_RESPONSE_ADAPTER.dump_json(
            BootResponse(
                protocol_version=PROTOCOL_VERSION_BOOT,
                type="response",
                peers=peers,
                count=len(peers),
                ttl=int(self.ttl),
                error=error,
                retry_after=retry_after,
            )
        )

    def _ack(self, peer_ip: str, peer_port: int) -> bytes:
        # STUN-echo: reply with the source endpoint the datagrams actually
        # arrived from (observed port = the NAT-mapped public port, if any).
        observed = ObservedEndpoint(proto="udp", ip=peer_ip, port=peer_port)
        return BOOT_ACK_ADAPTER.dump_json(
            BootAck(
                protocol_version=PROTOCOL_VERSION_BOOT,
                type="ack",
                observed_endpoint=observed,
                ttl=int(self.ttl),
                server_time=_utc_now_z(),
            )
        )

    @staticmethod
    def _to_peer(record: PeerRecord, model: BootQuery) -> BootPeer:
        """Prefer the peer's advertised listen endpoint over the observed source."""
        cached = record.wire
        if cached is not None:
            return cached
        if record.endpoints:
            ep = record.endpoints[0]
            peer = BootPeer(
                cid=record.cid,
                ip=ep.host,
                port=ep.port,
                proto=ep.proto,
                cert_fp=record.cert_fp,
                bucket=model.bucket,
                group=record.group,
                version=record.version,
                capacity=record.capacity,
                reachable=record.reachable,
            )
        else:
            peer = BootPeer(
                cid=record.cid,
                ip=record.ip,
                port=record.port,
                proto=record.proto,
                cert_fp=record.cert_fp,
                bucket=model.bucket,
                group=record.group,
                version=record.version,
                capacity=record.capacity,
                reachable=record.reachable,
            )
        record.wire = peer
        return peer
