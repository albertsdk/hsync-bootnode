"""``boot/1`` request handling — pure logic, no network transport.

``BootHandler`` is the transport-agnostic core of the bootstrap node: it owns
the in-memory routing table, the D11 protected-bucket enforcement (constant-time
token check), the per-IP/per-bucket rate limiters and the STUN-echo reply
building. The QUIC layer (``server.py``) only parses frames, calls
:meth:`BootHandler.handle` and writes whatever dict comes back.

No-log invariant: nothing in this module ever opens a file for writing.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Literal, cast

from pydantic import SecretStr, ValidationError

from hsync_bootnode.protocol import (
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
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class BootHandler:
    """Matchmaker core: routing + authorization (D11) + anti-abuse limits."""

    def __init__(
        self,
        *,
        ttl: float = DEFAULT_TTL,
        protected_buckets: Iterable[str] = (),
        group_keys: Mapping[str, SecretStr] | None = None,
        routing: RoutingTable | None = None,
    ) -> None:
        self.ttl = ttl
        self.routing = routing if routing is not None else RoutingTable(ttl=ttl)

        self._protected: set[str] = set(protected_buckets)
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

    # ------------------------------------------------------------------ API

    def handle(
        self,
        frame: object,
        *,
        peer_ip: str,
        peer_port: int,
    ) -> dict | None:
        """Process one decoded frame; return the response frame or ``None`` to drop.

        Malformed / unknown frames are silently dropped (no-log, no oracle).
        """
        if not isinstance(frame, dict):
            return None
        if not self._ops_ip.allow(peer_ip):
            return self._rate_limited(self._ops_ip, peer_ip)

        frame_type = frame.get("type")
        try:
            if frame_type == "register":
                register = BootRegister.model_validate(frame)
                return self._register(register, peer_ip, peer_port)
            if frame_type == "refresh":
                refresh = BootRefresh.model_validate(frame)
                return self._refresh(refresh, peer_ip, peer_port)
            if frame_type == "leave":
                leave = BootLeave.model_validate(frame)
                self._leave(leave)
                return None
            if frame_type == "query":
                query = BootQuery.model_validate(frame)
                return self._query(query, peer_ip)
        except ValidationError:
            return None
        return None

    def prune(self, now: float | None = None) -> int:
        """Drop expired records (TTL sweep); returns number removed."""
        return self.routing.prune(now)

    @property
    def prune_interval(self) -> float:
        return _PRUNE_INTERVAL_SECONDS

    # ------------------------------------------------------------- register

    def _register(self, model: BootRegister, peer_ip: str, peer_port: int) -> dict:
        if not self._register_bucket.allow(model.bucket):
            return self._rate_limited(self._register_bucket, model.bucket)
        result = self._authorize(model.bucket, model.bucket_token, peer_ip)
        if result != "ok":
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
            reachable=True,
        )
        record.touch(self.ttl)
        self.routing.upsert(record)
        return self._ack(peer_ip, peer_port)

    def _refresh(self, model: BootRefresh, peer_ip: str, peer_port: int) -> dict | None:
        if not self._register_bucket.allow(model.bucket):
            return self._rate_limited(self._register_bucket, model.bucket)
        result = self._authorize(model.bucket, model.bucket_token, peer_ip)
        if result != "ok":
            return self._refusal(result, peer_ip)

        record = self.routing.get(model.cid, model.bucket, model.group)
        if record is None:
            # refresh must not create: an unknown CID is silently dropped so the
            # client falls back to a full register. Clean, anti-abuse.
            return None
        record.touch(self.ttl)
        if model.connected is not None:
            record.connected = model.connected
        return self._ack(peer_ip, peer_port)

    def _leave(self, model: BootLeave) -> None:
        # Anonymous by design: exposes nothing, no token, no rate limit beyond
        # the generic per-IP admission. No response frame (spec has none).
        self.routing.remove(model.cid, model.bucket)
        return None

    def _query(self, model: BootQuery, peer_ip: str) -> dict:
        pair_key = f"{peer_ip}|{model.bucket}"
        if not self._query_pair.allow(pair_key):
            return self._rate_limited(self._query_pair, pair_key)
        if not self._query_bucket.allow(model.bucket):
            return self._rate_limited(self._query_bucket, model.bucket)
        result = self._authorize(model.bucket, model.bucket_token, peer_ip)
        if result != "ok":
            return self._refusal(result, peer_ip)

        records = self.routing.sample(model.bucket, model.group, model.limit)
        peers = [self._to_peer(record, model) for record in records]
        return BootResponse(
            protocol_version=PROTOCOL_VERSION_BOOT,
            type="response",
            peers=peers,
            count=len(peers),
            ttl=int(self.ttl),
        ).model_dump(mode="json")

    # -------------------------------------------------------------- helpers

    def _authorize(self, bucket: str, token: str | None, peer_ip: str) -> _AuthResult:
        """D11: protected buckets require a valid token, compared in constant time.

        Open buckets (not declared by the operator) require nothing. The refusal
        is uniform (`token_required`) — a wrong/missing token never reveals that
        a bucket exists.
        """
        if bucket not in self._protected:
            return "ok"
        if verify_bucket_token(self._tokens[bucket], token):
            return "ok"
        if self._bad_token_ip.allow(peer_ip):
            return "token_required"
        return "rate_limited"

    def _refusal(self, result: _AuthResult, peer_ip: str) -> dict:
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

    def _rate_limited(self, limiter: TokenBucketLimiter, key: str) -> dict:
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
    ) -> dict:
        return BootResponse(
            protocol_version=PROTOCOL_VERSION_BOOT,
            type="response",
            peers=peers,
            count=len(peers),
            ttl=int(self.ttl),
            error=error,
            retry_after=retry_after,
        ).model_dump(mode="json")

    def _ack(self, peer_ip: str, peer_port: int) -> dict:
        # STUN-echo: reply with the source endpoint the datagrams actually
        # arrived from (observed port = the NAT-mapped public port, if any).
        observed = ObservedEndpoint(proto="udp", ip=peer_ip, port=peer_port)
        return BootAck(
            protocol_version=PROTOCOL_VERSION_BOOT,
            type="ack",
            observed_endpoint=observed,
            ttl=int(self.ttl),
            server_time=_utc_now_z(),
        ).model_dump(mode="json")

    @staticmethod
    def _to_peer(record: PeerRecord, model: BootQuery) -> BootPeer:
        """Prefer the peer's advertised listen endpoint over the observed source."""
        if record.endpoints:
            ep = record.endpoints[0]
            return BootPeer(
                cid=record.cid,
                ip=ep.host,
                port=ep.port,
                proto=ep.proto,
                cert_fp=record.cert_fp,
                bucket=model.bucket,
                group=record.group,
                version=record.version,
                reachable=record.reachable,
            )
        return BootPeer(
            cid=record.cid,
            ip=record.ip,
            port=record.port,
            proto=record.proto,
            cert_fp=record.cert_fp,
            bucket=model.bucket,
            group=record.group,
            version=record.version,
            reachable=record.reachable,
        )
