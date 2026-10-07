"""``boot/1`` request handling — pure logic, no network transport.

``BootHandler`` is the transport-agnostic core of the bootstrap node: it owns
the in-memory routing table, the token-authorization policy (constant-time token
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
from typing import Literal

from pydantic import SecretStr, ValidationError

from hsync_bootnode.diagnostics import debug_enabled, debug_event, debug_log
from hsync_bootnode.protocol import (
    BOOT_ACK_ADAPTER,
    BOOT_FRAME_ADAPTER,
    BOOT_RESPONSE_ADAPTER,
    BUCKET_TOKEN_LEN,
    PROTOCOL_VERSION_BOOT,
    BootAck,
    BootError,
    BootLeave,
    BootPeer,
    BootQuery,
    BootRefresh,
    BootRegister,
    BootResponse,
    Endpoint,
    ObservedEndpoint,
)
from hsync_bootnode.ratelimit import TokenBucketLimiter
from hsync_bootnode.resources import ResourceLimits
from hsync_bootnode.routing import DEFAULT_TTL, PeerRecord, RoutingTable
from hsync_bootnode.tokens import (
    constant_time_equals,
    derive_bucket_token,
    is_valid_bucket_token,
)

__all__ = [
    "BootConfigError",
    "BootHandler",
]

# Token authorization / spec rate limits (in-memory sliding windows). Budgets
# are per minute over ``WINDOW_SECONDS`` unless stated otherwise.
OP_IP_RATE_PER_SECOND = 10.0  # per-IP admission: ~10 req/s, burst 50 (spec)
OP_IP_BURST = 50
QUERY_PAIR_LIMIT = 5  # query per (IP, bucket)
QUERY_PAIR_BURST = 10
QUERY_IP_LIMIT = 20  # query per IP across every bucket (anti-enumeration)
QUERY_IP_BURST = 40
REGISTER_PAIR_LIMIT = 10  # register/refresh per (IP, bucket)
REGISTER_PAIR_BURST = 10
BAD_TOKEN_IP_LIMIT = 5  # failed-token attempts per IP
# Malformed/unknown frames: own budget per IP (rationale in handle()); it also
# gates the parser, so an IP that exhausts it is dropped before parsing.
PARSE_IP_LIMIT = 30  # invalid frames per IP per minute
PARSE_IP_BURST = 60
WINDOW_SECONDS = 60.0

# Fallback token compared against when a bucket has no provisioned key, so the
# authorization path costs the same whether or not the bucket is provisioned.
_DUMMY_TOKEN = "0" * BUCKET_TOKEN_LEN

# Internal authorization outcome used by register/refresh/query.
_AuthResult = Literal["ok", "token_required", "rate_limited"]

# TTL sweep cadence (spec: prune every 15 s).
_PRUNE_INTERVAL_SECONDS = 15.0

# Max expired records one request-path sweep may remove (see _maybe_prune).
REQUEST_PATH_PRUNE_BUDGET = 2048


class BootConfigError(RuntimeError):
    """Invalid operator configuration (fail fast at startup, never silently)."""


_LAST_UTC_SECOND = -1
_LAST_UTC_Z = ""


def _utc_now_z() -> str:
    """UTC timestamp in the fixture format ``2026-10-09T10:00:00Z``.

    Cached per wall-clock second: the format has one-second resolution, so every
    ACK inside the same second carries the identical string, and a registration
    burst skips one ``strftime`` per frame (the cache key is the epoch second;
    a clock step still forces a reformat).
    """
    global _LAST_UTC_SECOND, _LAST_UTC_Z
    now = time.time()
    second = int(now)
    if second != _LAST_UTC_SECOND:
        _LAST_UTC_Z = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        _LAST_UTC_SECOND = second
    return _LAST_UTC_Z


class BootHandler:
    """Matchmaker core: routing + authorization (token policy / private) + anti-abuse limits."""

    def __init__(
        self,
        *,
        ttl: float = DEFAULT_TTL,
        protected_buckets: Iterable[str] = (),
        private: bool = False,
        group_keys: Mapping[str, SecretStr] | None = None,
        routing: RoutingTable | None = None,
        enforce_rate_limits: bool = True,
        limits: ResourceLimits | None = None,
    ) -> None:
        self.ttl = ttl
        # Memory ceilings are host-derived unless a caller (tests, embedding)
        # supplies them explicitly; they bound the routing table and the
        # rate-limiter key population.
        self.limits = limits if limits is not None else ResourceLimits.detect()
        self.routing = (
            routing
            if routing is not None
            else RoutingTable(
                max_records=self.limits.max_peer_records,
                max_records_per_group=self.limits.max_records_per_group,
            )
        )
        # ``None`` sentinel forces the first handle() to sweep; a 0.0 seed would
        # skip the first sweep when monotonic() < prune_interval (recent boot).
        self._last_prune: float | None = None
        # Benchmark/test seam: disable every token bucket so measured ops stay
        # on the unthrottled fast path (--no-rate-limit).
        self._enforce_rate_limits = enforce_rate_limits

        self._protected: set[str] = set(protected_buckets)
        # Node-wide policy: with private mode every bucket is token-gated, so
        # every bucket the operator provisions a key for is authorized (the protected-bucket
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

        max_keys = self.limits.max_limiter_keys
        # Every limiter is bounded in both key population and rate; each one is
        # keyed by source IP (or (IP, bucket)), never by a shared bucket alone,
        # so a single abusive source cannot exhaust a global budget.
        self._ops_ip = TokenBucketLimiter(
            OP_IP_BURST, OP_IP_RATE_PER_SECOND, 1.0, max_keys=max_keys
        )
        self._query_pair = TokenBucketLimiter(
            QUERY_PAIR_BURST, QUERY_PAIR_LIMIT, WINDOW_SECONDS, max_keys=max_keys
        )
        self._query_ip = TokenBucketLimiter(
            QUERY_IP_BURST, QUERY_IP_LIMIT, WINDOW_SECONDS, max_keys=max_keys
        )
        self._register_pair = TokenBucketLimiter(
            REGISTER_PAIR_BURST, REGISTER_PAIR_LIMIT, WINDOW_SECONDS, max_keys=max_keys
        )
        self._bad_token_ip = TokenBucketLimiter(
            BAD_TOKEN_IP_LIMIT, BAD_TOKEN_IP_LIMIT, WINDOW_SECONDS, max_keys=max_keys
        )
        self._bad_parse_ip = TokenBucketLimiter(
            PARSE_IP_BURST, PARSE_IP_LIMIT, WINDOW_SECONDS, max_keys=max_keys
        )
        debug_event(
            "handler ready",
            ttl=int(self.ttl),
            private=self._private,
            protected_buckets=len(self._protected),
            group_keys=len(self._tokens),
            rate_limits=self._enforce_rate_limits,
            max_peer_records=self.limits.max_peer_records,
            max_limiter_keys=max_keys,
        )

    # ------------------------------------------------------------------ API

    def _maybe_prune(self) -> None:
        """Run a TTL sweep at most once per prune_interval.

        The request-path sweep carries a removal budget: pruning runs
        synchronously inside the frame handler, so a node that fell far behind
        (huge stale backlog, e.g. after a vanished upstream or under a burst)
        must not do the whole sweep on the event loop in one go — the
        background sweep (with no budget) converges within one interval
        anyway.
        """
        now = time.monotonic()
        if self._last_prune is None or now - self._last_prune >= self.prune_interval:
            self.prune(now, max_remove=REQUEST_PATH_PRUNE_BUDGET)
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
        # Pre-parse gate: once an IP has exhausted its malformed-frame budget,
        # every further frame from it is dropped BEFORE the parser runs, so a
        # parse storm costs no CPU beyond the line read. A well-behaved IP never
        # drains that budget (only invalid frames charge it), so its valid
        # traffic is unaffected; only an IP that actually flooded invalid frames
        # is gated wholesale (the documented anti-abuse trade-off).
        if self._enforce_rate_limits and not self._bad_parse_ip.has_tokens(peer_ip):
            if debug_enabled():
                debug_event(
                    "drop pre-parse over-budget", peer=f"{peer_ip}:{peer_port}", bytes=len(raw)
                )
            return None
        try:
            frame = BOOT_FRAME_ADAPTER.validate_json(raw)
        except ValidationError:
            # Charge the budget that gates the check above; the drop stays a
            # silent no-op (no oracle) and invalid frames never drain the
            # VALID-frame per-IP admission.
            if self._enforce_rate_limits:
                self._bad_parse_ip.allow(peer_ip)
            if debug_enabled():
                debug_event("drop invalid-frame", peer=f"{peer_ip}:{peer_port}", bytes=len(raw))
            return None
        # Admission is charged only for VALID frames (malformed/unknown frames
        # stay silently dropped and are bounded by their own budget above).
        if not self._limit_ok(self._ops_ip, peer_ip):
            if debug_enabled():
                debug_event("rate_limited ip-admission", peer=f"{peer_ip}:{peer_port}")
            return self._rate_limited(self._ops_ip, peer_ip)

        # Prune expired records periodically (spec: every 15 s) so memory does
        # not grow unbounded under sustained load. Runs on the first handle()
        # (self._last_prune is None) and then once per prune_interval.
        self._maybe_prune()

        if debug_enabled():
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

    def prune(self, now: float | None = None, *, max_remove: int | None = None) -> int:
        """Drop expired records (TTL sweep); returns number removed."""
        removed = self.routing.prune(now, max_remove=max_remove)
        if now is None:
            # Background sweep only: also bound the rate-limiter state. Evicting
            # fully-refilled buckets is behaviour-identical to keeping them, and
            # keeping this off the request path avoids adding latency to a frame.
            for limiter in (
                self._ops_ip,
                self._query_pair,
                self._query_ip,
                self._register_pair,
                self._bad_token_ip,
                self._bad_parse_ip,
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

    def _register(self, model: BootRegister, peer_ip: str, peer_port: int) -> bytes | None:
        refused = self._admit(
            "register",
            self._register_pair,
            model.bucket,
            model.bucket_token,
            peer_ip,
            peer_port,
            cid=model.cid,
        )
        if refused is not None:
            return refused
        if not self._may_replace(model.cid, model.bucket, model.group, peer_ip):
            # A foreign source must not overwrite a live registration it does
            # not own (the source-IP ownership rule, like leave): the frame is
            # dropped silently and the existing record survives.
            if debug_enabled():
                debug_event(
                    "register dropped foreign-source",
                    cid=model.cid,
                    bucket=model.bucket,
                    peer=f"{peer_ip}:{peer_port}",
                )
            return None

        record = PeerRecord.from_register(model, peer_ip=peer_ip, peer_port=peer_port)
        record.touch(self.ttl)
        if not self.routing.upsert(record):
            # Bounded table: reclaim expired entries once, then signal
            # backpressure with ``overloaded`` (the node is at its host-derived
            # ceiling — not a client abuse signal) instead of growing RAM without
            # limit. Pass ``now`` so this request-path sweep stays record-only
            # (limiter eviction is the background sweep's job).
            self.prune(time.monotonic(), max_remove=REQUEST_PATH_PRUNE_BUDGET)
            if not self.routing.upsert(record):
                if debug_enabled():
                    debug_event(
                        "register refused table-full",
                        cid=model.cid,
                        bucket=model.bucket,
                        peer=f"{peer_ip}:{peer_port}",
                        error="overloaded",
                    )
                return self._response(
                    peers=[], error="overloaded", retry_after=max(1, int(self.ttl))
                )
        if debug_enabled():
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
        refused = self._admit(
            "refresh",
            self._register_pair,
            model.bucket,
            model.bucket_token,
            peer_ip,
            peer_port,
            cid=model.cid,
        )
        if refused is not None:
            return refused

        record = self.routing.get(model.cid, model.bucket, model.group)
        if record is None:
            # refresh must not create: an unknown CID is silently dropped so the
            # client falls back to a full register. Clean, anti-abuse.
            if debug_enabled():
                debug_event(
                    "refresh dropped unknown-record",
                    cid=model.cid,
                    bucket=model.bucket,
                    peer=f"{peer_ip}:{peer_port}",
                )
            return None
        if not self._may_replace(model.cid, model.bucket, model.group, peer_ip):
            # A foreign source must not renew someone else's record either;
            # otherwise an attacker's overwrite (or a stale entry) would be kept
            # alive by the victim's own refresh loop.
            if debug_enabled():
                debug_event(
                    "refresh dropped foreign-source",
                    cid=model.cid,
                    bucket=model.bucket,
                    peer=f"{peer_ip}:{peer_port}",
                )
            return None
        record.touch(self.ttl)
        if model.connected is not None:
            record.connected = model.connected
        if debug_enabled():
            debug_event(
                "refresh ack",
                cid=model.cid,
                bucket=model.bucket,
                peer=f"{peer_ip}:{peer_port}",
                connected=record.connected,
            )
        return self._ack(peer_ip, peer_port)

    def _may_replace(self, cid: str, bucket: str, group: str | None, peer_ip: str) -> bool:
        """Whether ``peer_ip`` may create/replace the ``(cid, bucket, group)`` record.

        An absent record is always claimable. A live record is owned by the
        source network it registered from: only the same source IP may replace
        or renew it, unless the frame was already token-authorized (a protected
        or private bucket), which authenticates bucket membership from any
        source — the same model ``leave`` uses.
        """
        record = self.routing.get(cid, bucket, group)
        if record is None or record.ip == peer_ip:
            return True
        return self._private or bucket in self._protected

    def _leave(self, model: BootLeave, peer_ip: str) -> None:
        """Remove the record; unauthorized departures are silently ignored.

        Three authorization paths, in order:
            1. private node: the protected-bucket token check applies exactly
               as for register/refresh/query;
            2. protected bucket on an open node: a valid token authenticates
               the departure from any source IP;
            3. open bucket (the default): a departure is honoured only from
               the source network the peer registered from (same observed IP).
               A ``leave`` from any other IP is ignored, so an attacker who
               knows a ``(cid, bucket)`` pair can no longer evict someone else.
               A peer behind a NAT rebound keeps its TTL (60 s) as before: it
               re-registers with the next cycle.

        The failed-token budget is charged exactly as for register/refresh/
        query when a token was checked. The spec has no response frame for
        ``leave``, so every refusal stays a silent drop.
        """
        if self._private:
            if self._authorize(model.bucket, model.bucket_token, peer_ip) != "ok":
                if debug_enabled():
                    debug_event("leave refused", cid=model.cid, bucket=model.bucket, peer=peer_ip)
                return
            self.routing.remove(model.cid, model.bucket)
            if debug_enabled():
                debug_event("leave removed", cid=model.cid, bucket=model.bucket, peer=peer_ip)
            return
        if peer_ip in self.routing.source_ips(model.cid, model.bucket):
            self.routing.remove(model.cid, model.bucket, source_ip=peer_ip)
            if debug_enabled():
                debug_event("leave removed", cid=model.cid, bucket=model.bucket, peer=peer_ip)
            return
        if (
            model.bucket in self._protected
            and self._authorize(model.bucket, model.bucket_token, peer_ip) == "ok"
        ):
            self.routing.remove(model.cid, model.bucket)
            if debug_enabled():
                debug_event("leave removed", cid=model.cid, bucket=model.bucket, peer=peer_ip)
            return
        if debug_enabled():
            debug_event(
                "leave ignored foreign-source",
                cid=model.cid,
                bucket=model.bucket,
                peer=peer_ip,
            )
        return

    def _query(self, model: BootQuery, peer_ip: str) -> bytes:
        pair_key = f"{peer_ip}|{model.bucket}"
        if not self._limit_ok(self._query_pair, pair_key):
            if debug_enabled():
                debug_event("query rate_limited pair", bucket=model.bucket, peer=peer_ip)
            return self._rate_limited(self._query_pair, pair_key)
        if not self._limit_ok(self._query_ip, peer_ip):
            # Aggregate per-IP cap across every bucket: one source cannot sweep
            # the bucket namespace to enumerate the peer population.
            if debug_enabled():
                debug_event("query rate_limited ip", bucket=model.bucket, peer=peer_ip)
            return self._rate_limited(self._query_ip, peer_ip)
        refused = self._authorize_or_refuse(
            "query", model.bucket, model.bucket_token, peer_ip, peer_display=peer_ip
        )
        if refused is not None:
            return refused

        records = self.routing.sample(model.bucket, model.group, model.limit)
        to_peer = self._to_peer
        peers = [to_peer(record, model) for record in records]
        if debug_enabled():
            debug_event(
                "query response",
                bucket=model.bucket,
                group=model.group,
                peer=peer_ip,
                peers=len(peers),
                cids=[p.cid for p in peers],
            )
        return self._response(peers=peers, error=None, retry_after=None)

    # -------------------------------------------------------------- helpers

    def _authorize(self, bucket: str, token: str | None, peer_ip: str) -> _AuthResult:
        """Token-gated buckets are verified in constant time.

        Policy: an **open** node gates only the buckets the operator declared
        ``--protected-bucket``; a **private** node (``--private``) gates every
        bucket. The refusal is uniform (`token_required`) either way, so neither
        a wrong/missing token nor an unprovisioned bucket reveals that some
        other bucket exists or is provisioned. The comparison runs in constant
        time on the same 64-byte shapes whether or not the bucket has a key, so
        timing does not reveal the provisioned set either.
        """
        if not (self._private or bucket in self._protected):
            return "ok"
        expected = self._tokens.get(bucket)
        provided_valid = token is not None and is_valid_bucket_token(token)
        candidate = token if token is not None and provided_valid else _DUMMY_TOKEN
        reference = expected if expected is not None else _DUMMY_TOKEN
        matched = constant_time_equals(reference.encode("ascii"), candidate.encode("ascii"))
        if expected is not None and provided_valid and matched:
            return "ok"
        # Failed authorization: same uniform answer, same per-IP budget. On a
        # private node a bucket with no key loaded lands here as well.
        if not self._enforce_rate_limits or self._bad_token_ip.allow(peer_ip):
            return "token_required"
        return "rate_limited"

    def _authorize_or_refuse(
        self,
        event: str,
        bucket: str,
        token: str | None,
        peer_ip: str,
        *,
        peer_display: str,
        cid: str | None = None,
    ) -> bytes | None:
        """Authorize a bucket; return the refusal bytes, or ``None`` when admitted.

        One place owns the token policy's refusal shape (debug line + response), so
        register/refresh/query cannot drift.
        """
        result = self._authorize(bucket, token, peer_ip)
        if result == "ok":
            return None
        if debug_enabled():
            debug_event(
                f"{event} refused",
                cid=cid,
                bucket=bucket,
                peer=peer_display,
                reason=result,
            )
        return self._refusal(result, peer_ip)

    def _admit(
        self,
        event: str,
        limiter: TokenBucketLimiter,
        bucket: str,
        token: str | None,
        peer_ip: str,
        peer_port: int,
        *,
        cid: str | None = None,
    ) -> bytes | None:
        """Charge the per-(IP, bucket) limiter, then authorize; ``None`` = admitted.

        Shared by register and refresh. The limiter is keyed by (source IP,
        bucket) so a single abusive source cannot exhaust a budget shared with
        every other peer of the bucket.
        """
        pair_key = f"{peer_ip}|{bucket}"
        if not self._limit_ok(limiter, pair_key):
            if debug_enabled():
                debug_event(
                    f"{event} rate_limited pair",
                    cid=cid,
                    bucket=bucket,
                    peer=f"{peer_ip}:{peer_port}",
                )
            return self._rate_limited(limiter, pair_key)
        return self._authorize_or_refuse(
            event, bucket, token, peer_ip, peer_display=f"{peer_ip}:{peer_port}", cid=cid
        )

    def _refusal(self, error: Literal["token_required", "rate_limited"], peer_ip: str) -> bytes:
        return self._response(
            peers=[],
            error=error,
            retry_after=self._bad_token_ip.retry_after(peer_ip)
            if error == "rate_limited"
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
        error: BootError | None,
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
        """Relay the peer's full advertised candidate list over the observed source.

        Every declared ``endpoints[]`` element is relayed verbatim and in order;
        only a register that carried no endpoint at all (the first STUN
        register) falls back to a single-element list with the observed source
        endpoint. Both branches share one projection so the relayed advisory
        fields (``capacity``, ``reachable`` and the election advertisement)
        cannot drift; the whole record is relayed verbatim and never
        interpreted.
        """
        cached = record.wire
        if cached is not None:
            return cached
        if record.endpoints:
            endpoints = list(record.endpoints)
        else:
            endpoints = [Endpoint(proto=record.proto, host=record.ip, port=record.port)]
        peer = BootPeer(
            cid=record.cid,
            endpoints=endpoints,
            cert_fp=record.cert_fp,
            bucket=model.bucket,
            group=record.group,
            version=record.version,
            capacity=record.capacity,
            reachable=record.reachable,
            server_ready=record.server_ready,
            force_master=record.force_master,
            never_master=record.never_master,
            startup_time=record.startup_time,
            sync_direction=record.sync_direction,
        )
        record.wire = peer
        return peer
