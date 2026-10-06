"""In-memory routing table for ``boot/1`` — RAM only, no persistence.

Keyed by ``(cid, bucket, group)``; entries carry a TTL and are pruned by a
background sweep. Queries return a random sample (``K``). Nothing is ever
written to disk from this module.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field

from hsync_bootnode.protocol import BootPeer, BootRegister, BucketProto, Endpoint, SyncDirection

__all__ = [
    "DEFAULT_SAMPLE_LIMIT",
    "DEFAULT_TTL",
    "PeerRecord",
    "RoutingTable",
]

# Peer sampling is part of the matchmaker's exposure surface: with the
# predictable MT19937 generator a heavy query loop could reconstruct state and
# steer future samples. An OS-backed generator (SystemRandom) keeps the
# matchmaking unpredictable at no functional cost.
_RNG = secrets.SystemRandom()

# Seconds (spec: client refresh every 30 s, prune every 15 s, TTL 60 s).
DEFAULT_TTL = 60.0
DEFAULT_SAMPLE_LIMIT = 20


@dataclass(slots=True)
class PeerRecord:
    """A single active peer in a bucket/group."""

    cid: str
    bucket: str
    group: str | None
    ip: str
    port: int
    proto: BucketProto
    cert_fp: str
    version: str
    endpoints: list[Endpoint]
    connected: int = 0
    reachable: bool = True
    capacity: int = 0
    # Election advertisement relayed verbatim from ``register`` (defaults when
    # the peer advertised none). The node never interprets these values.
    server_ready: bool = False
    force_master: bool = False
    never_master: bool = False
    startup_time: float = 0.0
    sync_direction: SyncDirection = "bidirectional"
    expires_at: float = field(default_factory=lambda: time.monotonic() + DEFAULT_TTL)
    # Materialized wire projection, lazily built by BootHandler._to_peer. Valid for
    # this object's lifetime: register always creates a NEW PeerRecord, and refresh
    # only mutates connected/expires_at (neither is part of BootPeer). Every other
    # field IS part of BootPeer (the endpoints list, capacity, reachable and the
    # election advertisement), so none of them may be mutated in place after the
    # wire cache is built; a changed value requires a fresh register (new
    # PeerRecord), or the cache goes stale.
    wire: BootPeer | None = field(default=None, repr=False, compare=False)

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.monotonic()) >= self.expires_at

    def touch(self, ttl: float = DEFAULT_TTL) -> None:
        self.expires_at = time.monotonic() + ttl

    @classmethod
    def from_register(cls, model: BootRegister, *, peer_ip: str, peer_port: int) -> PeerRecord:
        """Build a record from a validated ``register`` frame.

        The observed source (``peer_ip``/``peer_port``) is the STUN-echo endpoint;
        every other field is relayed verbatim from the frame (or its documented
        default). One projector keeps ``register`` handling in sync with the model.
        """
        return cls(
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
            server_ready=model.server_ready,
            force_master=model.force_master,
            never_master=model.never_master,
            startup_time=model.startup_time,
            sync_direction=model.sync_direction,
        )


class RoutingTable:
    """Thread-safe in-memory registry of active peers (per ``boot/1``)."""

    def __init__(
        self,
        *,
        max_records: int | None = None,
        max_records_per_group: int | None = None,
    ) -> None:
        self._records: dict[tuple[str, str, str | None], PeerRecord] = {}
        self._by_group: dict[tuple[str, str | None], list[tuple[str, str, str | None]]] = {}
        self._by_cid: dict[tuple[str, str], set[tuple[str, str, str | None]]] = {}
        self._pos: dict[tuple[str, str, str | None], int] = {}
        self._max_records = max_records
        self._max_per_group = max_records_per_group

    # -- mutation ----------------------------------------------------------

    def upsert(self, record: PeerRecord) -> bool:
        """Insert or refresh a peer record; ``False`` when a ceiling is hit.

        An existing key is always updated (it does not grow the table). A new
        key is refused once ``max_records`` is reached, or once its
        ``(bucket, group)`` population reaches ``max_records_per_group`` — the
        per-group ceiling stops one bucket from being filled to the whole
        ceiling and dominating its random sample. Either refusal lets the caller
        answer with backpressure instead of growing RAM without limit.
        """
        key = (record.cid, record.bucket, record.group)
        if key not in self._records:
            if self._max_records is not None and len(self._records) >= self._max_records:
                return False
            group_keys = self._by_group.get((record.bucket, record.group))
            if (
                self._max_per_group is not None
                and group_keys is not None
                and len(group_keys) >= self._max_per_group
            ):
                return False
            lst = self._by_group.setdefault((record.bucket, record.group), [])
            self._pos[key] = len(lst)
            lst.append(key)
            self._by_cid.setdefault((record.cid, record.bucket), set()).add(key)
        self._records[key] = record
        return True

    def _unindex(self, key: tuple[str, str, str | None]) -> None:
        """Remove ``key`` from ``_by_group``/``_pos`` (O(1) swap-remove).

        Does NOT touch ``_by_cid``: ``remove`` pops the whole ``(cid, bucket)`` set
        itself, and ``prune`` discards the key from it inline.
        """
        bucket, group = key[1], key[2]
        lst = self._by_group[(bucket, group)]
        pos = self._pos.pop(key)
        last = lst[-1]
        if pos != len(lst) - 1:
            lst[pos] = last
            self._pos[last] = pos
        lst.pop()
        if not lst:
            del self._by_group[(bucket, group)]

    def _drop(self, key: tuple[str, str, str | None]) -> None:
        """Remove ``key`` from ``_records`` and the group index."""
        del self._records[key]
        self._unindex(key)

    def _rebuild_indexes(self) -> None:
        """Rebuild every secondary index from ``_records`` in one linear pass."""
        by_group: dict[tuple[str, str | None], list[tuple[str, str, str | None]]] = {}
        by_cid: dict[tuple[str, str], set[tuple[str, str, str | None]]] = {}
        pos: dict[tuple[str, str, str | None], int] = {}
        for key in self._records:
            lst = by_group.setdefault((key[1], key[2]), [])
            pos[key] = len(lst)
            lst.append(key)
            by_cid.setdefault((key[0], key[1]), set()).add(key)
        self._by_group = by_group
        self._by_cid = by_cid
        self._pos = pos

    def remove(
        self,
        cid: str,
        bucket: str,
        *,
        source_ip: str | None = None,
    ) -> int:
        """Remove records for ``(cid, bucket)`` regardless of group (leave).

        The ``leave`` frame carries no group field and a CID identifies a peer
        uniquely, so all of the caller's entries in the bucket must go.

        ``source_ip`` narrows the removal to records observed from that source
        IP: the handler's leave policy lets a peer only depart from the network
        it registered from, so a record owned by a *different* source IP must
        survive (it is someone else's registration, not an abuse the caller
        gets to rewrite). ``source_ip=None`` removes everything (token-
        authenticated departures and the token-gated private path).

        Returns the number of records removed.
        """
        keys = self._by_cid.get((cid, bucket))
        if not keys:
            return 0
        records = self._records
        doomed = [key for key in keys if source_ip is None or records[key].ip == source_ip]
        for key in doomed:
            self._drop(key)
            # _drop (via _unindex) does not touch _by_cid — see its contract:
            # the caller updates the cid index, so it always mirrors _records.
            keys.discard(key)
        if not keys:
            self._by_cid.pop((cid, bucket), None)
        return len(doomed)

    def source_ips(self, cid: str, bucket: str) -> list[str]:
        """Observed source IPs of every active record for ``(cid, bucket)``.

        Used by the leave policy to decide whether the sender may be the
        legitimate owner of the registration.
        """
        keys = self._by_cid.get((cid, bucket))
        if not keys:
            return []
        return [self._records[key].ip for key in keys]

    def get(self, cid: str, bucket: str, group: str | None = None) -> PeerRecord | None:
        """Return the active record for the exact key, or ``None`` (refresh)."""
        return self._records.get((cid, bucket, group))

    def prune(self, now: float | None = None, *, max_remove: int | None = None) -> int:
        """Drop expired records; returns the number of removed entries.

        ``max_remove`` caps how many records one sweep drops (an on-request
        path calls this with a budget so a huge stale backlog cannot stall the
        event loop; the background sweep keeps ``None`` and fully converges).
        Left-over expired records are picked up by the next sweep.
        """
        now = now if now is not None else time.monotonic()
        # Inlined PeerRecord.is_expired(now) — now is already resolved, so the
        # method would just evaluate ``now >= r.expires_at``. Inlining removes
        # one Python call per record from the TTL sweep (behaviour identical).
        expired = [k for k, r in self._records.items() if now >= r.expires_at]
        if max_remove is not None and len(expired) > max_remove:
            expired = expired[:max_remove]
        if not expired:
            return 0
        total = len(self._records)
        if len(expired) == total:
            # Full expiry: drop every structure in one C-level pass instead of
            # N dict deletes plus an index rebuild (the DB-equivalent of TRUNCATE).
            self._records.clear()
            self._by_group.clear()
            self._by_cid.clear()
            self._pos.clear()
            return total
        for key in expired:
            del self._records[key]
        if len(expired) * 2 >= total:
            # Mass expiry: one bulk rebuild beats N swap-removes + set discards.
            self._rebuild_indexes()
        else:
            for key in expired:
                self._unindex(key)
                cset = self._by_cid[(key[0], key[1])]
                cset.discard(key)
                if not cset:
                    del self._by_cid[(key[0], key[1])]
        return len(expired)

    # -- queries -----------------------------------------------------------

    def sample(
        self,
        bucket: str,
        group: str | None = None,
        limit: int = DEFAULT_SAMPLE_LIMIT,
        now: float | None = None,
    ) -> list[PeerRecord]:
        """Return a random sample (up to ``limit``) of active peers in the bucket."""
        now = now if now is not None else time.monotonic()
        keys = self._by_group.get((bucket, group))
        if not keys:
            return []
        records = self._records
        n = len(keys)
        k = min(limit, n)
        if k == n:
            # Single ``records[key]`` lookup per key (walrus) instead of the
            # is_expired() call plus a second lookup in the comprehension.
            all_records = [record for key in keys if now < (record := records[key]).expires_at]
            _RNG.shuffle(all_records)
            return all_records
        # n > k: rejection-sample up to a bounded number of distinct draws; if
        # that does not yield k active records (mostly-expired group), fall back
        # to one linear pass. This caps the worst case at O(n) instead of the
        # coupon-collector O(n log n) the unbounded rejection loop would hit.
        result: list[PeerRecord] = []
        chosen: set[int] = set()
        budget = max(4 * k, 64)
        while len(result) < k and len(chosen) < budget:
            idx = _RNG.randrange(n)
            if idx in chosen:
                continue
            chosen.add(idx)
            record = records[keys[idx]]
            if now < record.expires_at:
                result.append(record)
        if len(result) < k:
            remaining = [record for key in keys if now < (record := records[key]).expires_at]
            return _RNG.sample(remaining, min(k, len(remaining)))
        return result

    def count(self, bucket: str | None = None, group: str | None = None) -> int:
        """Number of active records (optionally filtered)."""
        if bucket is None:
            return len(self._records)
        if group is None:
            return sum(1 for r in self._records.values() if r.bucket == bucket)
        return len(self._by_group.get((bucket, group), ()))
