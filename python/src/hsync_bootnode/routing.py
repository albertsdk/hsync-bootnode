"""In-memory routing table for ``boot/1`` — RAM only, no persistence (D7).

Keyed by ``(cid, bucket, group)``; entries carry a TTL and are pruned by a
background sweep. Queries return a random sample (``K``). Nothing is ever
written to disk from this module.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

from hsync_bootnode.protocol import BootPeer, BucketProto, Endpoint

__all__ = [
    "PeerRecord",
    "RoutingTable",
    "DEFAULT_TTL",
    "DEFAULT_PRUNE_INTERVAL",
    "DEFAULT_SAMPLE_LIMIT",
]

# Seconds (spec: client refresh every 30 s, prune every 15 s, TTL 60 s).
DEFAULT_TTL = 60.0
DEFAULT_PRUNE_INTERVAL = 15.0
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
    expires_at: float = field(default_factory=lambda: time.monotonic() + DEFAULT_TTL)
    # Materialized wire projection, lazily built by BootHandler._to_peer. Valid for
    # this object's lifetime: register always creates a NEW PeerRecord, and refresh
    # only mutates connected/expires_at (neither is part of BootPeer). capacity and
    # reachable ARE part of BootPeer, so they must never be mutated in place after
    # the wire cache is built; a changed value requires a fresh register (new
    # PeerRecord), or the cache goes stale.
    wire: BootPeer | None = field(default=None, repr=False, compare=False)

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.monotonic()) >= self.expires_at

    def touch(self, ttl: float = DEFAULT_TTL) -> None:
        self.expires_at = time.monotonic() + ttl


class RoutingTable:
    """Thread-safe in-memory registry of active peers (per ``boot/1``)."""

    def __init__(self, ttl: float = DEFAULT_TTL) -> None:
        self._ttl = ttl
        self._records: dict[tuple[str, str, str | None], PeerRecord] = {}
        self._by_group: dict[tuple[str, str | None], list[tuple[str, str, str | None]]] = {}
        self._by_cid: dict[tuple[str, str], set[tuple[str, str, str | None]]] = {}
        self._pos: dict[tuple[str, str, str | None], int] = {}

    # -- mutation ----------------------------------------------------------

    def upsert(self, record: PeerRecord) -> None:
        """Insert or refresh a peer record (register/refresh)."""
        key = (record.cid, record.bucket, record.group)
        if key not in self._records:
            lst = self._by_group.setdefault((record.bucket, record.group), [])
            self._pos[key] = len(lst)
            lst.append(key)
            self._by_cid.setdefault((record.cid, record.bucket), set()).add(key)
        self._records[key] = record

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

    def remove(self, cid: str, bucket: str) -> int:
        """Remove every record for ``(cid, bucket)`` regardless of group (leave).

        The ``leave`` frame carries no group field and a CID identifies a peer
        uniquely, so all its entries in the bucket must go. Returns the number
        of records removed.
        """
        doomed = self._by_cid.pop((cid, bucket), ())
        for key in doomed:
            self._drop(key)
        return len(doomed)

    def get(self, cid: str, bucket: str, group: str | None = None) -> PeerRecord | None:
        """Return the active record for the exact key, or ``None`` (refresh)."""
        return self._records.get((cid, bucket, group))

    def prune(self, now: float | None = None) -> int:
        """Drop expired records; returns the number of removed entries."""
        now = now if now is not None else time.monotonic()
        # Inlined PeerRecord.is_expired(now) — now is already resolved, so the
        # method would just evaluate ``now >= r.expires_at``. Inlining removes
        # one Python call per record from the TTL sweep (behaviour identical).
        expired = [k for k, r in self._records.items() if now >= r.expires_at]
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
            all_records = [records[key] for key in keys if not records[key].is_expired(now)]
            random.shuffle(all_records)
            return all_records
        # n > k: rejection-sample up to a bounded number of distinct draws; if
        # that does not yield k active records (mostly-expired group), fall back
        # to one linear pass. This caps the worst case at O(n) instead of the
        # coupon-collector O(n log n) the unbounded rejection loop would hit.
        result: list[PeerRecord] = []
        chosen: set[int] = set()
        budget = max(4 * k, 64)
        while len(result) < k and len(chosen) < budget:
            idx = random.randrange(n)
            if idx in chosen:
                continue
            chosen.add(idx)
            record = records[keys[idx]]
            if not record.is_expired(now):
                result.append(record)
        if len(result) < k:
            remaining = [records[key] for key in keys if not records[key].is_expired(now)]
            return random.sample(remaining, min(k, len(remaining)))
        return result

    def count(self, bucket: str | None = None, group: str | None = None) -> int:
        """Number of active records (optionally filtered)."""
        if bucket is None:
            return len(self._records)
        if group is None:
            return sum(1 for r in self._records.values() if r.bucket == bucket)
        return len(self._by_group.get((bucket, group), ()))
