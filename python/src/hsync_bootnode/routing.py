"""In-memory routing table for ``boot/1`` — RAM only, no persistence (D7).

Keyed by ``(cid, bucket, group)``; entries carry a TTL and are pruned by a
background sweep. Queries return a random sample (``K``). Nothing is ever
written to disk from this module.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

from hsync_bootnode.protocol import BucketProto, Endpoint

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
    expires_at: float = field(default_factory=lambda: time.monotonic() + DEFAULT_TTL)

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.monotonic()) >= self.expires_at

    def touch(self, ttl: float = DEFAULT_TTL) -> None:
        self.expires_at = time.monotonic() + ttl


class RoutingTable:
    """Thread-safe in-memory registry of active peers (per ``boot/1``)."""

    def __init__(self, ttl: float = DEFAULT_TTL) -> None:
        self._ttl = ttl
        self._records: dict[tuple[str, str, str | None], PeerRecord] = {}

    # -- mutation ----------------------------------------------------------

    def upsert(self, record: PeerRecord) -> None:
        """Insert or refresh a peer record (register/refresh)."""
        key = (record.cid, record.bucket, record.group)
        self._records[key] = record

    def remove(self, cid: str, bucket: str) -> int:
        """Remove every record for ``(cid, bucket)`` regardless of group (leave).

        The ``leave`` frame carries no group field and a CID identifies a peer
        uniquely, so all its entries in the bucket must go. Returns the number
        of records removed.
        """
        doomed = [key for key in self._records if key[0] == cid and key[1] == bucket]
        for key in doomed:
            del self._records[key]
        return len(doomed)

    def get(self, cid: str, bucket: str, group: str | None = None) -> PeerRecord | None:
        """Return the active record for the exact key, or ``None`` (refresh)."""
        return self._records.get((cid, bucket, group))

    def prune(self, now: float | None = None) -> int:
        """Drop expired records; returns the number of removed entries."""
        now = now if now is not None else time.monotonic()
        expired = [k for k, r in self._records.items() if r.is_expired(now)]
        for key in expired:
            del self._records[key]
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
        candidates = [
            r
            for r in self._records.values()
            if r.bucket == bucket and r.group == group and not r.is_expired(now)
        ]
        k = min(limit, len(candidates))
        return random.sample(candidates, k)

    def count(self, bucket: str | None = None, group: str | None = None) -> int:
        """Number of active records (optionally filtered)."""
        if bucket is None:
            return len(self._records)
        if group is None:
            return sum(1 for r in self._records.values() if r.bucket == bucket)
        return sum(1 for r in self._records.values() if r.bucket == bucket and r.group == group)
