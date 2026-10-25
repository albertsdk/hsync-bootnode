"""Host-resource detection used to size the daemon's in-memory ceilings.

The bootstrap node has no tuning file for its memory bounds: the routing table,
the rate-limiter state and the per-IP connection guard are sized from the
resources the host actually offers (available RAM, CPU count), so the same
binary behaves sensibly on a Raspberry Pi and on a large server without operator
intervention. Detection is read-only and best-effort: every source is guarded so
a sandboxed service unit that hides ``/proc`` still starts with a conservative
fallback. Nothing here is ever written to disk (no-log).

Consumers: ``hsync-bootnode.cli`` (sizes the handler and the connection guard),
``hsync-bootnode.server`` (connection guard) and the white-box tests.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Host-resource probing (cgroup v1/v2, MemAvailable) is the shared
# ``hsync_common.runtime`` implementation; this module only derives the
# bootnode-specific ceilings from it.
from hsync_common.runtime import available_memory_bytes as _shared_available_memory_bytes
from hsync_common.runtime import get_memory_limit_bytes as _get_memory_limit_bytes
from hsync_common.runtime import total_memory_bytes as _shared_total_memory_bytes

__all__ = [
    "ResourceLimits",
    "available_memory_bytes",
    "cpu_count",
    "total_memory_bytes",
]

_MIB = 1024 * 1024
_GIB = 1024 * _MIB

# Conservative estimate of one live peer entry: the record, its cached wire
# fragment, the (cid, bucket, group) key and the three index entries. Measured
# per record (tracemalloc, Python 3.14 / pydantic 2.14): ~1.8 KiB with 3
# advertised endpoints and ~4.8 KiB at the 16-endpoint maximum, so the ceiling
# must size on the worst case or a peer population of large endpoint lists would
# overshoot the memory budget.
_RECORD_BYTES = 6 * 1024
# Conservative estimate of one QUIC connection: the aioquic connection object,
# its stream table and the sessions it may run (server.MAX_SESSIONS_PER_CONNECTION,
# each with its own 4 KiB+ read buffer). aioquic's fixed 128-stream table is why
# this stays well above the session budget.
_CONNECTION_BYTES = 128 * 1024
# Conservative estimate of one rate-limiter key (a (tokens, timestamp) tuple plus
# its single dict entry; the limiter keeps one dict, not two).
_LIMITER_KEY_BYTES = 256

# Fraction of the available memory each subsystem may budget for.
_RECORD_MEMORY_FRACTION = 0.25
_LIMITER_MEMORY_FRACTION = 0.05
_CONNECTION_MEMORY_FRACTION = 0.25

# Clamps keep a pathological host (tiny container, huge server) from producing
# an unusable ceiling.
_MIN_RECORDS = 4_096
_MAX_RECORDS = 4_000_000
_MIN_LIMITER_KEYS = 4_096
_MAX_LIMITER_KEYS = 1_000_000
_MIN_CONNECTIONS = 64
_MAX_CONNECTIONS = 8_192
_MIN_CONNECTIONS_PER_IP = 16
_MAX_CONNECTIONS_PER_IP = 256
# One connection per this many CPU-bound connection slots, so a many-core host
# is not forced to serialize through a purely memory-derived cap.
_CONNECTIONS_PER_CPU = 256
# The total record ceiling is divided across (bucket, group) populations so a
# single bucket cannot be filled to the whole ceiling (which would let a botnet
# dominate one random sample); the divisor bounds how many full groups fit.
_GROUPS_PER_HOST = 256
_MIN_RECORDS_PER_GROUP = 128
_MAX_RECORDS_PER_GROUP = 100_000
# A bucket's share of the table. ``group`` is chosen by the registrant, so the
# per-(bucket, group) cap alone can be rotated around; one bucket may hold at
# most 1/_BUCKETS_PER_HOST of the whole ceiling.
_BUCKETS_PER_HOST = 8
_MIN_RECORDS_PER_BUCKET = 512
_MAX_RECORDS_PER_BUCKET = 500_000

_FALLBACK_MEMORY_BYTES = 256 * _MIB


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def _budget(
    memory: int,
    fraction: float,
    item_bytes: int,
    low: int,
    high: int,
    *,
    cap: int | None = None,
) -> int:
    """A memory-derived item count clamped into ``[low, high]`` (optional ``cap``)."""
    items = int(memory * fraction) // item_bytes
    return _clamp(items if cap is None else min(items, cap), low, high)


def cpu_count() -> int:
    """Logical CPUs visible to the process (never below 1)."""
    return max(1, os.cpu_count() or 1)


def total_memory_bytes() -> int:
    """Physical memory the process may use, in bytes (best effort).

    The cgroup limit wins when one is enforced (a container may see the whole
    host through ``sysconf``); the conservative fallback keeps a sandboxed
    service unit that hides ``/proc`` usable instead of giving it zero budget.
    """
    limit = _get_memory_limit_bytes()
    if limit is not None:
        return limit
    return _shared_total_memory_bytes() or _FALLBACK_MEMORY_BYTES


def available_memory_bytes() -> int:
    """Currently available memory, in bytes (best effort).

    Delegates to the shared probe (``MemAvailable`` capped by the process's
    cgroup limit) and degrades to the total when the statistics are unreadable.
    """
    available = _shared_available_memory_bytes()
    if available is not None:
        return available
    return total_memory_bytes()


@dataclass(slots=True, kw_only=True)
class ResourceLimits:
    """Memory/CPU-derived ceilings shared by the handler and the transport.

    ``max_records_per_bucket`` is the anti-monopoly ceiling a registrant cannot
    rotate around (``group`` is free-form), ``max_records_per_group`` the
    per-sample ceiling; both sit under the global ``max_peer_records``.

    Instantiate with :meth:`detect` in production; the tests construct explicit
    values so the caps are deterministic.
    """

    max_peer_records: int
    max_limiter_keys: int
    max_active_connections: int
    max_active_connections_per_ip: int
    max_records_per_group: int
    max_records_per_bucket: int

    @classmethod
    def detect(cls) -> ResourceLimits:
        """Derive the ceilings from the host's available memory and CPU count."""
        memory = available_memory_bytes()
        cpu = cpu_count()
        records = _budget(
            memory, _RECORD_MEMORY_FRACTION, _RECORD_BYTES, _MIN_RECORDS, _MAX_RECORDS
        )
        limiter_keys = _budget(
            memory,
            _LIMITER_MEMORY_FRACTION,
            _LIMITER_KEY_BYTES,
            _MIN_LIMITER_KEYS,
            _MAX_LIMITER_KEYS,
        )
        connections = _budget(
            memory,
            _CONNECTION_MEMORY_FRACTION,
            _CONNECTION_BYTES,
            _MIN_CONNECTIONS,
            _MAX_CONNECTIONS,
            cap=cpu * _CONNECTIONS_PER_CPU,
        )
        per_ip = _clamp(connections // 8, _MIN_CONNECTIONS_PER_IP, _MAX_CONNECTIONS_PER_IP)
        per_group = _clamp(
            records // _GROUPS_PER_HOST, _MIN_RECORDS_PER_GROUP, _MAX_RECORDS_PER_GROUP
        )
        per_bucket = _clamp(
            records // _BUCKETS_PER_HOST, _MIN_RECORDS_PER_BUCKET, _MAX_RECORDS_PER_BUCKET
        )
        return cls(
            max_peer_records=records,
            max_limiter_keys=limiter_keys,
            max_active_connections=connections,
            max_active_connections_per_ip=per_ip,
            max_records_per_group=per_group,
            max_records_per_bucket=per_bucket,
        )
