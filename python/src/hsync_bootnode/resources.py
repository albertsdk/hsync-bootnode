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

__all__ = [
    "ResourceLimits",
    "available_memory_bytes",
    "cpu_count",
    "total_memory_bytes",
]

_MIB = 1024 * 1024
_GIB = 1024 * _MIB

# Conservative estimate of one live peer entry: the record, its materialized
# wire projection, the (cid, bucket, group) key and the three index entries.
_RECORD_BYTES = 4 * 1024
# Conservative estimate of one QUIC connection: the aioquic connection object,
# its fixed 128-stream table and the per-stream read buffers.
_CONNECTION_BYTES = 128 * 1024
# Conservative estimate of one rate-limiter key (two floats plus dict overhead).
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

_FALLBACK_MEMORY_BYTES = 256 * _MIB
# cgroup "no limit" sentinel: v2 spells it ``max``, v1 uses a value near 2**63.
_UNLIMITED_BYTES = 1 << 62


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def _read_first_int(path: str) -> int | None:
    """Return the first integer token of a procfs/sysfs file, or ``None``."""
    try:
        with open(path, encoding="ascii") as handle:
            for line in handle:
                token = line.strip().split()[0] if line.strip() else ""
                if token.isdigit():
                    return int(token)
    except (OSError, ValueError):
        return None
    return None


def _process_cgroup_limit_bytes() -> int | None:
    """The limit of the process's OWN cgroup, resolved via ``/proc/self/cgroup``.

    systemd services and containers with a non-namespaced cgroup view run in a
    nested cgroup, so the mount root ``memory.max`` is often ``max`` while the
    enforced limit lives under the service's slice; a root-only probe would miss
    an operator's ``MemoryMax=`` and over-size the in-memory ceilings.
    """
    try:
        with open("/proc/self/cgroup", encoding="ascii") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) != 3 or not parts[2]:
            continue
        controllers, path = parts[1], parts[2]
        if controllers == "":  # cgroup v2 unified hierarchy
            candidate = f"/sys/fs/cgroup{path}/memory.max"
        elif "memory" in controllers.split(","):  # cgroup v1
            candidate = f"/sys/fs/cgroup/memory{path}/memory.limit_in_bytes"
        else:
            continue
        value = _read_first_int(candidate)
        if value is not None and 0 < value < _UNLIMITED_BYTES:
            return value
    return None


def _cgroup_memory_limit_bytes() -> int | None:
    """The effective cgroup memory limit, or ``None`` when unlimited.

    The process's own (possibly nested) cgroup is consulted first, then the
    mount root; ``max`` (v2) and the v1 sentinel near ``2**63`` mean no limit.
    """
    value = _process_cgroup_limit_bytes()
    if value is not None:
        return value
    for path in (
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ):
        value = _read_first_int(path)
        if value is not None and 0 < value < _UNLIMITED_BYTES:
            return value
    return None


def cpu_count() -> int:
    """Logical CPUs visible to the process (never below 1)."""
    return max(1, os.cpu_count() or 1)


def total_memory_bytes() -> int:
    """Physical memory the process may use, in bytes (best effort)."""
    limit = _cgroup_memory_limit_bytes()
    if limit is not None:
        return limit
    try:
        pages = int(os.sysconf("SC_PHYS_PAGES"))
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        if pages > 0 and page_size > 0:
            return pages * page_size
    except (ValueError, OSError, AttributeError):
        pass
    return _FALLBACK_MEMORY_BYTES


def available_memory_bytes() -> int:
    """Currently available memory, in bytes (best effort).

    ``MemAvailable`` is preferred when readable; a cgroup limit caps the result
    so a container cannot over-commit the host.
    """
    limit = _cgroup_memory_limit_bytes()
    try:
        with open("/proc/meminfo", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    available = int(line.split()[1]) * 1024
                    if available > 0:
                        return min(available, limit) if limit is not None else available
    except (OSError, ValueError, IndexError):
        pass
    if limit is not None:
        return limit
    return total_memory_bytes()


class ResourceLimits:
    """Memory/CPU-derived ceilings shared by the handler and the transport.

    Instantiate with :meth:`detect` in production; the tests construct explicit
    values so the caps are deterministic.
    """

    __slots__ = (
        "max_active_connections",
        "max_active_connections_per_ip",
        "max_limiter_keys",
        "max_peer_records",
        "max_records_per_group",
    )

    def __init__(
        self,
        *,
        max_peer_records: int,
        max_limiter_keys: int,
        max_active_connections: int,
        max_active_connections_per_ip: int,
        max_records_per_group: int,
    ) -> None:
        self.max_peer_records = max_peer_records
        self.max_limiter_keys = max_limiter_keys
        self.max_active_connections = max_active_connections
        self.max_active_connections_per_ip = max_active_connections_per_ip
        self.max_records_per_group = max_records_per_group

    @classmethod
    def detect(cls) -> ResourceLimits:
        """Derive the ceilings from the host's available memory and CPU count."""
        memory = available_memory_bytes()
        cpu = cpu_count()
        records = _clamp(
            int(memory * _RECORD_MEMORY_FRACTION) // _RECORD_BYTES,
            _MIN_RECORDS,
            _MAX_RECORDS,
        )
        limiter_keys = _clamp(
            int(memory * _LIMITER_MEMORY_FRACTION) // _LIMITER_KEY_BYTES,
            _MIN_LIMITER_KEYS,
            _MAX_LIMITER_KEYS,
        )
        connections = _clamp(
            min(
                int(memory * _CONNECTION_MEMORY_FRACTION) // _CONNECTION_BYTES,
                cpu * _CONNECTIONS_PER_CPU,
            ),
            _MIN_CONNECTIONS,
            _MAX_CONNECTIONS,
        )
        per_ip = _clamp(
            connections // 8,
            _MIN_CONNECTIONS_PER_IP,
            _MAX_CONNECTIONS_PER_IP,
        )
        per_group = _clamp(
            records // _GROUPS_PER_HOST,
            _MIN_RECORDS_PER_GROUP,
            _MAX_RECORDS_PER_GROUP,
        )
        return cls(
            max_peer_records=records,
            max_limiter_keys=limiter_keys,
            max_active_connections=connections,
            max_active_connections_per_ip=per_ip,
            max_records_per_group=per_group,
        )

    def as_fields(self) -> dict[str, int]:
        """The ceilings as a flat mapping (startup diagnostics)."""
        return {
            "max_peer_records": self.max_peer_records,
            "max_limiter_keys": self.max_limiter_keys,
            "max_active_connections": self.max_active_connections,
            "max_active_connections_per_ip": self.max_active_connections_per_ip,
            "max_records_per_group": self.max_records_per_group,
        }
