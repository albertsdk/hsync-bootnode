"""Diagnostics for the bootstrap node: an always-on operational channel plus the
opt-in peer-aware debug stream.

The node is **no-log by design**: nothing peer-related is ever written to
**disk**. The routing table is RAM-only, the TLS identity is regenerated per
process, and without ``--debug`` no peer data leaves memory at all.

Two channels
------------

``warn_event`` / ``error_event`` — **node health, always emitted** (stderr):
UPnP mapping unavailable, an unwritable readiness file, an unexpected session
failure. They accept only the non-identifying field allow-list
:data:`_PUBLIC_FIELDS`: a peer-identifying field (CID, bucket, IP, port) raises
instead of being rendered, so the default run stays peer-free **by
construction** and the no-log invariant holds even though this channel is on.
The setting follows the practice for rendezvous infrastructure (Tor relay
operators: log at an operational level by default, expose user IPs only for a
specific debug session; RFC 8932 §5.2: minimize or discard correlation data;
RFC 6973 §6.1: data minimization): identifying data is debug-only, and the
always-on stream carries the node's own operational state.

``debug_log`` / ``debug_event`` — the opt-in full operation log
(``--debug`` / ``HSYNC_BOOTNODE_DEBUG=1``), an *explicit operator opt-in* that
follows the whole request life cycle — connections opened/closed, frames
received, the decision taken, records created/refreshed/removed, TTL sweeps and
refusals — **including the peer identity** (CID, bucket, IP, port). That detail
is exactly what makes the log usable for analysis, and it exists only in this
mode and only on stderr: the process still never writes it to disk, and a normal
run emits no debug line.

Line format (``timestamp source[instance]: level: message``) for both channels::

    2026-09-30T10:30:45.123Z - hsync-bootnode[1234] debug: register ack cid=… bucket=shared
    2026-09-30T10:30:45.200Z - hsync-bootnode[1234] warn: upnp no igd on lan port=443

The timestamp is the UTC ISO-8601 SSOT (:func:`hsync_common.time_utils.utc_now_iso`)
because no log transport supplies one here: the shipped service units forward or
discard stderr, so this stream *is* the whole artefact, and it must be
correlatable with the timestamped ``hsync-client``/``hsync-server`` logs. The
pid identifies which instance emitted the line when several share one stderr
(benchmarks, two nodes on one host); the level marker keeps the peer-aware
stream distinguishable from the always-on operational one.
"""

from __future__ import annotations

import os
import sys
import time
from collections import deque

from hsync_common.time_utils import utc_now_iso

__all__ = [
    "configure_debug",
    "debug_enabled",
    "debug_event",
    "debug_log",
    "error_event",
    "warn_event",
]

# Program name of the emitted lines' identity prefix (``hsync-bootnode[1234]``).
_LOG_IDENTITY = "hsync-bootnode"

# Fields ``warn_event``/``error_event`` may render. Everything here describes the
# node or the host, never a peer: the always-on channel is persisted by the
# operator, so a CID, bucket, peer endpoint or peer port must not be able to
# reach it (``debug_event`` is the only peer-aware sink).
_PUBLIC_FIELDS = frozenset({"action", "exc", "path", "port", "proto", "reason", "suppressed"})

# Bound a rendered value so a malformed/attacker-influenced string cannot grow a
# line without limit (OWASP: log injection and log-flooding availability risk).
_MAX_VALUE_CHARS = 200

# Anti-flood for the always-on error channel: a repeated failure must not emit a
# line per occurrence (nor grow state without bound). Inside the window only the
# count is kept; the next emission reports it as ``suppressed=<n>``.
_DEDUP_WINDOW_SECONDS = 60.0
_DEDUP_MAX_KEYS = 64

_enabled = False
# ``(event, rendered fields) -> (window start, suppressed count)``, plus the
# insertion order used to keep the mapping bounded.
_dedup: dict[tuple[str, str], tuple[float, int]] = {}
_dedup_order: deque[tuple[str, str]] = deque()


def configure_debug(enabled: bool) -> None:
    """Enable or disable the stderr debug sink (process-wide)."""
    global _enabled
    _enabled = enabled


def debug_enabled() -> bool:
    """Whether the operator opted into the debug sink."""
    return _enabled


def _sanitize(value: object) -> str:
    """Render one line fragment (event name or field value) as log-safe text.

    Newlines, tabs and other control characters become spaces, so no fragment can
    forge a second log line (OWASP log injection); the result is truncated to
    :data:`_MAX_VALUE_CHARS`.
    """
    text = "".join(ch if ch >= " " and ch != "\x7f" else " " for ch in str(value))
    if len(text) > _MAX_VALUE_CHARS:
        text = text[:_MAX_VALUE_CHARS] + "…"
    return text


def _render(event: str, fields: dict[str, object], *, allowed: frozenset[str] | None) -> str:
    """Render ``event key=value ...`` (``None`` fields are omitted).

    Both the event name and every value go through :func:`_sanitize`, so no part
    of the line can contain a control character and forge a second line. With
    ``allowed`` set, a key outside it is a programming error and raises: the
    always-on channel fails loudly rather than leaking peer identity.
    """
    parts = [_sanitize(event)]
    for key, value in fields.items():
        if value is None:
            continue
        if allowed is not None and key not in allowed:
            raise ValueError(
                f"diagnostic field {key!r} is not allowed on the always-on channel "
                f"(allowed: {', '.join(sorted(allowed))}); peer-identifying fields "
                "belong to debug_event(), which requires --debug"
            )
        parts.append(f"{key}={_sanitize(value)}")
    return " ".join(parts)


def _emit(level: str, body: str) -> None:
    """Write one ``timestamp - source[pid] level: body`` line to stderr.

    The single emission point for every channel, so the prefix is rendered once.
    The pid is resolved per line — a fork without ``exec`` would otherwise keep
    logging the parent's pid (the same reason loguru renders
    ``record["process"].id`` per record).
    """
    sys.stderr.write(f"{utc_now_iso()} - {_LOG_IDENTITY}[{os.getpid()}] {level}: {body}\n")
    sys.stderr.flush()


def _dedup_suppressed(key: tuple[str, str]) -> int | None:
    """Throttle a repeated always-on error.

    Returns ``0`` when the line must be emitted as-is, a positive count when it
    must be emitted with ``suppressed=<n>`` (the occurrences hidden in the
    previous window) and ``None`` when this occurrence is a repeat inside the
    current window and must stay silent.
    """
    now = time.monotonic()
    entry = _dedup.get(key)
    if entry is not None and now - entry[0] < _DEDUP_WINDOW_SECONDS:
        _dedup[key] = (entry[0], entry[1] + 1)
        return None
    suppressed = entry[1] if entry is not None else 0
    _evict_dedup(now)
    _dedup[key] = (now, 0)
    _dedup_order.append(key)
    return suppressed


def _evict_dedup(now: float) -> None:
    """Bound the dedup state: drop expired windows, then the oldest keys."""
    while _dedup_order:
        key = _dedup_order[0]
        entry = _dedup.get(key)
        expired = entry is None or now - entry[0] >= _DEDUP_WINDOW_SECONDS
        if not expired and len(_dedup_order) <= _DEDUP_MAX_KEYS:
            return
        _dedup.pop(key, None)
        _dedup_order.popleft()


def debug_log(message: str) -> None:
    """Emit one free-form diagnostic line (no-op unless enabled)."""
    if _enabled:
        _emit("debug", _sanitize(message))


def debug_event(event: str, **fields: object) -> None:
    """Emit one structured debug line: ``event key=value ...`` (opt-in only).

    Fields with a ``None`` value are omitted. The sink is an explicit opt-in, so
    callers may include peer-identifying fields (CID, bucket, IP, port) here — and
    only here. Names and values pass through :func:`_sanitize`.
    """
    if not _enabled:
        return
    _emit("debug", _render(event, fields, allowed=None))


def warn_event(event: str, **fields: object) -> None:
    """Emit one always-on operational warning (peer-free by construction).

    Use for node health: a capability that could not be enabled, a degraded
    mode, an operator-visible misconfiguration. ``fields`` is restricted to
    :data:`_PUBLIC_FIELDS`; passing a peer-identifying key raises ``ValueError``.
    """
    _emit("warn", _render(event, fields, allowed=_PUBLIC_FIELDS))


def error_event(event: str, **fields: object) -> None:
    """Emit one always-on operational error (peer-free by construction).

    Same field policy as :func:`warn_event`. Repeated identical errors are
    throttled (:data:`_DEDUP_WINDOW_SECONDS`) and reported as ``suppressed=<n>``
    on the next emission, so a failing path cannot flood the operator's log.
    """
    body = _render(event, fields, allowed=_PUBLIC_FIELDS)
    suppressed = _dedup_suppressed((event, body))
    if suppressed is None:
        return
    if suppressed:
        body = f"{body} suppressed={suppressed}"
    _emit("error", body)
