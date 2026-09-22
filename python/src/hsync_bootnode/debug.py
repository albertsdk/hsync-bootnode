"""Opt-in stderr diagnostics for the bootstrap node (disabled by default).

The node is **no-log by design** (D7): nothing peer-related is ever written to
**disk**. The routing table is RAM-only, the TLS identity is regenerated per
process, and without ``--debug`` no peer data leaves memory at all.

``--debug`` / ``HSYNC_BOOTNODE_DEBUG=1`` is an *explicit operator opt-in* that
installs a stderr sink following the full request life cycle — connections
opened/closed, frames received, the decision taken, records created/refreshed/
removed, TTL sweeps and refusals — **including the peer identity** (CID, bucket,
IP, port). That detail is exactly what makes the log
usable for analysis, and it exists only in this mode and only on stderr: the
process still never writes it to disk, and a normal run emits nothing.
"""

from __future__ import annotations

import sys

__all__ = ["configure_debug", "debug_enabled", "debug_event", "debug_log"]

_enabled = False


def configure_debug(enabled: bool) -> None:
    """Enable or disable the stderr debug sink (process-wide)."""
    global _enabled
    _enabled = enabled


def debug_enabled() -> bool:
    """Whether the operator opted into the debug sink."""
    return _enabled


def debug_log(message: str) -> None:
    """Emit one free-form diagnostic line (no-op unless enabled)."""
    if _enabled:
        sys.stderr.write(f"[hsync-bootnode][debug] {message}\n")
        sys.stderr.flush()


def debug_event(event: str, **fields: object) -> None:
    """Emit one structured diagnostic line: ``event key=value ...``.

    Fields with a ``None`` value are omitted. Values are rendered verbatim: the
    sink is an explicit opt-in, so callers may include peer-identifying fields
    (CID, bucket, IP, port) here — and only here.
    """
    if not _enabled:
        return
    parts = [event]
    parts.extend(f"{key}={value}" for key, value in fields.items() if value is not None)
    sys.stderr.write("[hsync-bootnode][debug] " + " ".join(parts) + "\n")
    sys.stderr.flush()
