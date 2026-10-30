"""Readiness and watchdog signalling for a systemd-managed node (sd_notify).

The packaged units run the node as ``Type=notify`` with ``WatchdogSec=``: the
service manager then learns when the QUIC listeners are actually bound (not when
the process merely forked) and restarts a node whose event loop stopped making
progress. Outside systemd — ``$NOTIFY_SOCKET`` unset, i.e. a container without
systemd, launchd, Windows or a foreground run — every call is a no-op, so the
node behaves identically with and without a service manager.

Consumer: ``hsync_rendezvous.cli`` (the ``run`` command), which announces READY
once the listeners are bound, STOPPING before the transports close, and
WATCHDOG at half the armed interval.
"""

from __future__ import annotations

import os
import socket

__all__ = [
    "notify_available",
    "notify_ready",
    "notify_status",
    "notify_stopping",
    "notify_watchdog",
    "watchdog_interval",
]

# systemd encodes an abstract-namespace AF_UNIX address with a leading '@' (the
# real sockaddr starts with a NUL byte instead of a filesystem path).
_ABSTRACT_PREFIX = "@"

# A STATUS= assignment is a single line, and the whole notification datagram stays
# far below the manager's buffer: render a bounded one-liner whatever the caller
# passes (defensive, the counters themselves are already bounded).
_STATUS_MAX_CHARS = 200


def _send(payload: str) -> bool:
    """Send one sd_notify datagram; ``False`` when no service manager listens.

    Best-effort by contract: a manager that stopped (closed ``$NOTIFY_SOCKET``)
    or a socket path this process may not reach must never disturb the node.
    """
    address = os.environ.get("NOTIFY_SOCKET")
    if not address or not hasattr(socket, "AF_UNIX"):
        return False
    if address.startswith(_ABSTRACT_PREFIX):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.send(payload.encode("utf-8"))
    except (OSError, ValueError):
        return False
    return True


def notify_available() -> bool:
    """True when a service manager is reachable (``$NOTIFY_SOCKET`` is set)."""
    return bool(os.environ.get("NOTIFY_SOCKET"))


def _sanitize_status(status: str) -> str:
    """Collapse a status line to one bounded line (``STATUS=`` is single-line)."""
    return " ".join(status.split())[:_STATUS_MAX_CHARS]


def notify_ready(status: str | None = None) -> bool:
    """Announce ``READY=1`` plus the optional ``STATUS=`` once the listeners are bound."""
    if status is None:
        return _send("READY=1")
    return _send(f"READY=1\nSTATUS={_sanitize_status(status)}")


def notify_status(status: str) -> bool:
    """Announce the current state as ``STATUS=`` (shown by ``systemctl status``)."""
    return _send(f"STATUS={_sanitize_status(status)}")


def notify_stopping() -> bool:
    """Announce ``STOPPING=1`` before the transports are closed."""
    return _send("STOPPING=1")


def notify_watchdog() -> bool:
    """Feed the watchdog (``WATCHDOG=1``) so systemd keeps the unit alive."""
    return _send("WATCHDOG=1")


def watchdog_interval() -> float | None:
    """Half of ``$WATCHDOG_USEC`` in seconds, or ``None`` when no watchdog is armed.

    systemd derives ``WATCHDOG_USEC`` from the unit's ``WatchdogSec=`` and sets
    ``WATCHDOG_PID`` to the process that must ping. A ping addressed to another
    process, an unparsable value and ``0`` (watchdog disabled) all disable the
    feed instead of guessing an interval.
    """
    raw = os.environ.get("WATCHDOG_USEC")
    if not raw:
        return None
    watchdog_pid = os.environ.get("WATCHDOG_PID")
    if watchdog_pid is not None and watchdog_pid.strip() != str(os.getpid()):
        return None
    try:
        microseconds = int(raw)
    except ValueError:
        return None
    if microseconds <= 0:
        return None
    return microseconds / 2_000_000
