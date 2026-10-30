"""Bounded NDJSON read framing shared by every stream protocol.

One reader serves both the rendezvous request loop (``server.py``, bounded to
``MAX_FRAME_BYTES``, no idle timer) and the relay listener's keepalive line
(``relay.py``, bounded to the control-frame size, with an idle timeout): the
framing logic must never drift between the two paths.
"""

from __future__ import annotations

import asyncio
from typing import Any

__all__ = ["FrameTooLarge", "read_ndjson"]

_READ_CHUNK_BYTES = 4096


class FrameTooLarge(Exception):
    """One NDJSON line exceeded its byte bound (refused, no-log)."""


async def read_ndjson(
    reader: Any,
    pending: bytearray,
    *,
    max_bytes: int,
    idle_timeout: float | None = None,
) -> bytes | None:
    """Read one newline-terminated NDJSON frame, bounded to ``max_bytes``.

    ``pending`` keeps bytes already received but not yet consumed, so several
    frames sent back-to-back on the same stream are each returned in turn (no
    pipelined frame is ever lost). Returns ``None`` on EOF; with
    ``idle_timeout`` a stalled read also returns ``None``. A frame longer than
    ``max_bytes`` — newline beyond the bound, or no newline within it — raises
    :class:`FrameTooLarge`; a larger read chunk must not let it slip through as
    a legitimate frame just because its newline arrived in the same read.
    """
    while True:
        newline = pending.find(b"\n")
        if newline != -1:
            if newline > max_bytes:
                raise FrameTooLarge
            frame = bytes(pending[:newline])
            del pending[: newline + 1]
            return frame
        if len(pending) > max_bytes:
            raise FrameTooLarge
        try:
            if idle_timeout is None:
                chunk = await reader.read(_READ_CHUNK_BYTES)
            else:
                chunk = await asyncio.wait_for(reader.read(_READ_CHUNK_BYTES), idle_timeout)
        except (TimeoutError, ConnectionError, OSError):
            return None
        if not chunk:
            return None
        pending.extend(chunk)
