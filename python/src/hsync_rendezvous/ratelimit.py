"""In-memory token-bucket rate limiters for the rendezvous.

The implementation is the ``hsync_common.ratelimit`` SSOT shared with
``hsync-client``; this facade keeps the ``hsync_rendezvous.ratelimit`` import path
used by the boot server, handler and tests.
"""

from __future__ import annotations

from hsync_common.ratelimit import TokenBucketLimiter

__all__ = [
    "TokenBucketLimiter",
]
