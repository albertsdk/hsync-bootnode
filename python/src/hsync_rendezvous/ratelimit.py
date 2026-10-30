"""In-memory token-bucket rate limiters for the rendezvous.

The implementation is the ``hsync_common.ratelimit`` SSOT shared with
``hsync-client``; the boot server, the handler and the tests import the limiter
from ``hsync_rendezvous.ratelimit``.
"""

from __future__ import annotations

from hsync_common.ratelimit import TokenBucketLimiter

__all__ = [
    "TokenBucketLimiter",
]
