"""In-memory token-bucket rate limiters — RAM only, no persistence.

A token bucket expresses the spec's ``N/min (burst B)`` semantics exactly:
the bucket holds at most ``capacity`` tokens (the burst) and is refilled at
``refill`` tokens per ``window`` seconds (the sustained rate), lazily on each
check using a monotonic clock. Expired state is pruned lazily too; nothing is
ever written to disk.
"""

from __future__ import annotations

import time

__all__ = [
    "RateLimitKey",
    "TokenBucketLimiter",
]

RateLimitKey = str


class TokenBucketLimiter:
    """Per-key token bucket: at most ``capacity`` tokens, refill ``refill``/window.

    ``allow(key)`` consumes one token and returns True, or returns False when
    the bucket is empty; ``retry_after(key)`` then reports the seconds until
    the next token is available so the caller can answer with an explicit
    ``retry_after`` instead of silently dropping. Bucket state initialises on
    first use and refills lazily on each check (monotonic clock); a caller may
    pass ``now`` explicitly for deterministic tests.
    """

    def __init__(self, capacity: int, refill: float, window: float = 60.0) -> None:
        if capacity < 1 or refill <= 0 or window <= 0:
            raise ValueError("capacity/refill/window must be positive")
        self._capacity = float(capacity)
        self._rate = refill / window  # tokens per second
        self._tokens: dict[RateLimitKey, float] = {}
        self._updated: dict[RateLimitKey, float] = {}

    def allow(self, key: RateLimitKey, now: float | None = None) -> bool:
        now = now if now is not None else time.monotonic()
        # Inlined _refill(): the check is the per-frame hot path (one call per
        # admitted metric), so it avoids a second method call and the redundant
        # ``_tokens`` write _refill would do before this method overwrites it.
        updated_at = self._updated.get(key)
        if updated_at is None:
            tokens = self._capacity
        else:
            elapsed = now - updated_at
            if elapsed < 0.0:
                elapsed = 0.0
            tokens = self._tokens[key] + elapsed * self._rate
            if tokens > self._capacity:
                tokens = self._capacity
        self._updated[key] = now
        if tokens < 1.0:
            self._tokens[key] = tokens
            return False
        self._tokens[key] = tokens - 1.0
        return True

    def retry_after(self, key: RateLimitKey, now: float | None = None) -> int:
        """Seconds until the next token of ``key`` becomes available (>=1)."""
        now = now if now is not None else time.monotonic()
        tokens = self._refill(key, now)
        if tokens >= 1.0:
            return 1
        seconds = (1.0 - tokens) / self._rate
        return max(1, int(seconds) + 1)

    def evict_stale(self, now: float | None = None) -> int:
        """Drop buckets that have fully refilled since their last check.

        A key untouched for ``capacity / rate`` seconds refills to exactly
        ``capacity`` — the value a first-use key starts from — so evicting it is
        behaviour-identical to keeping it, and bounds memory under IP churn.
        """
        now = now if now is not None else time.monotonic()
        horizon = self._capacity / self._rate
        stale = [k for k, ts in self._updated.items() if now - ts >= horizon]
        for k in stale:
            del self._tokens[k]
            del self._updated[k]
        return len(stale)

    def _refill(self, key: RateLimitKey, now: float) -> float:
        """Return the (unconsumed) token count after applying the elapsed refill."""
        updated_at = self._updated.get(key)
        if updated_at is None:
            self._tokens[key] = self._capacity
            self._updated[key] = now
            return self._capacity
        elapsed = max(0.0, now - updated_at)
        tokens = min(self._capacity, self._tokens[key] + elapsed * self._rate)
        self._tokens[key] = tokens
        self._updated[key] = now
        return tokens
