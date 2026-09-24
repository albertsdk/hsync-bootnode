"""``boot/1`` token derivation and constant-time comparison.

The bucket token is derived from the existing group key ``HSYNC_P2P_KEY``:
``HMAC-SHA256(key, "boot/1" || bucket)[:32]``, hex-encoded (64 chars). The key
itself is never transported on the wire; only the derived token is.
"""

from __future__ import annotations

import hashlib
import hmac

from hsync_bootnode.protocol import _BUCKET_TOKEN_RE, BUCKET_TOKEN_LEN

__all__ = [
    "derive_bucket_token",
    "is_valid_bucket_token",
    "constant_time_equals",
    "verify_bucket_token",
]

_DOMAIN = b"boot/1"


def derive_bucket_token(key: bytes, bucket: str) -> str:
    """Derive the 64-char hex bucket token for the given group key + bucket."""
    digest = hmac.new(key, _DOMAIN + bucket.encode("utf-8"), hashlib.sha256).digest()
    return digest[:32].hex()


def is_valid_bucket_token(value: str) -> bool:
    """True iff ``value`` is a well-formed 64-char lowercase hex token."""
    return _BUCKET_TOKEN_RE.match(value) is not None


def constant_time_equals(a: bytes, b: bytes) -> bool:
    """Constant-time byte-string comparison (no timing side-channel)."""
    return hmac.compare_digest(a, b)


def verify_bucket_token(expected: str, provided: str | None) -> bool:
    """Return True iff a provided token matches the expected one, uniformly.

    A missing/malformed token simply never matches (caller decides whether the
    bucket requires one — this helper never reveals that a bucket exists).
    """
    if provided is None:
        return False
    if not is_valid_bucket_token(provided):
        return False
    return constant_time_equals(
        expected.encode("ascii"),
        provided.encode("ascii"),
    )


assert len(derive_bucket_token(b"secret", "shared")) == BUCKET_TOKEN_LEN
