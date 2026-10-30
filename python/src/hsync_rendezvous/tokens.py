"""``rdv/1`` token derivation and constant-time comparison.

The bucket token is derived from the group key (the raw ``HSYNC_P2P_KEY``, or the
64-hex key derived from ``HSYNC_P2P_PASSPHRASE``):
``HMAC-SHA256(key, "rdv/1" || bucket)[:32]``, hex-encoded (64 chars). The key
itself is never transported on the wire; only the derived token is.

The algorithm and the token grammar are the shared, protocol-neutral
implementation in :mod:`hsync_common.protocol.rdv_tokens` (ADR-0033 keeps the
frame *models* separate, not the cryptography); this module only re-exports it
so the daemon's import path stays stable.
"""

from __future__ import annotations

from hsync_common.protocol.rdv_tokens import (
    BUCKET_TOKEN_LEN,
    constant_time_equals,
    derive_bucket_token,
    is_valid_bucket_token,
    verify_bucket_token,
)

__all__ = [
    "BUCKET_TOKEN_LEN",
    "constant_time_equals",
    "derive_bucket_token",
    "is_valid_bucket_token",
    "verify_bucket_token",
]
