"""Opt-in stderr diagnostics for the bootstrap node (disabled by default).

The node is no-log by design (D7): nothing peer-related is ever written to
disk. This module provides an *explicitly opt-in* stderr sink
(``--debug`` / ``HSYNC_BOOTNODE_DEBUG=1``) that emits NON-PII diagnostics only —
frame types, outcomes, counters and lifecycle events, never IPs, CIDs or
fingerprints — so an operator can troubleshoot the node without weakening the
no-log invariant.
"""

from __future__ import annotations

import sys

__all__ = ["configure_debug", "debug_log"]

_enabled = False


def configure_debug(enabled: bool) -> None:
    """Enable or disable the stderr debug sink (process-wide)."""
    global _enabled
    _enabled = enabled


def debug_log(message: str) -> None:
    """Emit one NON-PII diagnostic line to stderr (no-op unless enabled)."""
    if _enabled:
        sys.stderr.write(f"[hsync-bootnode][debug] {message}\n")
        sys.stderr.flush()
