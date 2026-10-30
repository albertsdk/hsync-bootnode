"""Pytest fixtures for the language-neutral rendezvous black-box suite.

Every test in this directory is gated by ``HSYNC_BB_RENDEZVOUS=1`` and must keep
the isolation contract: a fresh subprocess per test, scrubbed environment, and
teardown that never leaves an orphan process behind.
"""

from __future__ import annotations

import os
import random

import pytest
from harness import (
    random_bucket,
    start_rendezvous,
    terminate,
)

_BB_REASON = "rendezvous black-box tests require HSYNC_BB_RENDEZVOUS=1"


@pytest.fixture(autouse=True)
def _require_black_box() -> None:
    if os.environ.get("HSYNC_BB_RENDEZVOUS") != "1":
        pytest.skip(_BB_REASON)


@pytest.fixture
def rng(request: pytest.FixtureRequest) -> random.Random:
    """Per-test RNG with a logged seed for reproducible failures."""
    seed = int.from_bytes(os.urandom(8), "big")
    request.node.user_properties.append(("seed", seed))
    print(f"[seed] {seed}")
    return random.Random(seed)


@pytest.fixture
def bucket(rng: random.Random) -> str:
    """A fresh bucket name so each test starts from a clean namespace."""
    return random_bucket(rng)


@pytest.fixture
def group_key(rng: random.Random) -> str:
    """A random 64-hex-char group secret for protected-bucket tests."""
    return os.urandom(32).hex()


@pytest.fixture
def rendezvous_factory(tmp_path):
    """Factory returning a started ``RendezvousProc`` (terminated on teardown)."""
    handles = []

    def _start(**kwargs):
        handle = start_rendezvous(tmp_path, **kwargs)
        handles.append(handle)
        return handle

    yield _start
    for handle in handles:
        terminate(handle)
