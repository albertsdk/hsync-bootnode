# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Alberto Basso

"""Tests for the host-resource detection that sizes the in-memory ceilings."""

from __future__ import annotations

import dataclasses

from hsync_bootnode.resources import (
    ResourceLimits,
    available_memory_bytes,
    cpu_count,
    total_memory_bytes,
)


def test_memory_and_cpu_detection_are_sane() -> None:
    assert total_memory_bytes() > 0
    assert available_memory_bytes() > 0
    assert available_memory_bytes() <= total_memory_bytes() * 2  # cgroup cap may differ
    assert cpu_count() >= 1


def test_detect_returns_positive_bounded_ceilings() -> None:
    limits = ResourceLimits.detect()
    assert limits.max_peer_records > 0
    assert limits.max_limiter_keys > 0
    assert limits.max_active_connections > 0
    assert 1 <= limits.max_active_connections_per_ip <= limits.max_active_connections
    assert 1 <= limits.max_records_per_group <= limits.max_peer_records


def test_detect_clamps_a_tiny_host_to_a_usable_floor() -> None:
    """A pathological host still yields usable (not zero) ceilings."""
    from unittest.mock import patch

    with patch("hsync_bootnode.resources.available_memory_bytes", return_value=1):
        limits = ResourceLimits.detect()
    assert limits.max_peer_records >= 4_096
    assert limits.max_limiter_keys >= 4_096
    assert limits.max_active_connections >= 64
    assert limits.max_active_connections_per_ip >= 16
    assert limits.max_records_per_group >= 128


def test_ceilings_are_exposed_as_a_flat_mapping() -> None:
    limits = ResourceLimits(
        max_peer_records=1,
        max_limiter_keys=2,
        max_active_connections=3,
        max_active_connections_per_ip=4,
        max_records_per_group=5,
    )
    assert dataclasses.asdict(limits) == {
        "max_peer_records": 1,
        "max_limiter_keys": 2,
        "max_active_connections": 3,
        "max_active_connections_per_ip": 4,
        "max_records_per_group": 5,
    }


def test_available_memory_is_capped_by_the_process_cgroup_limit() -> None:
    """The process's own (nested) cgroup limit bounds the detected memory."""
    from unittest.mock import patch

    cap = 64 * 1024 * 1024
    with patch("hsync_bootnode.resources._process_cgroup_limit_bytes", return_value=cap):
        assert available_memory_bytes() <= cap
