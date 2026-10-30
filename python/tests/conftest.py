# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Alberto Basso

"""White-box test isolation for process-global diagnostic state.

``configure_debug`` flips a process-wide stderr sink and the always-on error
channel keeps a dedup window in module globals. Both outlive a single test and a
single module: a CLI test that enables ``--debug`` (or any test that emits an
error-bearing line) would otherwise leak into a later test — e.g. a server test
asserting its always-on line is "peer-free" would suddenly see the peer-aware
debug line of the leaked sink.

Reset to the documented default (sink off, empty dedup history) before and after
every test so each starts from a clean process state regardless of execution
order.
"""

from __future__ import annotations

import pytest

from hsync_rendezvous import diagnostics


def _reset_diagnostics() -> None:
    diagnostics.configure_debug(False)
    diagnostics._dedup.clear()
    diagnostics._dedup_order.clear()


@pytest.fixture(autouse=True)
def _isolate_diagnostics() -> None:
    _reset_diagnostics()
    yield
    _reset_diagnostics()
