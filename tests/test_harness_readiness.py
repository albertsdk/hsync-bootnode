"""Readiness-contract tests for the black-box harness (packaging-neutral).

A onefile-packaged binary (PyInstaller ``--onefile``) runs the bootnode in a
child process, so the PID written to ``HSYNC_BOOTNODE_READY_FILE`` differs from
the launcher PID that ``subprocess.Popen`` reports. ``wait_ready`` must accept
that: readiness is signalled by the *application*, not by the packaging launcher.
These tests exercise the harness contract without spawning the real binary.
"""

from __future__ import annotations

import subprocess
import sys

import pytest
from harness import wait_ready


class _FakeHandle:
    """Minimal stand-in exposing the attributes ``wait_ready`` relies on."""

    def __init__(self, proc: subprocess.Popen, ready_file) -> None:
        self.proc = proc
        self.ready_file = ready_file
        self.node_pid: int | None = None

    def stderr_text(self) -> str:
        return ""


def _idle_proc() -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])


def test_wait_ready_accepts_app_pid_different_from_launcher(tmp_path) -> None:
    """Readiness must not require the ready PID to equal the launcher PID."""
    proc = _idle_proc()
    try:
        ready = tmp_path / "ready.pid"
        # Emulate a onefile launcher: the app writes its own (child) PID.
        ready.write_text(str(proc.pid + 1), encoding="utf-8")
        handle = _FakeHandle(proc, ready)
        wait_ready(handle, timeout=2.0)
        assert handle.node_pid == proc.pid + 1
    finally:
        proc.terminate()
        proc.wait()


def test_wait_ready_raises_on_early_exit(tmp_path) -> None:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    handle = _FakeHandle(proc, tmp_path / "ready.pid")
    with pytest.raises(RuntimeError):
        wait_ready(handle, timeout=2.0)


def test_wait_ready_raises_on_timeout(tmp_path) -> None:
    proc = _idle_proc()
    try:
        handle = _FakeHandle(proc, tmp_path / "ready.pid")
        with pytest.raises(TimeoutError):
            wait_ready(handle, timeout=0.5)
    finally:
        proc.terminate()
        proc.wait()
