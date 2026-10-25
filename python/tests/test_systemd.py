"""``sd_notify`` signalling: readiness, watchdog feed and teardown announcement.

The packaged units run the node as ``Type=notify`` with ``WatchdogSec=``, so these
calls are the contract with the service manager: READY only once the listeners
are bound, WATCHDOG at half the armed interval, STOPPING before the transports
close. Outside systemd (``$NOTIFY_SOCKET`` unset) every call must be inert and
must never raise: the same binary runs in a container, under launchd, on Windows
and in the foreground.
"""

from __future__ import annotations

import os
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from hsync_bootnode.systemd import (
    notify_available,
    notify_ready,
    notify_status,
    notify_stopping,
    notify_watchdog,
    watchdog_interval,
)

pytestmark = pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="AF_UNIX unavailable")


@pytest.fixture
def notify_socket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[socket.socket]:
    """A bound AF_UNIX datagram socket advertised through ``$NOTIFY_SOCKET``."""
    path = tmp_path / "notify.sock"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(str(path))
    sock.settimeout(2.0)
    monkeypatch.setenv("NOTIFY_SOCKET", str(path))
    monkeypatch.delenv("WATCHDOG_USEC", raising=False)
    monkeypatch.delenv("WATCHDOG_PID", raising=False)
    try:
        yield sock
    finally:
        sock.close()


def _recv(sock: socket.socket) -> str:
    return sock.recv(4096).decode("utf-8")


def test_ready_stopping_and_watchdog_are_delivered(notify_socket: socket.socket) -> None:
    # When: each state is announced
    assert notify_ready() is True
    assert notify_watchdog() is True
    assert notify_stopping() is True
    # Then: the service manager receives them in order, verbatim
    assert [_recv(notify_socket) for _ in range(3)] == ["READY=1", "WATCHDOG=1", "STOPPING=1"]


def test_without_a_service_manager_every_call_is_inert(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given: no NOTIFY_SOCKET (container, launchd, Windows, foreground run)
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    # Then: the calls report "not delivered" and never raise
    assert notify_ready() is False
    assert notify_watchdog() is False
    assert notify_stopping() is False


def test_an_unreachable_socket_never_raises(tmp_path: Path, monkeypatch) -> None:
    """A manager that stopped must not be able to disturb the node."""
    monkeypatch.setenv("NOTIFY_SOCKET", str(tmp_path / "gone.sock"))
    assert notify_ready() is False


def test_the_abstract_namespace_is_supported(monkeypatch) -> None:
    """systemd reports an abstract address as ``@name``; nothing may raise on it."""
    monkeypatch.setenv("NOTIFY_SOCKET", "@hsync-bootnode-does-not-exist")
    assert notify_ready() is False


def test_watchdog_interval_is_half_of_the_armed_timeout(monkeypatch) -> None:
    monkeypatch.setenv("WATCHDOG_USEC", "60000000")
    monkeypatch.delenv("WATCHDOG_PID", raising=False)
    assert watchdog_interval() == 30.0


def test_watchdog_interval_accepts_its_own_pid(monkeypatch) -> None:
    monkeypatch.setenv("WATCHDOG_USEC", "2000000")
    monkeypatch.setenv("WATCHDOG_PID", str(os.getpid()))
    assert watchdog_interval() == 1.0


def test_watchdog_interval_refuses_another_process(monkeypatch) -> None:
    """A ping addressed to a different process is not ours to send."""
    monkeypatch.setenv("WATCHDOG_USEC", "2000000")
    monkeypatch.setenv("WATCHDOG_PID", str(os.getpid() + 1))
    assert watchdog_interval() is None


@pytest.mark.parametrize("raw", [None, "", "0", "-1", "not-a-number"])
def test_watchdog_interval_requires_a_positive_number(monkeypatch, raw: str | None) -> None:
    if raw is None:
        monkeypatch.delenv("WATCHDOG_USEC", raising=False)
    else:
        monkeypatch.setenv("WATCHDOG_USEC", raw)
    assert watchdog_interval() is None


def test_status_is_delivered_as_a_single_line(notify_socket: socket.socket) -> None:
    assert notify_status("conn=1/2\npeers=3/4") is True
    assert _recv(notify_socket) == "STATUS=conn=1/2 peers=3/4"


def test_ready_carries_the_first_status_when_given(notify_socket: socket.socket) -> None:
    assert notify_ready("conn=0/0 peers=0/0") is True
    assert _recv(notify_socket) == "READY=1\nSTATUS=conn=0/0 peers=0/0"


def test_ready_without_a_status_is_the_plain_assignment(notify_socket: socket.socket) -> None:
    assert notify_ready() is True
    assert _recv(notify_socket) == "READY=1"


def test_a_long_status_is_bounded(notify_socket: socket.socket) -> None:
    notify_status("x" * 500)
    payload = _recv(notify_socket)
    assert payload.startswith("STATUS=")
    assert len(payload) <= len("STATUS=") + 200
    assert "\n" not in payload


def test_notify_available_tracks_the_socket(monkeypatch) -> None:
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    assert notify_available() is False
    monkeypatch.setenv("NOTIFY_SOCKET", "/run/systemd/notify")
    assert notify_available() is True
