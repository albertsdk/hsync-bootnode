"""Diagnostics tests: the always-on operational channel and the opt-in debug log.

Without ``--debug`` the peer-aware stream is silent (peer data stays in memory
only); ``warn_event``/``error_event`` are always emitted but can only carry
non-identifying fields. Every line carries the timestamp and the emitting pid
(``timestamp - hsync-bootnode[pid] <level>: …``), so the stream can be correlated
with the other HSYNC components.
"""

from __future__ import annotations

import json
import os
import re
from collections import deque
from datetime import datetime

import pytest

from hsync_bootnode import diagnostics
from hsync_bootnode.diagnostics import (
    configure_debug,
    debug_enabled,
    debug_event,
    debug_log,
    error_event,
    warn_event,
)
from hsync_bootnode.handler import BootHandler

CID = "A1b2C3d4E5f6G7h8I9j0K"
FP = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"

# "2026-09-30T10:30:45.123Z - hsync-bootnode[1234] <level>: <body>"
_LINE_RE = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)"
    r" - hsync-bootnode\[(?P<pid>\d+)\] (?P<level>debug|warn|error): (?P<body>.+)\n"
)


def _lines(stderr: str) -> list[re.Match[str]]:
    """Parse every stderr line, asserting the documented diagnostic format."""
    parsed: list[re.Match[str]] = []
    for line in stderr.splitlines(keepends=True):
        match = _LINE_RE.fullmatch(line)
        assert match is not None, f"unexpected stderr line: {line!r}"
        parsed.append(match)
    assert parsed, "expected at least one diagnostic line"
    return parsed


@pytest.fixture(autouse=True)
def _restore_sink(monkeypatch):
    """Never leak the enabled state (or a dedup window) into another test."""
    configure_debug(False)
    monkeypatch.setattr(diagnostics, "_dedup", {})
    monkeypatch.setattr(diagnostics, "_dedup_order", deque())
    yield
    configure_debug(False)


def _register(cid: str = CID, bucket: str = "shared") -> bytes:
    return json.dumps(
        {
            "protocol_version": "boot/1",
            "type": "register",
            "cid": cid,
            "bucket": bucket,
            "cert_fp": FP,
            "version": "1.0.0",
            "capacity": 5,
            "endpoints": [{"proto": "tcp", "host": "198.51.100.7", "port": 8443}],
        }
    ).encode()


class TestDebugSink:
    def test_disabled_by_default_and_silent(self, capsys):
        assert debug_enabled() is False
        debug_log("hello")
        debug_event("event", cid=CID)
        assert capsys.readouterr().err == ""

    def test_enabled_renders_structured_fields(self, capsys):
        configure_debug(True)
        assert debug_enabled() is True
        debug_event("register ack", cid=CID, bucket="shared", reachable=True, group=None)
        err = capsys.readouterr().err
        (line,) = _lines(err)
        assert line["level"] == "debug"
        assert line["pid"] == str(os.getpid())
        body = line["body"]
        assert body.startswith("register ack ")
        assert f"cid={CID}" in body
        assert "bucket=shared" in body
        assert "reachable=True" in body
        assert "group=" not in body  # None fields are omitted

    def test_free_form_line_carries_timestamp_and_pid(self, capsys):
        configure_debug(True)
        debug_log("listener bound 0.0.0.0:443 (retry+address-validation)")
        (line,) = _lines(capsys.readouterr().err)
        # The timestamp is the hsync-common ISO-8601 UTC form, parseable as such.
        assert datetime.strptime(line["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
        assert line["pid"] == str(os.getpid())
        assert line["body"] == "listener bound 0.0.0.0:443 (retry+address-validation)"

    def test_each_event_gets_its_own_timestamped_line(self, capsys):
        configure_debug(True)
        debug_event("request", seq=1)
        debug_event("request", seq=2)
        first, second = _lines(capsys.readouterr().err)
        assert first["body"] == "request seq=1"
        assert second["body"] == "request seq=2"
        # Time-ordered stream: never goes backwards, even within the same ms.
        assert first["timestamp"] <= second["timestamp"]


class TestAlwaysOnChannel:
    """``warn``/``error`` are visible without ``--debug`` and never carry peer data."""

    def test_emitted_without_debug_opt_in(self, capsys):
        assert debug_enabled() is False
        warn_event("upnp no igd on lan", port=443)
        error_event("session failed", exc="ValueError")
        warn_line, error_line = _lines(capsys.readouterr().err)
        assert warn_line["level"] == "warn"
        assert warn_line["body"] == "upnp no igd on lan port=443"
        assert error_line["level"] == "error"
        assert error_line["body"] == "session failed exc=ValueError"

    def test_peer_identifying_fields_are_refused(self, capsys):
        for key in ("peer", "cid", "bucket", "host", "endpoint", "group"):
            with pytest.raises(ValueError, match="not allowed on the always-on channel"):
                warn_event("event", **{key: "x"})
            with pytest.raises(ValueError, match="not allowed on the always-on channel"):
                error_event("event", **{key: "x"})
        assert capsys.readouterr().err == ""  # nothing emitted before raising

    def test_optionally_absent_fields_are_omitted(self, capsys):
        warn_event("event", reason=None, port=1)
        (line,) = _lines(capsys.readouterr().err)
        assert line["body"] == "event port=1"

    def test_a_value_cannot_forge_a_second_line(self, capsys):
        warn_event(
            "event",
            reason="boom\n2020-01-01T00:00:00.000Z - hsync-bootnode[1] error: fake",
        )
        (line,) = _lines(capsys.readouterr().err)
        assert line["level"] == "warn"
        assert "\n" not in line["body"]
        assert "2020-01-01T00:00:00.000Z" in line["body"]  # neutralized, not dropped

    def test_an_event_name_cannot_forge_a_second_line(self, capsys):
        debug_event("fake\nerror: forged")
        debug_log("also\nforged")
        assert capsys.readouterr().err == ""  # debug is off: nothing at all

        configure_debug(True)
        debug_event("fake\nerror: forged")
        debug_log("also\nforged")
        first, second = _lines(capsys.readouterr().err)
        assert first["level"] == "debug"
        assert "\n" not in first["body"]
        assert "\n" not in second["body"]

    def test_a_value_is_bounded(self, capsys):
        warn_event("event", reason="x" * 1000)
        (line,) = _lines(capsys.readouterr().err)
        assert len(line["body"]) < 300


class TestErrorThrottle:
    """A repeated failure must not flood the operator's log (OWASP: availability)."""

    def test_repeats_collapse_and_report_the_count(self, capsys, monkeypatch):
        for _ in range(5):
            error_event("session failed", exc="ValueError")
        (first,) = _lines(capsys.readouterr().err)
        assert first["body"] == "session failed exc=ValueError"

        # Expire the window: the next occurrence closes the burst.
        monkeypatch.setattr(diagnostics, "_DEDUP_WINDOW_SECONDS", 0.0)
        error_event("session failed", exc="ValueError")
        (next_line,) = _lines(capsys.readouterr().err)
        assert next_line["body"] == "session failed exc=ValueError suppressed=4"

    def test_distinct_errors_are_not_throttled(self, capsys):
        error_event("session failed", exc="ValueError")
        error_event("session failed", exc="OSError")
        first, second = _lines(capsys.readouterr().err)
        assert first["body"] == "session failed exc=ValueError"
        assert second["body"] == "session failed exc=OSError"

    def test_warnings_are_never_throttled(self, capsys):
        warn_event("upnp no igd on lan", port=443)
        warn_event("upnp no igd on lan", port=443)
        assert len(_lines(capsys.readouterr().err)) == 2

    def test_dedup_state_is_bounded(self, monkeypatch):
        monkeypatch.setattr(diagnostics, "_DEDUP_MAX_KEYS", 4)
        for i in range(20):
            error_event("event", port=i)
        # Steady state is the cap plus the key currently being recorded.
        assert len(diagnostics._dedup) <= diagnostics._DEDUP_MAX_KEYS + 1
        assert len(diagnostics._dedup_order) <= diagnostics._DEDUP_MAX_KEYS + 1


class TestHandlerOperationLog:
    def test_verbose_log_names_the_peer_only_when_enabled(self, capsys):
        handler = BootHandler()
        handler.handle(_register(), peer_ip="203.0.113.9", peer_port=51000)
        assert capsys.readouterr().err == ""

        configure_debug(True)
        handler.handle(_register(), peer_ip="203.0.113.9", peer_port=51000)
        err = capsys.readouterr().err
        assert f"cid={CID}" in err
        assert "peer=203.0.113.9:51000" in err
        assert "register ack" in err
        assert "reachable=True" in err

    def test_verbose_log_covers_refusals_and_drops(self, capsys):
        handler = BootHandler()
        configure_debug(True)
        # unknown frame type: silently dropped, but visible in the debug log
        handler.handle(
            b'{"protocol_version":"boot/1","type":"bogus"}', peer_ip="1.2.3.4", peer_port=1
        )
        handler.handle(b"not-json", peer_ip="1.2.3.4", peer_port=1)
        err = capsys.readouterr().err
        assert "drop invalid-frame" in err
        assert "peer=1.2.3.4:1" in err
