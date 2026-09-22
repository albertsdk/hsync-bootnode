"""Debug-sink tests: the full operation log is opt-in and peer-aware.

Without ``--debug`` the sink is silent (peer data stays in memory only); with it
enabled every operation is emitted, including the peer identity that makes the
log usable for analysis.
"""

from __future__ import annotations

import json

import pytest

from hsync_bootnode.debug import configure_debug, debug_enabled, debug_event, debug_log
from hsync_bootnode.handler import BootHandler

CID = "A1b2C3d4E5f6G7h8I9j0K"
FP = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"


@pytest.fixture(autouse=True)
def _restore_sink():
    """Never leak the enabled state into another test."""
    configure_debug(False)
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
        assert err.startswith("[hsync-bootnode][debug] register ack ")
        assert f"cid={CID}" in err
        assert "bucket=shared" in err
        assert "reachable=True" in err
        assert "group=" not in err  # None fields are omitted


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
