"""Black-box lifecycle tests: CLI surface, fail-fast config, readiness, shutdown.

Every scenario drives the real bootnode binary (``HSYNC_BOOTNODE_BIN``) and
observes only public behaviour: exit codes, stderr, the readiness PID file and
the wire protocol.
"""

from __future__ import annotations

import re

import pytest
from harness import query_frame, register_frame, run_cli

# Any diagnostic line: "2026-09-30T10:30:45.123Z - hsync-bootnode[1234] warn: …".
_LINE_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z"
    r" - hsync-bootnode\[\d+\] (debug|warn|error): .+"
)
_DEBUG_LINE_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z"
    r" - hsync-bootnode\[\d+\] debug: .+"
)


def test_version_flag_prints_protocol_and_impl() -> None:
    result = run_cli(["--version"])
    assert result.returncode == 0
    assert "boot/1" in result.stdout
    assert "hsync-bootnode" in result.stdout


def test_protected_bucket_without_key_fails_fast() -> None:
    result = run_cli(["run", "--protected-bucket", "shared"])
    assert result.returncode == 2
    assert "configuration error" in result.stderr


def test_startup_with_protected_bucket_and_keys_serves(bootnode_factory, bucket, group_key) -> None:
    handle = bootnode_factory(protected=[bucket], keys={bucket: group_key})
    assert handle.proc.poll() is None
    assert handle.ready_file is not None
    # The ready file reports the application PID, which for a onefile-packaged
    # binary is the launcher's child, not the launcher process itself.
    assert handle.ready_file.read_text().strip().isdigit()
    assert handle.node_pid is not None


@pytest.mark.asyncio
async def test_ready_file_removed_on_graceful_sigterm(bootnode_factory) -> None:
    handle = bootnode_factory()
    ready_file = handle.ready_file
    assert ready_file is not None and ready_file.read_text().strip().isdigit()

    handle.proc.terminate()
    handle.proc.wait(timeout=15)
    assert handle.proc.returncode == 0
    assert not ready_file.exists()


@pytest.mark.asyncio
async def test_debug_mode_emits_the_full_operation_log(bootnode_factory, bucket, rng) -> None:
    """``--debug`` follows the whole request life cycle, peer identity included."""
    from harness import BootClient, random_cid

    handle = bootnode_factory(debug=True)
    cid = random_cid(rng)
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))
        await client.exchange(query_frame(bucket))

    stderr = handle.stderr_text()
    debug_lines = [line for line in stderr.splitlines() if " debug: " in line]
    assert debug_lines, stderr
    # Each line is a timestamped, self-identifying record: the operator who
    # dumps this stderr must be able to order and attribute every event.
    unmatched = [line for line in debug_lines if not _DEBUG_LINE_RE.fullmatch(line)]
    assert not unmatched, unmatched
    assert "register ack" in stderr
    assert "query response" in stderr
    # The operator opted in: the log must say WHO connected and what happened.
    assert cid in stderr
    assert f"bucket={bucket}" in stderr
    # Opting in is announced on the always-on channel (transparency), and that
    # announcement itself stays peer-free.
    assert "warn: peer data logging enabled reason=--debug" in stderr
    announcement = next(line for line in stderr.splitlines() if "warn:" in line)
    assert cid not in announcement
    assert bucket not in announcement


@pytest.mark.asyncio
async def test_default_mode_keeps_peer_data_out_of_stderr(bootnode_factory, bucket, rng) -> None:
    """Without ``--debug`` nothing peer-related leaves memory."""
    from harness import BootClient, random_cid

    handle = bootnode_factory()
    cid = random_cid(rng)
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))

    stderr = handle.stderr_text()
    assert not [line for line in stderr.splitlines() if _DEBUG_LINE_RE.fullmatch(line)]
    assert cid not in stderr
    assert bucket not in stderr
    # A healthy default run is silent: this suite always starts the node with
    # --no-upnp, so no operational warning is expected either.
    assert not [line for line in stderr.splitlines() if _LINE_RE.fullmatch(line)]


def test_ready_file_failure_exits_4_without_a_traceback(tmp_path) -> None:
    """The readiness seam fails actionably (exit 4) and is reported on stderr."""
    from harness import free_udp_port

    missing = tmp_path / "missing-dir" / "ready.pid"
    result = run_cli(
        [
            "run",
            "--host",
            "127.0.0.1",
            "--port",
            str(free_udp_port()),
            "--no-upnp",
            "--ready-file",
            str(missing),
        ]
    )
    assert result.returncode == 4
    assert "no such directory" in result.stderr
    assert "Traceback" not in result.stderr
    # The always-on diagnostics channel carries it too, peer-free.
    assert "error: readiness file not writable" in result.stderr
    assert f"path={missing}" in result.stderr


def test_port_in_use_fails_fast_with_actionable_error() -> None:
    """A bind failure reports exit code 3 + an actionable message, no traceback."""
    import socket

    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        holder.bind(("127.0.0.1", 0))
        port = int(holder.getsockname()[1])

        # Guard: if the OS lets a second plain bind succeed (SO_REUSEPORT
        # defaults), the node would start and this scenario cannot be reproduced.
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            probe.close()
        else:
            probe.close()
            pytest.skip("UDP SO_REUSEPORT allows a second bind; cannot reproduce")

        result = run_cli(["run", "--host", "127.0.0.1", "--port", str(port)])
        assert result.returncode == 3
        assert "cannot bind" in result.stderr
        assert "already in use" in result.stderr
        assert "Traceback" not in result.stderr
    finally:
        holder.close()
