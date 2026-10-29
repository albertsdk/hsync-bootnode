"""Black-box lifecycle tests: CLI surface, fail-fast config, readiness, shutdown.

Every scenario drives the real bootnode binary (``HSYNC_BOOTNODE_BIN``) and
observes only public behaviour: exit codes, stderr, the readiness PID file and
the wire protocol.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import signal
import socket
import time

import pytest
from harness import query_frame, register_frame, run_cli

# Any diagnostic line: "2026-09-30T10:30:45.123Z - hsync-bootnode[1234] warn: …".
_LINE_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z"
    r" - hsync-bootnode\[\d+\] (debug|warn|error): .+"
)


def _collect_notifications(
    sock: socket.socket, wanted: set[str], timeout: float = 10.0
) -> set[str]:
    """Read sd_notify datagrams until every payload in *wanted* has arrived."""
    seen: set[str] = set()
    deadline = time.monotonic() + timeout
    while not wanted <= seen and time.monotonic() < deadline:
        try:
            seen.add(sock.recv(4096).decode("utf-8"))
        except TimeoutError:
            continue
    return seen


_DEBUG_LINE_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z"
    r" - hsync-bootnode\[\d+\] debug: .+"
)


def test_version_flag_prints_protocol_and_impl() -> None:
    # When: --version is run
    result = run_cli(["--version"])
    # Then: the protocol and implementation name are printed
    assert result.returncode == 0
    assert "boot/1" in result.stdout
    assert "hsync-bootnode" in result.stdout


def test_protected_bucket_without_key_fails_fast() -> None:
    # When: --protected-bucket is set with no group key
    result = run_cli(["run", "--protected-bucket", "shared"])
    # Then: fail-fast configuration error (exit 2)
    assert result.returncode == 2
    assert "configuration error" in result.stderr


def test_startup_with_protected_bucket_and_keys_serves(bootnode_factory, bucket, group_key) -> None:
    # Given: a protected bucket with a provisioned group key
    handle = bootnode_factory(protected=[bucket], keys={bucket: group_key})
    # Then: the node is up and the ready file holds the application PID
    assert handle.proc.poll() is None
    assert handle.ready_file is not None
    # The ready file reports the application PID, which for a onefile-packaged
    # binary is the launcher's child, not the launcher process itself.
    assert handle.ready_file.read_text().strip().isdigit()
    assert handle.node_pid is not None


@pytest.mark.asyncio
async def test_ready_file_removed_on_graceful_sigterm(bootnode_factory) -> None:
    # Given: a running node with a ready file
    handle = bootnode_factory()
    ready_file = handle.ready_file
    assert ready_file is not None and ready_file.read_text().strip().isdigit()

    # When: SIGTERM is delivered
    handle.proc.terminate()
    handle.proc.wait(timeout=15)
    # Then: clean exit (0) and the ready file is removed
    assert handle.proc.returncode == 0
    assert not ready_file.exists()


@pytest.mark.asyncio
async def test_debug_mode_emits_the_full_operation_log(bootnode_factory, bucket, rng) -> None:
    """``--debug`` follows the whole request life cycle, peer identity included."""
    from harness import BootClient, random_cid

    # Given: a node started with --debug
    handle = bootnode_factory(debug=True)
    cid = random_cid(rng)
    # When: a register + query are sent
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))
        await client.exchange(query_frame(bucket))

    # Then: the debug log records the full request life cycle, peer identity
    #       included, and announces the opt-in peer-free
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

    # Given: a node started without --debug
    handle = bootnode_factory()
    cid = random_cid(rng)
    # When: a register is sent
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))

    # Then: nothing peer-related reaches stderr
    stderr = handle.stderr_text()
    assert not [line for line in stderr.splitlines() if _DEBUG_LINE_RE.fullmatch(line)]
    assert cid not in stderr
    assert bucket not in stderr
    # A healthy default run is silent: UPnP is off by default, so no
    # operational warning is expected either.
    assert not [line for line in stderr.splitlines() if _LINE_RE.fullmatch(line)]


def test_ready_file_failure_exits_4_without_a_traceback(tmp_path) -> None:
    """The readiness seam fails actionably (exit 4) and is reported on stderr."""
    from harness import free_udp_port

    # Given: a --ready-file path in a missing directory
    missing = tmp_path / "missing-dir" / "ready.pid"
    # When: the node starts
    result = run_cli(
        [
            "run",
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            str(free_udp_port()),
            "--ready-file",
            str(missing),
        ]
    )
    # Then: exit 4 with an actionable, traceback-free message
    assert result.returncode == 4
    assert "no such directory" in result.stderr
    assert "Traceback" not in result.stderr
    # The always-on diagnostics channel carries it too, peer-free.
    assert "error: readiness file not writable" in result.stderr
    assert f"path={missing}" in result.stderr


def test_port_in_use_fails_fast_with_actionable_error() -> None:
    """A bind failure reports exit code 3 + an actionable message, no traceback."""
    import socket

    # Given: a UDP socket already bound to a loopback port
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

        # When: the node tries to bind the same port
        result = run_cli(["run", "--listen-host", "127.0.0.1", "--listen-port", str(port)])
        # Then: exit 3 with an actionable, traceback-free message
        assert result.returncode == 3
        assert "cannot bind" in result.stderr
        assert "already in use" in result.stderr
        assert "Traceback" not in result.stderr
    finally:
        holder.close()


@pytest.mark.asyncio
async def test_sigterm_under_load_exits_cleanly(bootnode_factory, bucket, rng) -> None:
    """SIGTERM mid-traffic still runs the graceful teardown (exit 0, ready file removed)."""
    from harness import BootClient, random_cid

    # Given: a running node with a registered peer
    handle = bootnode_factory()
    ready_file = handle.ready_file
    assert ready_file is not None

    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(random_cid(rng), bucket))

        async def hammer() -> None:
            # Keep the event loop busy with valid traffic until the node stops.
            while True:
                try:
                    await client.exchange(query_frame(bucket), timeout=1.0)
                except Exception:  # noqa: BLE001 - the node shutting down ends the loop
                    return

        load = asyncio.create_task(hammer())
        await asyncio.sleep(0.1)  # let the load ramp before signalling

        # When: SIGTERM is delivered under sustained query load
        handle.proc.terminate()
        returncode = await asyncio.to_thread(handle.proc.wait, 15)
        load.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await load

    # Then: clean exit (0) and the ready file is removed
    assert returncode == 0
    assert not ready_file.exists()


@pytest.mark.asyncio
async def test_sigint_exits_cleanly_and_removes_ready_file(bootnode_factory) -> None:
    """Ctrl+C (SIGINT) follows the same graceful path as SIGTERM."""
    # Given: a running node with a ready file
    handle = bootnode_factory()
    ready_file = handle.ready_file
    assert ready_file is not None

    # When: SIGINT is delivered
    handle.proc.send_signal(signal.SIGINT)
    returncode = await asyncio.to_thread(handle.proc.wait, 15)

    # Then: clean exit (0) and the ready file is removed
    assert returncode == 0
    assert not ready_file.exists()


@pytest.mark.asyncio
async def test_ipv6_listener_serves(bootnode_factory, bucket, rng) -> None:
    """``--listen-host [::1]`` binds the IPv6 loopback and serves ``boot/1`` over it."""
    from harness import BootClient, random_cid

    # Given: IPv6 loopback is available
    if not socket.has_ipv6:
        pytest.skip("IPv6 unavailable on this host")
    probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        probe.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback unavailable on this host")
    finally:
        probe.close()

    # When: the node binds [::1] and serves a register
    handle = bootnode_factory(host="[::1]")
    async with BootClient(handle.port, host="::1") as client:
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    # Then: the register is served over IPv6
    assert ack["type"] == "ack"
    assert handle.proc.poll() is None


def test_upnp_flag_is_reported_and_serves(bootnode_factory, bucket, rng) -> None:
    """--upnp is reflected in the startup banner and the node still serves."""
    # Given: a node started with --upnp (no IGD on loopback)
    handle = bootnode_factory(args=["--upnp"])
    # Then: the banner reports UPnP enabled
    assert "upnp" in handle.stdout_text()
    assert "enabled" in handle.stdout_text()


@pytest.mark.asyncio
async def test_upnp_node_still_serves_boot(bootnode_factory, bucket, rng) -> None:
    """--upnp with no IGD must not block readiness or the wire."""
    from harness import BootClient, random_cid

    # Given: a node started with --upnp (no IGD on loopback)
    handle = bootnode_factory(args=["--upnp"])
    # When: a register is sent
    async with BootClient(handle.port) as client:
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    # Then: it is served normally
    assert ack["type"] == "ack"
    assert handle.proc.poll() is None


def test_invalid_ttl_fails_fast() -> None:
    """--ttl outside 1..3600 is a CLI usage error (exit 2), no node started."""
    # Given: the CLI bound (min=1, max=3600)
    # When: --ttl 0 and --ttl 3601 are passed
    for bad in ("0", "3601"):
        result = run_cli(["run", "--ttl", bad])
        # Then: both fail fast with exit 2
        assert result.returncode == 2


@pytest.mark.asyncio
async def test_sighup_does_not_stop_the_node(bootnode_factory, bucket, rng) -> None:
    """A hung-up terminal is not a stop request: the node keeps serving boot/1."""
    from harness import BootClient, random_cid

    if not hasattr(signal, "SIGHUP"):
        pytest.skip("SIGHUP unavailable on this platform")

    # Given: a running node
    handle = bootnode_factory()
    # When: SIGHUP is delivered (terminal closed, SSH session dropped)
    handle.proc.send_signal(signal.SIGHUP)
    await asyncio.sleep(0.2)
    # Then: it is still alive and answers a register
    assert handle.proc.poll() is None
    async with BootClient(handle.port) as client:
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_sd_notify_reports_ready_watchdog_and_stopping(bootnode_factory, tmp_path) -> None:
    """The service-manager contract: READY (+STATUS) on bind, WATCHDOG, STOPPING on stop."""
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("AF_UNIX unavailable on this platform")

    # Given: a notification socket standing in for the service manager, with the
    #        watchdog armed at 200 ms (the node feeds it every 100 ms)
    notify_path = tmp_path / "notify.sock"
    notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    notify.bind(str(notify_path))
    notify.settimeout(0.2)
    try:
        handle = bootnode_factory(
            env_extra={"NOTIFY_SOCKET": str(notify_path), "WATCHDOG_USEC": "200000"}
        )
        # Then: readiness (carrying the first STATUS) and the watchdog reach the manager
        seen = _collect_notifications(notify, {"WATCHDOG=1"})
        assert "WATCHDOG=1" in seen, seen
        ready = [payload for payload in seen if payload.startswith("READY=1")]
        assert ready, seen
        assert "STATUS=conn=" in ready[0], ready[0]

        # When: the service manager stops the node
        handle.proc.terminate()
        await asyncio.to_thread(handle.proc.wait, 15)
        # Then: the teardown is announced, so no restart is inferred from the drop
        assert "STOPPING=1" in _collect_notifications(notify, {"STOPPING=1"}, timeout=5.0)
    finally:
        notify.close()
