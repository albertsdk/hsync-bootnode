"""Black-box lifecycle tests: CLI surface, fail-fast config, readiness, shutdown.

Every scenario drives the real bootnode binary (``HSYNC_BOOTNODE_BIN``) and
observes only public behaviour: exit codes, stderr, the readiness PID file and
the wire protocol.
"""

from __future__ import annotations

import pytest
from harness import register_frame, run_cli


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
async def test_debug_mode_emits_non_pii_stderr(bootnode_factory, bucket, rng) -> None:
    from harness import BootClient, random_cid

    handle = bootnode_factory(debug=True)
    cid = random_cid(rng)
    async with BootClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))

    stderr = handle.stderr_text()
    assert "[hsync-bootnode][debug]" in stderr
    assert "register ack" in stderr
    # non-PII: the peer's CID must never appear in diagnostics
    assert cid not in stderr
