"""CLI smoke tests: version output, fail-fast configuration, keys-fd loading."""

from __future__ import annotations

import errno
import os

from typer.testing import CliRunner

from hsync_bootnode.cli import _load_keys, _remove_ready_file, _write_ready_file, app

runner = CliRunner()


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "boot/1" in result.output
    assert "hsync-bootnode" in result.output


def test_protected_bucket_without_key_fails_fast() -> None:
    result = runner.invoke(app, ["run", "--protected-bucket", "shared"])
    assert result.exit_code == 2
    combined = result.output + getattr(result, "stderr", "") or result.output
    assert "configuration error" in combined
    assert "protected bucket(s) without a group key" in combined


def test_load_keys_from_fd() -> None:
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"shared=abc123\n# operator comment\nhome=def456\n")
    os.close(write_fd)
    try:
        keys = _load_keys(read_fd)
    finally:
        os.close(read_fd)
    assert set(keys) == {"shared", "home"}
    assert keys["shared"].get_secret_value() == "abc123"
    assert keys["home"].get_secret_value() == "def456"


def test_load_keys_ignores_blank_and_comments() -> None:
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"\n# only a comment\n")
    os.close(write_fd)
    try:
        keys = _load_keys(read_fd)
    finally:
        os.close(read_fd)
    assert keys == {}

    # None / negative fd → empty mapping (no crash)
    assert _load_keys(None) == {}
    assert _load_keys(-1) == {}


def test_ttl_out_of_range_is_rejected() -> None:
    for bad in ("0", "-1", "3601"):
        result = runner.invoke(app, ["run", "--ttl", bad])
        assert result.exit_code == 2


def test_private_without_key_fails_fast() -> None:
    result = runner.invoke(app, ["run", "--private"])
    assert result.exit_code == 2
    assert "private node without any group key" in result.output


def test_private_envvar_is_equivalent_to_the_flag() -> None:
    """The service units use the envvar form; it must reach the same fail-fast."""
    result = runner.invoke(app, ["run"], env={"HSYNC_BOOTNODE_PRIVATE": "1"})
    assert result.exit_code == 2
    assert "private node without any group key" in result.output


def test_private_option_is_documented_in_help() -> None:
    result = runner.invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    assert "--private" in result.output
    assert "HSYNC_BOOTNODE_PRIVATE" in result.output


def test_ready_file_helpers_write_pid_and_remove(tmp_path) -> None:
    ready = tmp_path / "ready"
    _write_ready_file(str(ready))
    assert ready.read_text(encoding="utf-8").strip() == str(os.getpid())
    _remove_ready_file(str(ready))
    assert not ready.exists()
    # removing a missing file is a no-op, not an error
    _remove_ready_file(str(ready))


def _combined(result) -> str:
    return result.output + getattr(result, "stderr", "") or result.output


def _patch_run_no_side_effects(monkeypatch, start_server) -> None:
    """Stub the listener start and the two process-global installers.

    ``run`` reaches ``_install_uvloop``/``_install_sigterm_handler`` before the
    bind; stubbing them keeps the test process free of a global event-loop policy
    swap and a SIGTERM handler.
    """
    monkeypatch.setattr("hsync_bootnode.cli.start_server", start_server)
    monkeypatch.setattr("hsync_bootnode.cli._install_uvloop", lambda: None)
    monkeypatch.setattr("hsync_bootnode.cli._install_sigterm_handler", lambda: None)


def test_bind_permission_denied_is_actionable(monkeypatch) -> None:
    async def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        # aioquic wraps the real error: no errno on the outer OSError.
        raise OSError("could not bind to local_addr ('0.0.0.0', 443)") from PermissionError(
            errno.EACCES, "Permission denied"
        )

    _patch_run_no_side_effects(monkeypatch, _boom)
    result = runner.invoke(app, ["run", "--port", "443"])
    assert result.exit_code == 3
    out = _combined(result)
    assert "permission denied" in out
    assert "CAP_NET_BIND_SERVICE" in out
    assert "--port 8443" in out
    assert "Traceback" not in out


def test_bind_address_in_use_is_actionable(monkeypatch) -> None:
    async def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise OSError(errno.EADDRINUSE, "Address already in use")

    _patch_run_no_side_effects(monkeypatch, _boom)
    result = runner.invoke(app, ["run", "--port", "443"])
    assert result.exit_code == 3
    out = _combined(result)
    assert "already in use" in out
    assert "--port <PORT>" in out
    assert "Traceback" not in out


def test_bind_bad_host_is_actionable(monkeypatch) -> None:
    async def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise OSError(errno.EADDRNOTAVAIL, "Cannot assign requested address")

    _patch_run_no_side_effects(monkeypatch, _boom)
    result = runner.invoke(app, ["run", "--host", "127.0.0.1", "--port", "443"])
    assert result.exit_code == 3
    out = _combined(result)
    assert "not available" in out
    assert "--host" in out
    assert "0.0.0.0" in out


def test_run_port_default_uses_the_shared_ssot() -> None:
    """The CLI ``--port`` default is the shared ``BOOT_DEFAULT_PORT`` (spec §Transport)."""
    from hsync_common.constants import BOOT_DEFAULT_PORT
    from typer.main import get_command

    run_command = get_command(app).commands["run"]
    port_default = next(param.default for param in run_command.params if param.name == "port")
    assert port_default == BOOT_DEFAULT_PORT == 443
