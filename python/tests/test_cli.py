"""CLI smoke tests: version output, fail-fast configuration, keys-fd loading."""

from __future__ import annotations

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


def test_ready_file_helpers_write_pid_and_remove(tmp_path) -> None:
    ready = tmp_path / "ready"
    _write_ready_file(str(ready))
    assert ready.read_text(encoding="utf-8").strip() == str(os.getpid())
    _remove_ready_file(str(ready))
    assert not ready.exists()
    # removing a missing file is a no-op, not an error
    _remove_ready_file(str(ready))
