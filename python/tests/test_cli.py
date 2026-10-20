"""CLI smoke tests: version output, fail-fast configuration, keys-fd loading."""

from __future__ import annotations

import errno
import os
import re
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hsync_bootnode.cli import (
    _load_keys,
    _remove_ready_file,
    _resolve_identity,
    _write_ready_file,
    app,
    default_identity_path,
)
from hsync_bootnode.handler import BootConfigError

runner = CliRunner()

# Keep the CLI tests hermetic: without this the default identity would be created
# in the real XDG state dir. Tests that exercise persistence set their own path.
_EPHEMERAL_ENV = {"HSYNC_BOOTNODE_EPHEMERAL": "1"}

# Rich highlights option names by splitting them into styled segments (e.g.
# ``--private`` becomes ``-`` + ``-private`` with an ANSI reset between) whenever
# it emits color — as a CI runner that forces it does. Strip the escapes before
# substring assertions so the help checks do not depend on color detection.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Return *text* without ANSI styling (for help/substring assertions)."""
    return _ANSI_RE.sub("", text)


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


def test_load_keys_refuses_stdout_and_stderr() -> None:
    """fd 1/2 are never a key source: passing stdout/stderr is a config error."""
    for bad in (1, 2):
        try:
            _load_keys(bad)
        except BootConfigError:
            pass
        else:  # pragma: no cover - expected to raise
            raise AssertionError(f"fd {bad} must be refused as a keys source")


def test_load_keys_caps_the_fd_payload(tmp_path) -> None:
    """A descriptor that keeps producing bytes is refused, never read to the end.

    A misrouted fd (a pipe held open, some random device) would otherwise stall
    startup or grow without bound: the cap fails fast instead.
    """
    from hsync_bootnode.cli import KEYS_FD_MAX_BYTES

    with tempfile.NamedTemporaryFile(dir=tmp_path, suffix=".keys", delete=False) as handle:
        handle.write(b"shared=abc123\n" * 100_000)  # well past the cap
        path = handle.name
    fd = os.open(path, os.O_RDONLY)
    try:
        try:
            _load_keys(fd)
        except BootConfigError:
            pass
        else:  # pragma: no cover - expected to raise
            raise AssertionError(f"payload larger than {KEYS_FD_MAX_BYTES} bytes must fail fast")
    finally:
        os.close(fd)
        os.unlink(path)


@pytest.mark.skipif(os.name == "nt", reason="the read timeout is enforced with select() (POSIX)")
def test_load_keys_times_out_on_a_stuck_open_fd(monkeypatch) -> None:
    """A descriptor held open without EOF must fail fast, not hang startup.

    The write end stays open and silent, so the read would block forever without
    the bounded wait; the configuration error is raised instead.
    """
    monkeypatch.setattr("hsync_bootnode.cli.KEYS_FD_READ_TIMEOUT_SECONDS", 0.05)
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(BootConfigError, match="not received within"):
            _load_keys(read_fd)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_load_keys_from_file(tmp_path) -> None:
    """An operator file is a first-class key source (Windows has no fd seam)."""
    path = tmp_path / "group-keys"
    path.write_text("shared=abc123\n# operator comment\nhome=def456\n", encoding="utf-8")
    keys = _load_keys(None, str(path))
    assert set(keys) == {"shared", "home"}
    assert keys["shared"].get_secret_value() == "abc123"
    assert keys["home"].get_secret_value() == "def456"


def test_load_keys_empty_file_means_open_mode(tmp_path) -> None:
    path = tmp_path / "group-keys"
    path.write_text("", encoding="utf-8")
    assert _load_keys(None, str(path)) == {}


def test_load_keys_missing_file_fails_fast(tmp_path) -> None:
    with pytest.raises(BootConfigError, match="cannot open group keys file"):
        _load_keys(None, str(tmp_path / "missing"))


def test_load_keys_fd_and_file_are_mutually_exclusive(tmp_path) -> None:
    path = tmp_path / "group-keys"
    path.write_text("shared=abc123\n", encoding="utf-8")
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    try:
        with pytest.raises(BootConfigError, match="mutually exclusive"):
            _load_keys(read_fd, str(path))
    finally:
        os.close(read_fd)


@pytest.mark.skipif(os.name == "nt", reason="creating a symlink needs a privilege on Windows")
def test_load_keys_refuses_a_symlink(tmp_path) -> None:
    real = tmp_path / "real"
    real.write_text("shared=abc123\n", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(BootConfigError, match="symlink"):
        _load_keys(None, str(link))


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_load_keys_warns_on_loose_permissions(tmp_path, monkeypatch) -> None:
    path = tmp_path / "group-keys"
    path.write_text("shared=abc123\n", encoding="utf-8")
    path.chmod(0o644)
    events: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "hsync_bootnode.cli.warn_event",
        lambda event, **fields: events.append((event, fields)),
    )
    assert set(_load_keys(None, str(path))) == {"shared"}
    assert events and events[0][0] == "group keys file permissions are too open"
    assert events[0][1]["path"] == str(path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_load_keys_accepts_a_group_readable_file(tmp_path, monkeypatch) -> None:
    """0640 is the documented service-account mode: group read is allowed."""
    path = tmp_path / "group-keys"
    path.write_text("shared=abc123\n", encoding="utf-8")
    path.chmod(0o640)
    events: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "hsync_bootnode.cli.warn_event",
        lambda event, **fields: events.append((event, fields)),
    )
    assert set(_load_keys(None, str(path))) == {"shared"}
    assert events == []


def test_load_keys_file_caps_the_payload(tmp_path) -> None:
    from hsync_bootnode.cli import KEYS_FD_MAX_BYTES

    path = tmp_path / "group-keys"
    path.write_bytes(b"shared=abc123\n" * 100_000)
    with pytest.raises(BootConfigError, match="exceeded"):
        _load_keys(None, str(path))
    assert KEYS_FD_MAX_BYTES > 0


def test_keys_file_and_fd_are_rejected_by_the_cli(tmp_path) -> None:
    path = tmp_path / "group-keys"
    path.write_text("shared=abc123\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["run", "--keys-fd", "5", "--keys-file", str(path)],
        env=_EPHEMERAL_ENV,
    )
    combined = result.output + getattr(result, "stderr", "")
    assert result.exit_code == 2
    assert "mutually exclusive" in combined


def test_missing_keys_file_fails_fast_via_the_cli(tmp_path) -> None:
    result = runner.invoke(
        app,
        ["run", "--keys-file", str(tmp_path / "missing")],
        env=_EPHEMERAL_ENV,
    )
    combined = result.output + getattr(result, "stderr", "")
    assert result.exit_code == 2
    assert "cannot open group keys file" in combined


def test_keys_options_are_documented_in_help() -> None:
    result = runner.invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    output = _plain(result.output)
    assert "--keys-fd" in output
    assert "--keys-file" in output
    assert "HSYNC_BOOTNODE_KEYS_FILE" in output


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
    output = _plain(result.output)
    assert "--private" in output
    assert "HSYNC_BOOTNODE_PRIVATE" in output


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


def _patch_run_no_side_effects(monkeypatch, start_servers) -> None:
    """Stub the listener start and the two process-global installers.

    ``run`` reaches ``_install_uvloop``/``_install_sigterm_handler`` before the
    bind; stubbing them keeps the test process free of a global event-loop policy
    swap and a SIGTERM handler.
    """
    monkeypatch.setattr("hsync_bootnode.cli.start_servers", start_servers)
    monkeypatch.setattr("hsync_bootnode.cli._install_uvloop", lambda: None)
    monkeypatch.setattr("hsync_bootnode.cli._install_sigterm_handler", lambda: None)


def test_bind_permission_denied_is_actionable(monkeypatch) -> None:
    async def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        # aioquic wraps the real error: no errno on the outer OSError.
        raise OSError("could not bind to local_addr ('0.0.0.0', 443)") from PermissionError(
            errno.EACCES, "Permission denied"
        )

    _patch_run_no_side_effects(monkeypatch, _boom)
    result = runner.invoke(app, ["run", "--port", "443"], env=_EPHEMERAL_ENV)
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
    result = runner.invoke(app, ["run", "--port", "443"], env=_EPHEMERAL_ENV)
    assert result.exit_code == 3
    out = _combined(result)
    assert "already in use" in out
    assert "--port <PORT>" in out
    assert "Traceback" not in out


def test_bind_bad_host_is_actionable(monkeypatch) -> None:
    async def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise OSError(errno.EADDRNOTAVAIL, "Cannot assign requested address")

    _patch_run_no_side_effects(monkeypatch, _boom)
    result = runner.invoke(app, ["run", "--host", "127.0.0.1", "--port", "443"], env=_EPHEMERAL_ENV)
    assert result.exit_code == 3
    out = _combined(result)
    assert "not available" in out
    assert "--host" in out
    assert "0.0.0.0" in out


def test_run_port_default_uses_the_shared_ssot() -> None:
    """The effective default port is the shared ``BOOT_DEFAULT_PORT`` (spec §Transport)."""
    from hsync_common.constants import BOOT_DEFAULT_PORT

    from hsync_bootnode.cli import _resolve_listeners

    assert _resolve_listeners(None, None, None) == ("0.0.0.0", [BOOT_DEFAULT_PORT])
    assert _resolve_listeners("0.0.0.0", None, None) == ("0.0.0.0", [BOOT_DEFAULT_PORT])


def test_host_port_shorthand_is_accepted() -> None:
    """``--host HOST:PORT`` resolves host and port without a separate ``--port``."""
    from hsync_bootnode.cli import _resolve_listeners

    assert _resolve_listeners("0.0.0.0:8443", None, None) == ("0.0.0.0", [8443])
    assert _resolve_listeners("[::1]:8443", None, None) == ("::1", [8443])


def test_host_port_and_port_flag_are_mutually_exclusive() -> None:
    """A port in ``--host`` and in ``--port`` is a usage error, not a precedence."""
    import pytest
    import typer

    from hsync_bootnode.cli import _resolve_listeners

    with pytest.raises(typer.BadParameter):
        _resolve_listeners("0.0.0.0:8443", 8443, None)


def test_port_flag_alone_keeps_the_default_host() -> None:
    """``--port`` without ``--host`` binds all interfaces, as before."""
    from hsync_bootnode.cli import _resolve_listeners

    assert _resolve_listeners(None, 8443, None) == ("0.0.0.0", [8443])


def test_ports_flag_resolves_the_ordered_set() -> None:
    """``--ports`` resolves a comma-separated ordered set and conflicts with --port."""
    import pytest
    import typer

    from hsync_bootnode.cli import _resolve_listeners

    assert _resolve_listeners(None, None, "443,53") == ("0.0.0.0", [443, 53])
    # Whitespace around entries is tolerated; order is preserved.
    assert _resolve_listeners("0.0.0.0", None, "53, 443") == ("0.0.0.0", [53, 443])

    with pytest.raises(typer.BadParameter):
        _resolve_listeners(None, 443, "443,53")  # --port + --ports
    with pytest.raises(typer.BadParameter):
        _resolve_listeners("0.0.0.0:8443", None, "443,53")  # host port + --ports
    with pytest.raises(typer.BadParameter):
        _resolve_listeners(None, None, "443,443")  # duplicate
    with pytest.raises(typer.BadParameter):
        _resolve_listeners(None, None, "0")  # out of range
    with pytest.raises(typer.BadParameter):
        _resolve_listeners(None, None, "443,notaport")  # non-integer


class _FakeIdentity:
    """Minimal stand-in for the listener identity (only ``fingerprint`` is read)."""

    fingerprint = "00" * 32


class _FakeServer:
    """Minimal stand-in for the started listener (only ``close`` is called)."""

    def close(self) -> None:
        pass


def test_ready_file_failure_is_actionable_exit_4(monkeypatch, tmp_path) -> None:
    """An unwritable --ready-file exits 4 with an actionable message, no traceback."""

    async def _start(*args, **kwargs):  # noqa: ANN002, ANN003
        return [_FakeServer()], [8443], _FakeIdentity(), []

    _patch_run_no_side_effects(monkeypatch, _start)
    ready = tmp_path / "missing-dir" / "ready.pid"
    result = runner.invoke(
        app, ["run", "--port", "8443", "--ready-file", str(ready)], env=_EPHEMERAL_ENV
    )

    assert result.exit_code == 4
    out = _combined(result)
    assert "no such directory" in out
    assert "Traceback" not in out
    # The always-on diagnostics channel reports it too, and it stays peer-free.
    assert "error: readiness file not writable" in out
    assert f"path={ready}" in out


def test_ready_file_conflict_leaves_the_existing_file_alone(monkeypatch, tmp_path) -> None:
    """A pre-existing path is refused (O_EXCL) and never deleted by the node."""

    async def _start(*args, **kwargs):  # noqa: ANN002, ANN003
        return [_FakeServer()], [8443], _FakeIdentity(), []

    _patch_run_no_side_effects(monkeypatch, _start)
    ready = tmp_path / "ready.pid"
    ready.write_text("stale", encoding="utf-8")

    result = runner.invoke(
        app, ["run", "--port", "8443", "--ready-file", str(ready)], env=_EPHEMERAL_ENV
    )

    assert result.exit_code == 4
    assert "already exists" in _combined(result)
    assert ready.read_text(encoding="utf-8") == "stale"


def test_debug_run_announces_the_peer_aware_stream(monkeypatch, tmp_path) -> None:
    """Opting into --debug is announced on the always-on channel (transparency).

    The unwritable readiness file ends the run deterministically right after the
    announcement, so the assertion does not depend on a serving process.
    """

    async def _start(*args, **kwargs):  # noqa: ANN002, ANN003
        return [_FakeServer()], [8443], _FakeIdentity(), []

    _patch_run_no_side_effects(monkeypatch, _start)
    ready = tmp_path / "missing-dir" / "ready.pid"
    result = runner.invoke(
        app,
        ["run", "--port", "8443", "--debug", "--no-rate-limit", "--ready-file", str(ready)],
        env=_EPHEMERAL_ENV,
    )

    out = _combined(result)
    assert "warn: peer data logging enabled reason=--debug" in out
    assert "warn: rate limiting disabled reason=--no-rate-limit" in out


def test_default_identity_path_uses_xdg_state(monkeypatch, tmp_path) -> None:
    """With no override the path is an XDG *state* path (stable across restarts)."""
    monkeypatch.delenv("HSYNC_BOOTNODE_IDENTITY", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert default_identity_path() == tmp_path / "hsync" / "bootnode" / "identity.pem"


def test_default_identity_path_honours_the_env_override(monkeypatch, tmp_path) -> None:
    target = tmp_path / "custom" / "id.pem"
    monkeypatch.setenv("HSYNC_BOOTNODE_IDENTITY", str(target))
    assert default_identity_path() == target


def test_resolve_identity_returns_none_for_ephemeral() -> None:
    assert _resolve_identity(None, True, host="127.0.0.1", public_hosts=[]) is None


def test_resolve_identity_rejects_identity_and_ephemeral() -> None:
    import pytest

    from hsync_bootnode.handler import BootConfigError

    with pytest.raises(BootConfigError, match="mutually exclusive"):
        _resolve_identity("id.pem", True, host="127.0.0.1", public_hosts=[])


def test_resolve_identity_defaults_to_the_state_path(monkeypatch, tmp_path) -> None:
    state = tmp_path / "state" / "identity.pem"
    monkeypatch.setenv("HSYNC_BOOTNODE_IDENTITY", str(state))
    node = _resolve_identity(None, False, host="127.0.0.1", public_hosts=[])
    assert node is not None
    assert state.is_file()


def test_identity_options_are_documented_in_help() -> None:
    result = runner.invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    output = _plain(result.output)
    assert "--identity" in output
    assert "--ephemeral" in output
    assert "HSYNC_BOOTNODE_EPHEMERAL" in output


_PACKAGED_UNIT = Path(__file__).resolve().parents[2] / (
    "packaging/deb/usr/lib/systemd/system/hsync-bootnode.service"
)
_SOURCE_UNIT = Path(__file__).resolve().parents[2] / ("packaging/systemd/hsync-bootnode.service")
# A DynamicUser has no resolvable home directory, so the packaged unit must
# never rely on the default XDG state path (Path.home() raises RuntimeError).
_IDENTITY_FLAG = "--identity /var/lib/hsync-bootnode/identity.pem"


def test_packaged_unit_pins_the_identity_path() -> None:
    """The deb unit passes an explicit identity path in every ExecStart branch."""
    text = _PACKAGED_UNIT.read_text(encoding="utf-8")
    assert "StateDirectory=hsync-bootnode" in text
    for line in text.splitlines():
        if line.startswith("ExecStart="):
            assert _IDENTITY_FLAG in line, f"missing identity path: {line}"


def test_packaged_unit_matches_the_source_unit() -> None:
    """The deb and source units must not diverge on identity handling again."""
    packaged = _PACKAGED_UNIT.read_text(encoding="utf-8")
    source = _SOURCE_UNIT.read_text(encoding="utf-8")
    assert ("StateDirectory=hsync-bootnode" in source) == (
        "StateDirectory=hsync-bootnode" in packaged
    )
    assert (_IDENTITY_FLAG in source) == (_IDENTITY_FLAG in packaged)
