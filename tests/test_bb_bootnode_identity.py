# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Copyright (C) 2025 Alberto Basso

"""Black-box identity tests: persisted-by-default, rotation, ephemeral opt-out.

Drives the real bootnode binary and observes only the public CLI (``run``,
``identity show``/``identity rotate``) and filesystem artifacts (the identity
file and its mode) — never the implementation.
"""

from __future__ import annotations

from pathlib import Path

from harness import run_cli, terminate


def _show(path: Path) -> str:
    result = run_cli(["identity", "show", "--identity", str(path)])
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_default_identity_persists_and_is_stable(bootnode_factory, tmp_path) -> None:
    """With no ``--identity``/``--ephemeral`` the identity persists and is reused."""
    path = tmp_path / "state" / "identity.pem"
    env = {"HSYNC_BOOTNODE_IDENTITY": str(path)}

    first = bootnode_factory(ephemeral=False, env_extra=env)
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    fp1 = _show(path)
    assert fp1.startswith("sha256:")

    terminate(first)
    bootnode_factory(ephemeral=False, env_extra=env)
    assert _show(path) == fp1  # the persisted identity is reused, not regenerated


def test_ephemeral_writes_no_identity_file(bootnode_factory, tmp_path) -> None:
    """``--ephemeral`` keeps the identity in memory and writes nothing to disk."""
    state = tmp_path / "xdg-state"

    bootnode_factory(ephemeral=True, env_extra={"XDG_STATE_HOME": str(state)})
    assert not (state / "hsync").exists()  # no identity file, not even the directory


def test_identity_and_ephemeral_are_mutually_exclusive(tmp_path) -> None:
    """A single identity source: ``--identity`` and ``--ephemeral`` cannot combine."""
    result = run_cli(
        ["run", "--port", "8443", "--identity", str(tmp_path / "id.pem"), "--ephemeral"]
    )
    assert result.returncode == 2
    assert "mutually exclusive" in result.stderr


def test_identity_rotate_changes_fingerprint(bootnode_factory, tmp_path) -> None:
    path = tmp_path / "identity.pem"
    bootnode_factory(ephemeral=False, args=["--identity", str(path)])
    before = _show(path)

    result = run_cli(["identity", "rotate", "--identity", str(path)])
    assert result.returncode == 0, result.stderr
    after = result.stdout.strip()
    assert after.startswith("sha256:")
    assert after != before
    assert _show(path) == after


def test_identity_show_pem_never_leaks_the_key(bootnode_factory, tmp_path) -> None:
    path = tmp_path / "identity.pem"
    bootnode_factory(ephemeral=False, args=["--identity", str(path)])

    result = run_cli(["identity", "show", "--identity", str(path), "--pem"])
    assert result.returncode == 0
    assert "-----BEGIN CERTIFICATE-----" in result.stdout
    assert "PRIVATE KEY" not in result.stdout


def test_identity_show_on_missing_file_fails_fast(tmp_path) -> None:
    result = run_cli(["identity", "show", "--identity", str(tmp_path / "missing.pem")])
    assert result.returncode == 2
    assert "configuration error" in result.stderr


def test_identity_rotate_on_missing_file_fails_fast(tmp_path) -> None:
    result = run_cli(["identity", "rotate", "--identity", str(tmp_path / "missing.pem")])
    assert result.returncode == 2
    assert "configuration error" in result.stderr
