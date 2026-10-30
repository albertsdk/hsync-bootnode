# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Alberto Basso

"""Black-box identity tests: persisted-by-default, rotation, ephemeral opt-out.

Drives the real rendezvous binary and observes only the public CLI (``run``,
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


def test_default_identity_persists_and_is_stable(rendezvous_factory, tmp_path) -> None:
    """With no ``--identity``/``--ephemeral`` the identity persists and is reused."""
    # Given: a state path with HSYNC_RENDEZVOUS_IDENTITY set
    path = tmp_path / "state" / "identity.pem"
    env = {"HSYNC_RENDEZVOUS_IDENTITY": str(path)}

    # When: the node starts (persisted), is stopped, and starts again
    first = rendezvous_factory(ephemeral=False, env_extra=env)
    assert path.is_file()
    # Then: the identity is written 0600 in a 0700 dir, and reused on restart
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    fp1 = _show(path)
    assert fp1.startswith("sha256:")

    terminate(first)
    rendezvous_factory(ephemeral=False, env_extra=env)
    assert _show(path) == fp1  # the persisted identity is reused, not regenerated


def test_ephemeral_writes_no_identity_file(rendezvous_factory, tmp_path) -> None:
    """``--ephemeral`` keeps the identity in memory and writes nothing to disk."""
    # Given: an isolated XDG state directory
    state = tmp_path / "xdg-state"
    # When: the node starts in ephemeral mode
    rendezvous_factory(ephemeral=True, env_extra={"XDG_STATE_HOME": str(state)})
    # Then: no identity file — not even the directory — was written
    assert not (state / "hsync").exists()


def test_identity_and_ephemeral_are_mutually_exclusive(tmp_path) -> None:
    """A single identity source: ``--identity`` and ``--ephemeral`` cannot combine."""
    # When: both flags are passed
    result = run_cli(
        ["run", "--listen-port", "8443", "--identity", str(tmp_path / "id.pem"), "--ephemeral"]
    )
    # Then: fail-fast configuration error (exit 2)
    assert result.returncode == 2
    assert "mutually exclusive" in result.stderr


def test_identity_rotate_changes_fingerprint(rendezvous_factory, tmp_path) -> None:
    # Given: a persisted identity
    path = tmp_path / "identity.pem"
    rendezvous_factory(ephemeral=False, args=["--identity", str(path)])
    before = _show(path)

    # When: the identity is rotated
    result = run_cli(["identity", "rotate", "--identity", str(path)])
    assert result.returncode == 0, result.stderr
    after = result.stdout.strip()
    # Then: a new fingerprint is printed and persisted
    assert after.startswith("sha256:")
    assert after != before
    assert _show(path) == after


def test_identity_show_pem_never_leaks_the_key(rendezvous_factory, tmp_path) -> None:
    # Given: a persisted identity
    path = tmp_path / "identity.pem"
    rendezvous_factory(ephemeral=False, args=["--identity", str(path)])

    # When: ``identity show --pem`` is run
    result = run_cli(["identity", "show", "--identity", str(path), "--pem"])
    # Then: the certificate is present, the private key is never printed
    assert result.returncode == 0
    assert "-----BEGIN CERTIFICATE-----" in result.stdout
    assert "PRIVATE KEY" not in result.stdout


def test_identity_show_on_missing_file_fails_fast(tmp_path) -> None:
    # When: ``identity show`` points at a missing file
    result = run_cli(["identity", "show", "--identity", str(tmp_path / "missing.pem")])
    # Then: fail-fast configuration error (exit 2)
    assert result.returncode == 2
    assert "configuration error" in result.stderr


def test_identity_rotate_on_missing_file_fails_fast(tmp_path) -> None:
    # When: ``identity rotate`` points at a missing file
    result = run_cli(["identity", "rotate", "--identity", str(tmp_path / "missing.pem")])
    # Then: fail-fast configuration error (exit 2)
    assert result.returncode == 2
    assert "configuration error" in result.stderr
