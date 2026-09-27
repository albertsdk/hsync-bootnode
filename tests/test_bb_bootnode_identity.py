# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Copyright (C) 2025 Alberto Basso

"""Black-box identity tests: opt-in persistence, rotation, ephemeral default.

Drives the real bootnode binary and observes only the public CLI
(``identity show``/``identity rotate``) and filesystem artifacts (the identity
file and its mode) — never the implementation.
"""

from __future__ import annotations

from pathlib import Path

from harness import run_cli, terminate


def _show(path: Path) -> str:
    result = run_cli(["identity", "show", "--identity", str(path)])
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_persisted_identity_stable_across_restarts(bootnode_factory, tmp_path) -> None:
    path = tmp_path / "state" / "identity.pem"
    first = bootnode_factory(args=["--identity", str(path)])
    fp1 = _show(path)
    assert fp1.startswith("sha256:")

    terminate(first)
    bootnode_factory(args=["--identity", str(path)])
    fp2 = _show(path)
    assert fp2 == fp1  # the persisted identity is reused, not regenerated

    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


def test_identity_rotate_changes_fingerprint(bootnode_factory, tmp_path) -> None:
    path = tmp_path / "identity.pem"
    bootnode_factory(args=["--identity", str(path)])
    before = _show(path)

    result = run_cli(["identity", "rotate", "--identity", str(path)])
    assert result.returncode == 0, result.stderr
    after = result.stdout.strip()
    assert after.startswith("sha256:")
    assert after != before
    assert _show(path) == after


def test_identity_show_pem_never_leaks_the_key(bootnode_factory, tmp_path) -> None:
    path = tmp_path / "identity.pem"
    bootnode_factory(args=["--identity", str(path)])

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
