"""Guard for ``install.sh``'s container-image signature verification.

The installer used to pull ``ghcr.io/albertsdk/hsync-bootnode:<tag>`` and start it
with no integrity check: a mutated tag or a compromised registry answer would
run arbitrary code as the node. It now verifies the image's Sigstore (cosign)
signature — keyless, signed by the release workflow — before starting, and can
pin an exact digest (``--image-digest``); ``--no-verify`` opts out explicitly.

These tests stub ``docker``/``cosign``/``curl`` on ``PATH`` and run the real
script with ``--no-start`` (no container is started), so they need no Docker,
no registry and no network. Exercising the actual pull/run path needs all three
and is out of scope here.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO / "install.sh"
RELEASE_YML = REPO / ".github" / "workflows" / "release.yml"

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="install.sh is a POSIX shell script (bash/docker)"
)

DIGEST = "sha256:" + "a" * 64
IMAGE = "ghcr.io/albertsdk/hsync-bootnode"
LATEST_TAG = "v9.9.9"


def _run(
    tmp_path: Path,
    *args: str,
    cosign_exit: int | None = 0,
    with_cosign: bool = True,
    with_curl: bool = False,
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    """Run ``install.sh --no-start`` with stubbed tools; return (proc, state, log)."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    docker = bindir / "docker"
    docker.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    docker.chmod(0o755)

    cosign_log = tmp_path / "cosign.log"
    cosign = bindir / "cosign"
    cosign.write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\n" "$*" >> "{cosign_log}"\n'
        f"exit {cosign_exit if cosign_exit is not None else 0}\n",
        encoding="utf-8",
    )
    cosign.chmod(0o755)
    if not with_cosign:
        cosign.unlink()

    if with_curl:
        curl = bindir / "curl"
        curl.write_text(
            "#!/usr/bin/env bash\n"
            f"printf '%s\\n' 'https://github.com/albertsdk/hsync-bootnode/releases/tag/{LATEST_TAG}'\n",
            encoding="utf-8",
        )
        curl.chmod(0o755)

    install_dir = tmp_path / "state"
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    proc = subprocess.run(
        ["bash", str(INSTALL_SH), "--install-dir", str(install_dir), "--no-start", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
    )
    return proc, install_dir, cosign_log


def test_install_script_is_valid_bash() -> None:
    result = subprocess.run(["bash", "-n", str(INSTALL_SH)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_help_documents_the_verification_flags() -> None:
    result = subprocess.run(["bash", str(INSTALL_SH), "--help"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "--no-verify" in result.stdout
    assert "--image-digest" in result.stdout
    assert "cosign" in result.stdout


def test_default_run_verifies_the_signature(tmp_path: Path) -> None:
    proc, _state, log = _run(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "Verifying the container image signature" in proc.stdout
    logged = log.read_text(encoding="utf-8")
    assert "verify" in logged
    assert f"{IMAGE}:v1.0.0" in logged
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in logged


def test_missing_cosign_fails_closed(tmp_path: Path) -> None:
    proc, _state, _log = _run(tmp_path, with_cosign=False)
    assert proc.returncode != 0
    assert "cosign" in proc.stderr


def test_failed_verification_fails_closed(tmp_path: Path) -> None:
    proc, _state, _log = _run(tmp_path, cosign_exit=1)
    assert proc.returncode != 0
    assert "signature verification failed" in proc.stderr


def test_no_verify_skips_verification(tmp_path: Path) -> None:
    proc, _state, _log = _run(tmp_path, "--no-verify", with_cosign=False)
    assert proc.returncode == 0, proc.stderr
    assert "verification is disabled" in proc.stderr


def test_image_digest_pins_the_exact_reference(tmp_path: Path) -> None:
    proc, state, log = _run(tmp_path, "--image-digest", DIGEST)
    assert proc.returncode == 0, proc.stderr
    env_file = (state / ".env").read_text(encoding="utf-8")
    assert f"HSYNC_BOOTNODE_IMAGE={IMAGE}@{DIGEST}" in env_file
    assert f"{IMAGE}@{DIGEST}" in log.read_text(encoding="utf-8")


def test_invalid_digest_is_rejected(tmp_path: Path) -> None:
    proc, _state, _log = _run(tmp_path, "--image-digest", "sha256:zz")
    assert proc.returncode != 0
    assert "invalid --image-digest" in proc.stderr


def test_latest_version_resolves_and_is_verified(tmp_path: Path) -> None:
    proc, state, log = _run(tmp_path, "--version", "latest", with_curl=True)
    assert proc.returncode == 0, proc.stderr
    env_file = (state / ".env").read_text(encoding="utf-8")
    assert f"HSYNC_BOOTNODE_IMAGE={IMAGE}:{LATEST_TAG}" in env_file
    assert f"{IMAGE}:{LATEST_TAG}" in log.read_text(encoding="utf-8")


def test_release_workflow_signs_the_image() -> None:
    workflow = RELEASE_YML.read_text(encoding="utf-8")
    assert "id-token: write" in workflow
    assert "sigstore/cosign-installer" in workflow
    assert "cosign sign --yes" in workflow
    assert "steps.build.outputs.digest" in workflow
