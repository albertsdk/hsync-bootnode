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
import shutil
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


def _restricted_bin(tmp_path: Path) -> Path:
    """A minimal PATH dir without docker, so a real docker on the runner cannot
    leak into the "docker missing" preflight tests."""
    bin_dir = tmp_path / "restricted-bin"
    bin_dir.mkdir(exist_ok=True)
    for name in (
        "bash",
        "sh",
        "uname",
        "readlink",
        "id",
        "date",
        "sleep",
        "mkdir",
        "chmod",
        "mv",
        "rm",
        "cp",
        "grep",
    ):
        real = shutil.which(name)
        if real is not None:
            (bin_dir / name).symlink_to(real)
    return bin_dir


def _run(
    tmp_path: Path,
    *args: str,
    cosign_exit: int | None = 0,
    cosign_version: str = "v3.1.4",
    with_cosign: bool = True,
    with_curl: bool = False,
    snap_docker: bool = False,
    install_dir: Path | None = None,
    config_fails: bool = False,
    use_default_dir: bool = False,
    with_docker: bool = True,
    compose_version_fails: bool = False,
    compose_v1: bool = False,
    daemon_message: str | None = None,
    start_server: bool = False,
    uname_stub: tuple[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    """Run ``install.sh`` (``--no-start`` by default) with stubbed tools."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    # A snap-packaged docker is exposed through /snap/bin; mirror that layout so
    # the installer's snap detection sees the same path shape.
    docker_dir = tmp_path / "snap" / "bin" if snap_docker else bindir
    docker_dir.mkdir(parents=True, exist_ok=True)
    if with_docker:
        docker = docker_dir / "docker"
        docker_body = "#!/usr/bin/env bash\n"
        if compose_version_fails:
            docker_body += 'if [[ "$1" == "compose" && "$2" == "version" ]]; then\n  exit 1\nfi\n'
        if daemon_message is not None:
            docker_body += (
                'if [[ "$1" == "info" ]]; then\n'
                "  printf '%s\\n' \"${HSYNC_FAKE_DOCKER_INFO:-}\" >&2\n"
                "  exit 1\n"
                "fi\n"
            )
        if config_fails:
            docker_body += (
                'if [[ "$*" == *" config "* ]]; then\n'
                "  printf 'open /.env: permission denied\\n' >&2\n"
                "  exit 1\n"
                "fi\n"
            )
        docker.write_text(docker_body + "exit 0\n", encoding="utf-8")
        docker.chmod(0o755)

    if compose_v1:
        compose_v1_bin = bindir / "docker-compose"
        compose_v1_bin.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        compose_v1_bin.chmod(0o755)

    cosign_log = tmp_path / "cosign.log"
    cosign = bindir / "cosign"
    cosign.write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\n" "$*" >> "{cosign_log}"\n'
        'if [[ "$1" == "version" ]]; then\n'
        f'  printf "GitVersion:    {cosign_version}\\n"\n'
        "  exit 0\n"
        "fi\n"
        f"exit {cosign_exit if cosign_exit is not None else 0}\n",
        encoding="utf-8",
    )
    cosign.chmod(0o755)
    if not with_cosign:
        cosign.unlink()

    if uname_stub is not None:
        uname_os, uname_arch = uname_stub
        uname = bindir / "uname"
        uname.write_text(
            "#!/usr/bin/env bash\n"
            'case "$1" in\n'
            f'  -s) printf "%s\\n" "{uname_os}" ;;\n'
            f'  -m) printf "%s\\n" "{uname_arch}" ;;\n'
            '  *) printf "unknown\\n" ;;\n'
            "esac\n",
            encoding="utf-8",
        )
        uname.chmod(0o755)

    if with_curl:
        curl = bindir / "curl"
        curl.write_text(
            "#!/usr/bin/env bash\n"
            f"printf '%s\\n' 'https://github.com/albertsdk/hsync-bootnode/releases/tag/{LATEST_TAG}'\n",
            encoding="utf-8",
        )
        curl.chmod(0o755)

    install_dir = tmp_path / "state" if install_dir is None else install_dir
    env = os.environ.copy()
    if with_docker:
        env["PATH"] = f"{bindir}:{tmp_path / 'snap' / 'bin'}:{env['PATH']}"
    else:
        env["PATH"] = f"{bindir}:{_restricted_bin(tmp_path)}"
    if daemon_message is not None:
        env["HSYNC_FAKE_DOCKER_INFO"] = daemon_message
    cmd = ["bash", str(INSTALL_SH)]
    if not use_default_dir:
        cmd += ["--install-dir", str(install_dir)]
    if not start_server:
        cmd += ["--no-start"]
    cmd += list(args)
    proc = subprocess.run(
        cmd,
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


def test_missing_cosign_hint_is_actionable_and_writes_nothing(tmp_path: Path) -> None:
    """The hint names a real install command and the exact --no-verify re-run,
    and the missing verifier is detected before any file is written."""
    proc, state, _log = _run(tmp_path, with_cosign=False, uname_stub=("Linux", "x86_64"))
    assert proc.returncode != 0
    # The concrete command follows the host distro family (debian/rhel/suse print
    # the official binary, Arch/Alpine their package), so accept any of them.
    assert (
        "cosign-linux-amd64" in proc.stderr
        or "sudo pacman -S cosign" in proc.stderr
        or "sudo apk add cosign" in proc.stderr
    )
    assert "bash -s -- --no-verify" in proc.stderr
    # The documented final error line stays last (decision #73).
    assert proc.stderr.rstrip().endswith("Error: required command not found: cosign")
    assert not state.exists()


def test_missing_cosign_hint_follows_the_platform(tmp_path: Path) -> None:
    proc, _state, _log = _run(tmp_path, with_cosign=False, uname_stub=("Darwin", "arm64"))
    assert proc.returncode != 0
    assert "brew install cosign" in proc.stderr
    assert "cosign-linux-" not in proc.stderr


def test_failed_verification_fails_closed(tmp_path: Path) -> None:
    proc, state, _log = _run(tmp_path, cosign_exit=1)
    assert proc.returncode != 0
    assert "signature verification failed" in proc.stderr
    assert not state.exists()


def test_failed_verification_with_an_old_cosign_points_at_the_upgrade(tmp_path: Path) -> None:
    """A v2 cosign cannot read the v3 bundle signature of current releases, so
    that failure mode must name the upgrade instead of looking like tampering."""
    proc, state, _log = _run(tmp_path, cosign_exit=1, cosign_version="v2.4.1")
    assert proc.returncode != 0
    assert "cosign 2.x cannot verify the v3 bundle signature" in proc.stderr
    assert not state.exists()


def test_failed_verification_with_a_current_cosign_has_no_upgrade_hint(tmp_path: Path) -> None:
    proc, _state, _log = _run(tmp_path, cosign_exit=1, cosign_version="v3.1.4")
    assert proc.returncode != 0
    assert "cannot verify the v3 bundle signature" not in proc.stderr


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


def test_snap_docker_rejects_a_hidden_install_dir(tmp_path: Path) -> None:
    """Snap's home interface denies hidden paths under $HOME, so a snap-packaged
    docker cannot read .env in the default ~/.local/share directory."""
    hidden_dir = tmp_path / ".local" / "share" / "hsync-bootnode"
    proc, _state, _log = _run(tmp_path, snap_docker=True, install_dir=hidden_dir)
    assert proc.returncode != 0
    assert "snap" in proc.stderr
    assert "hidden path" in proc.stderr
    assert "bash -s -- --install-dir" in proc.stderr
    assert not hidden_dir.exists()


def test_snap_docker_allows_a_non_hidden_install_dir(tmp_path: Path) -> None:
    non_hidden = tmp_path / "hsync-bootnode"
    proc, _state, _log = _run(tmp_path, snap_docker=True, install_dir=non_hidden)
    assert proc.returncode == 0, proc.stderr


def test_snap_docker_adapts_a_default_hidden_install_dir(tmp_path: Path, monkeypatch) -> None:
    """With snap docker and no explicit --install-dir, fall back to a non-hidden
    default instead of failing the whole install."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    proc, _state, _log = _run(tmp_path, snap_docker=True, use_default_dir=True)
    assert proc.returncode == 0, proc.stderr
    assert (home / "hsync-bootnode" / ".env").exists()


def test_compose_failure_hints_at_snap_hidden_paths(tmp_path: Path) -> None:
    """A snap docker failure carrying the hidden-path signature gets an
    actionable hint even where the pre-flight check did not catch it."""
    non_hidden = tmp_path / "hsync-bootnode"
    proc, _state, _log = _run(tmp_path, snap_docker=True, config_fails=True, install_dir=non_hidden)
    assert proc.returncode != 0
    assert "Warning: docker is the snap package" in proc.stderr
    assert "bash -s -- --install-dir" in proc.stderr


# --- Prerequisite guidance ---------------------------------------------------


def test_dry_run_works_without_docker(tmp_path: Path) -> None:
    """--dry-run exits before the preflight, so it must not need docker."""
    proc, state, _log = _run(tmp_path, "--dry-run", with_docker=False)
    assert proc.returncode == 0, proc.stderr
    assert "Dry run" in proc.stdout
    assert not state.exists()


def test_missing_docker_prints_install_guidance(tmp_path: Path) -> None:
    proc, state, _log = _run(tmp_path, with_docker=False)
    assert proc.returncode != 0
    assert "required command not found: docker" in proc.stderr
    assert "docs.docker.com" in proc.stderr
    assert not state.exists()


def test_docker_compose_v2_missing_prints_guidance(tmp_path: Path) -> None:
    proc, state, _log = _run(tmp_path, compose_version_fails=True)
    assert proc.returncode != 0
    assert "Docker Compose v2 is required" in proc.stderr
    assert "docs.docker.com/compose/install" in proc.stderr
    assert not state.exists()


def test_docker_compose_v1_only_is_called_out(tmp_path: Path) -> None:
    proc, _state, _log = _run(tmp_path, compose_version_fails=True, compose_v1=True)
    assert proc.returncode != 0
    assert "Compose v1" in proc.stderr


def test_docker_daemon_unreachable_prints_start_guidance(tmp_path: Path) -> None:
    proc, state, _log = _run(
        tmp_path,
        start_server=True,
        daemon_message="Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
    )
    assert proc.returncode != 0
    assert "Cannot reach the Docker daemon" in proc.stderr
    assert not state.exists()


def test_docker_permission_denied_prints_group_guidance(tmp_path: Path) -> None:
    proc, state, _log = _run(
        tmp_path,
        start_server=True,
        daemon_message="permission denied while trying to connect to the Docker daemon socket",
    )
    assert proc.returncode != 0
    assert "usermod -aG docker" in proc.stderr
    assert not state.exists()
