"""Guard for the container build commands in ``../compile.sh`` (decisions #38/#39).

Two invariants are asserted on the script text (exercising the real cross-build
needs Docker, qemu and network access):

* the ``build`` group must be requested with the syntax Poetry honours —
  ``poetry install --only main --with build`` prunes it under Poetry 2.x, so the
  container installs no PyInstaller and falls back to the *host* ``.venv``
  mounted into the tree;
* the artifact paths must be absolute under explicit mounts, because the
  container workdir is ``python/``: a relative distpath lands in
  ``python/build/`` while the host checks the repo-root ``build/deb-all/``,
  and a relative package output lands in ``python/dist/`` instead of ``dist/``.

Consumers: hsync-bootnode maintainers (regression guard for decisions #38/#39).
"""

from __future__ import annotations

import re
from pathlib import Path

COMPILE_SH = Path(__file__).resolve().parents[2] / "compile.sh"

# The historical regression: Poetry 2.x ignores `--with` next to `--only`.
_BROKEN = "poetry install --only main --with build"
_FIXED = "poetry install --only main,build"


def _poetry_install_lines() -> list[str]:
    return [
        line.strip()
        for line in COMPILE_SH.read_text(encoding="utf-8").splitlines()
        if "poetry install" in line
    ]


def _build_group_requested(line: str) -> bool:
    """True when ``line`` installs the ``build`` group under Poetry 2.x rules."""
    only = re.search(r"--only\s+([^\s;]+)", line)
    if only:
        # Inside --only the group list is exhaustive: --with cannot re-add it.
        return "build" in only.group(1).split(",")
    return "--without build" not in line and "--without=build" not in line


def test_guard_rejects_the_pruned_build_group() -> None:
    """The guard must fail on the pre-fix form and pass on the fixed one."""
    assert not _build_group_requested(_BROKEN)
    assert _build_group_requested(_FIXED)
    # The `;`-terminated form used inside the container retry loop.
    assert not _build_group_requested("if poetry install --only main --with build; then :; fi")
    assert _build_group_requested("if poetry install --only main,build; then :; fi")


def test_every_container_build_installs_the_build_group() -> None:
    lines = _poetry_install_lines()
    assert lines, "no 'poetry install' invocation found in compile.sh"
    for line in lines:
        assert _build_group_requested(line), f"build group not installed: {line}"


def _script() -> str:
    return COMPILE_SH.read_text(encoding="utf-8")


def _container_build_cmd_body() -> str:
    """Body of ``_container_build_cmd()``, i.e. the in-container build command.

    Scoped on purpose: ``_build_onedir`` also contains a
    ``compile.sh -t onedir -o ...`` invocation (the host one, used by the
    ``deb`` target) and must keep its relative path.
    """
    script = _script()
    # Anchor on the definition: the name also appears in the dispatcher comment.
    start = script.index("_container_build_cmd() {")
    return script[start : script.index("\n}", start)]


def test_container_onedir_distpath_is_the_path_the_host_checks() -> None:
    """The bundle the container writes is the one the post-build check looks at.

    ``-o`` is resolved by the container against its workdir (``python/``), so a
    relative ``build/deb-all/...`` produced ``python/build/deb-all/...`` and the
    host check on the repo-root ``build/deb-all/...`` failed with "onedir bundle
    not produced".
    """
    distpath = re.search(r"-t onedir -o ([^\s\"]+)", _container_build_cmd_body())
    assert distpath, "no 'onedir -o <distpath>' in the container build command"
    assert distpath.group(1).startswith("/build/deb-all/"), distpath.group(1)
    script = _script()
    # /build must be anchored to the repo-root build/ dir, i.e. the parent of
    # DEB_ALL_BUILD_DIR, so the container path and the host path coincide.
    assert 'build_abs="$(cd "${BUILD_DIR}" && pwd)"' in script
    assert '-v "${build_abs}:/build"' in script
    assert 'readonly BUILD_DIR="build"' in script
    assert 'readonly DEB_ALL_BUILD_DIR="${BUILD_DIR}/deb-all"' in script
    assert 'if [[ ! -d "${bin_dir}/${APP_NAME}" ]]; then' in script
    assert 'local bin_dir="${DEB_ALL_BUILD_DIR}/${deb_arch}/pyinstaller"' in script


def test_deb_is_built_into_the_out_mount() -> None:
    """The package is emitted into /out (the host dist/deb), not python/dist/."""
    script = _script()
    assert 'stage="/build/deb-all/${deb_arch}/stage"' in script
    assert 'fakeroot dpkg-deb --build "${stage}" /out' in script
    assert '-v "${out_abs}:/out"' in script
    assert 'deb_path="${out_abs}/${deb_name}"' in script


def test_rpm_version_mapping_is_registered() -> None:
    """RPM >= 4.10 uses ``~`` for "sorts before everything"; ``_semver_to_rpm``
    must delegate to ``_semver_to_debian`` rather than re-encode the rule."""
    script = _script()
    assert "_semver_to_rpm()" in script
    assert "_semver_to_debian \"$1\"" in script


def test_rpm_arch_mapping_is_64_bit_only() -> None:
    """RHEL/Rocky is 64-bit only: only x86_64 and aarch64 are mapped."""
    script = _script()
    assert 'x86_64|amd64)   echo "x86_64"' in script
    assert 'aarch64|arm64)  echo "aarch64"' in script


def test_rpm_targets_are_registered_in_dispatch() -> None:
    script = _script()
    assert "rpm)" in script
    assert "rpm-all)" in script
    assert "Supported targets:" in script
    assert "rpm-all" in script


def test_rpm_container_onedir_distpath_is_under_rpm_all() -> None:
    """The RPM container build writes its onedir under /build/rpm-all/<arch>."""
    script = _script()
    assert "_container_rpm_build_cmd() {" in script
    assert "-o /build/rpm-all/${rpm_arch}/pyinstaller" in script
    assert 'local bin_dir="${RPM_ALL_BUILD_DIR}/${rpm_arch}/pyinstaller"' in script


def test_windows_installer_is_wired() -> None:
    """The Inno Setup installer + WinSW service XML must exist and be built."""
    repo = COMPILE_SH.parent
    win = repo / "packaging" / "windows"
    assert (win / "hsync-bootnode.iss").is_file()
    assert (win / "hsync-bootnode-service-frozen.xml").is_file()
    workflow = (repo / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "hsync-bootnode.iss" in workflow
    assert "innosetup" in workflow


def test_docs_latest_download_names_are_created_by_the_release() -> None:
    """Every fixed-name asset the docs download from releases/latest/download must
    be created as an alias by the release workflow, so the link cannot 404. Names
    with the VERSION/ARCH placeholders are pinned examples, not aliases."""
    repo = COMPILE_SH.parent
    workflow = (repo / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    names: set[str] = set()
    for md in (repo / "docs").rglob("*.md"):
        for name in re.findall(r"releases/latest/download/([A-Za-z0-9._-]+)", md.read_text(encoding="utf-8")):
            if name.startswith(repo.name) and "VERSION" not in name and "ARCH" not in name:
                names.add(name)
    names -= {"install.sh", "SHA256SUMS"}
    assert names, "expected at least one fixed latest/download asset in the docs"
    missing = sorted(n for n in names if n not in workflow)
    assert not missing, f"docs reference latest aliases the workflow does not create: {missing}"
