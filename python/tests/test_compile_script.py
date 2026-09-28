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
    only = re.search(r"--only\s+(\S+)", line)
    if only:
        # Inside --only the group list is exhaustive: --with cannot re-add it.
        return "build" in only.group(1).split(",")
    return "--without build" not in line and "--without=build" not in line


def test_guard_rejects_the_pruned_build_group() -> None:
    """The guard must fail on the pre-fix form and pass on the fixed one."""
    assert not _build_group_requested(_BROKEN)
    assert _build_group_requested(_FIXED)


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
