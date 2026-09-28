"""Guard for the container build commands in ``../compile.sh`` (decision #38).

Inside the cross-build containers the ``build`` group (PyInstaller) must be
requested with the syntax Poetry actually honours. With Poetry 2.x ``--only``
prunes every group not listed and a co-present ``--with`` is ignored, so
``poetry install --only main --with build`` installs no PyInstaller: the
container then falls back to the *host* ``.venv`` mounted into the tree and
``-t deb-all`` / ``-t rpi`` fail with ``cannot execute: required file not
found``. This module is a white-box guard: it asserts the invariant on the
script text, because exercising the real cross-build needs Docker, qemu and
network access.

Consumers: hsync-bootnode maintainers (regression guard for decision #38).
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
