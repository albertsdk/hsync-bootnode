"""Regression guard: Windows venv console-script layout in the build scripts.

Windows virtualenvs expose console scripts under ``Scripts/`` (with an ``.exe``
suffix), not ``bin/``. ``python/compile.sh`` hardcoded ``.venv/bin/pyinstaller``,
so the native Windows release build aborted with "PyInstaller not found" even
though Poetry had installed it: ``release.yml`` runs ``poetry install`` then the
build script without activating the venv, so the PATH fallback misses too.
``run.sh`` hardcoded the same ``bin/`` layout for the console script.

Consumers: hsync-bootnode maintainers (regression guard; the root build script
is covered separately by ``test_compile_script.py``).
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_PY_COMPILE = _ROOT / "python" / "compile.sh"
_RUN = _ROOT / "run.sh"


def test_pyinstaller_lookup_is_windows_aware() -> None:
    script = _PY_COMPILE.read_text(encoding="utf-8")
    assert 'if [[ "${OS_NAME}" == "windows" ]]; then' in script
    assert 'PYINSTALLER="${VENV_DIR}/Scripts/pyinstaller.exe"' in script
    assert 'PYINSTALLER="${VENV_DIR}/bin/pyinstaller"' in script


def test_pyinstaller_missing_hint_is_os_agnostic() -> None:
    script = _PY_COMPILE.read_text(encoding="utf-8")
    assert ".venv/bin/pip install pyinstaller" not in script
    assert "poetry install --with build" in script


def test_run_script_console_path_is_windows_aware() -> None:
    script = _RUN.read_text(encoding="utf-8")
    assert 'VENV_BIN_DIR="Scripts"' in script
    assert 'BIN_EXT=".exe"' in script
    assert 'readonly BIN="${PY_DIR}/.venv/${VENV_BIN_DIR}/hsync-bootnode${BIN_EXT}"' in script
