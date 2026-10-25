"""Debian maintainer scripts: the service lifecycle across install, upgrade, purge.

An upgrade must not silently turn the node off: the unit is stopped so the
executable can be replaced, then brought back only when the administrator had
enabled it. Enablement itself is never automatic — starting at boot stays the
operator's decision.
"""

from __future__ import annotations

import re
from pathlib import Path

DEBIAN = Path(__file__).resolve().parents[2] / "packaging" / "deb" / "DEBIAN"
PRERM = DEBIAN / "prerm"
POSTINST = DEBIAN / "postinst"
SERVICE = "hsync-bootnode.service"


def _script(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh"), f"{path.name} must stay a POSIX shell script"
    return text


def _branch(script: str, label: str) -> str:
    """Text of one ``case`` branch, from its label to the terminating ``;;``."""
    match = re.search(rf"^\s*{re.escape(label)}\)\s*$(.*?);;$", script, re.MULTILINE | re.DOTALL)
    assert match is not None, f"case branch {label!r} not found"
    return match.group(1)


def test_prerm_stops_without_disabling_on_upgrade() -> None:
    """The replaced executable needs the service stopped, not the admin's choice undone."""
    upgrade = _branch(_script(PRERM), "upgrade|failed-upgrade")
    assert 'systemctl stop "${SERVICE}"' in upgrade
    assert "disable" not in upgrade


def test_prerm_disables_on_removal() -> None:
    removal = _branch(_script(PRERM), "remove|deconfigure")
    assert "systemctl stop" in removal
    assert "systemctl disable" in removal


def _systemctl_calls(script: str) -> list[str]:
    """The script's own systemctl invocations (echoed hints are not commands)."""
    return [line.strip() for line in script.splitlines() if line.strip().startswith("systemctl")]


def test_postinst_never_enables_the_service() -> None:
    """Enablement stays the administrator's opt-in: only a reload and a restart."""
    calls = _systemctl_calls(_script(POSTINST))
    assert any("daemon-reload" in call for call in calls), calls
    assert not any(re.match(r"systemctl\s+enable\b", call) for call in calls), calls


def test_postinst_restarts_only_an_enabled_service() -> None:
    """The upgrade path restores what the administrator had enabled, nothing more."""
    script = _script(POSTINST)
    assert "systemctl daemon-reload" in script
    guard = re.search(rf"if systemctl is-enabled --quiet {re.escape(SERVICE)}", script)
    assert guard is not None, "postinst must guard the start on the enablement state"
    assert f"systemctl start {SERVICE}" in script[guard.end() :]


def test_postinst_provisions_the_metrics_token_as_a_secret() -> None:
    """The unit's LoadCredential= needs the source, and an empty file means "off"."""
    script = _script(POSTINST)
    assert 'METRICS_TOKEN_FILE="${KEYS_DIR}/metrics-token"' in script
    assert 'chmod 0600 "${METRICS_TOKEN_FILE}"' in script
    # It is provisioned empty: writing a token is the operator's opt-in.
    assert ': > "${METRICS_TOKEN_FILE}"' in script
