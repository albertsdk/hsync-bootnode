#!/usr/bin/env bash

# HSYNC bootnode — run from a fresh clone.
#
# Requires the hsync-common repository checked out as a sibling (the Python v1
# declares it as a Poetry path dependency). This script is the uniform
# "run after clone" entry point, mirroring hsync-server/run.sh: it creates (or
# reuses) the in-project virtualenv, installs the main dependencies once, and
# starts the node, forwarding any arguments to `hsync-bootnode`.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PY_DIR="${SCRIPT_DIR}/python"
readonly SIBLING="${SCRIPT_DIR}/../hsync-common"
readonly BIN="${PY_DIR}/.venv/bin/hsync-bootnode"

if [[ ! -d "${SIBLING}" ]]; then
    printf 'Error: hsync-common must be checked out as a sibling of hsync-bootnode.\n' >&2
    printf '  git clone <hsync-common-url> %s\n' "${SIBLING}" >&2
    exit 1
fi

if [[ ! -x "${BIN}" ]]; then
    command -v poetry >/dev/null 2>&1 || {
        printf 'Error: poetry is required to create the virtualenv.\n' >&2
        printf '  Install it (https://python-poetry.org/docs/#installation) or build the\n' >&2
        printf '  in-project venv yourself: cd python && poetry install --only main\n' >&2
        exit 1
    }
    printf 'Creating the in-project virtualenv (first run)…\n'
    (
        cd "${PY_DIR}"
        poetry config virtualenvs.in-project true
        poetry install --only main --no-interaction
    )
fi

exec "${BIN}" "$@"
