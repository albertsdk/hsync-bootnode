#!/usr/bin/env bash
#
# HSYNC Bootnode - Python Build Script
#
# Builds the hsync-bootnode standalone executable from the Python sources
# using PyInstaller. Binaries only: the Debian/Ubuntu .deb packaging lives in
# the repository root (../compile.sh), which selects the implementation
# language (python or rust) and assembles the package. A script placed
# inside one implementation directory stays responsible for that language's
# binary only.
#
# Usage:
#   ./compile.sh [options]
#
# Options:
#   -c, --clean             Clean build artifacts before building
#   -t, --target TARGET     Build target (default: native)
#                           Supported:
#                               native    host OS / arch standalone binary
#                               onedir    onedir bundle; the payload consumed
#                                         by ../compile.sh for the .deb
#   -o, --output-dir DIR    Directory receiving the artifact (default:
#                           native → dist/<os>-<arch>/; onedir → dist/onedir/).
#                           For native the executable itself lands directly in
#                           DIR; for onedir the bundle directory <DIR>/<app>/.
#   -h, --help              Show this help message
#
# Requirements:
#   - Python virtual environment (.venv) with dependencies installed; run
#     'poetry install' in python/ before the first build (PyInstaller is
#     declared as the Poetry build dependency in pyproject.toml). In the
#     Docker deb build this script runs under `poetry run`, so a pyinstaller
#     found on PATH is accepted as fallback.
#
# Output:
#   native:  dist/<os>-<arch>/hsync-bootnode[.exe]
#            e.g. dist/linux-amd64/hsync-bootnode
#   onedir:  <output-dir>/hsync-bootnode/  (main binary inside the bundle)
#
# Author: Alberto Basso
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

# Script directory (resolves symlinks)
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Platform detection (OS + architecture)
# Normalize OS name: linux | darwin | windows
case "$(uname -s)" in
    Linux*)               readonly OS_NAME="linux" ;;
    Darwin*)              readonly OS_NAME="darwin" ;;
    MINGW*|CYGWIN*|MSYS*) readonly OS_NAME="windows" ;;
    *)                    readonly OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')" ;;
esac

# Normalize architecture: amd64 | arm64 | armv7 | x86 | ...
case "$(uname -m)" in
    x86_64|amd64)   readonly ARCH_NAME="amd64" ;;
    aarch64|arm64)  readonly ARCH_NAME="arm64" ;;
    armv7l|armv7)   readonly ARCH_NAME="armv7" ;;
    i386|i686)      readonly ARCH_NAME="x86" ;;
    *)              readonly ARCH_NAME="$(uname -m)" ;;
esac

readonly PLATFORM="${OS_NAME}-${ARCH_NAME}"

readonly APP_NAME="hsync-bootnode"
readonly ENTRY_POINT="src/hsync_bootnode/__main__.py"
readonly MODULE_PATHS="src"
readonly PYPROJECT="pyproject.toml"
readonly BIN_EXT="$([[ "${OS_NAME}" == "windows" ]] && echo ".exe" || echo "")"
readonly OUTPUT_BASE="dist"
readonly OUTPUT_DIR="${OUTPUT_BASE}/${PLATFORM}"
readonly ONEDIR_DEFAULT_DIR="${OUTPUT_BASE}/onedir"
readonly BUILD_DIR="build"
readonly VENV_DIR=".venv"
# PyInstaller binary: the in-project venv wins; a pyinstaller found on PATH is
# the fallback (see _resolve_pyinstaller). NOT readonly: it can be re-pointed.
PYINSTALLER="${VENV_DIR}/bin/pyinstaller"
# --strip needs binutils and is unreliable on Windows; omit it there.
readonly STRIP_FLAG="$([[ "${OS_NAME}" == "windows" ]] && echo "" || echo "--strip")"

# Colors (disabled if not a terminal)
if [[ -t 1 ]]; then
    readonly RED=$'\033[0;31m'
    readonly GREEN=$'\033[0;32m'
    readonly YELLOW=$'\033[0;33m'
    readonly BLUE=$'\033[0;34m'
    readonly CYAN=$'\033[0;36m'
    readonly BOLD=$'\033[1m'
    readonly DIM=$'\033[2m'
    readonly RESET=$'\033[0m'
else
    readonly RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' RESET=''
fi

# Logging functions
log_info() { echo -e "${BLUE}i${RESET} $*"; }
log_ok() { echo -e "${GREEN}OK${RESET} $*"; }
log_warn() { echo -e "${YELLOW}!${RESET} $*"; }
log_error() { echo -e "${RED}X${RESET} $*" >&2; }
log_step() { echo -e "${CYAN}>${RESET} ${BOLD}$*${RESET}"; }

# Display usage information
show_help() {
    cat << EOF
${BOLD}HSYNC Bootnode - Python Build Script${RESET}

${BOLD}Usage:${RESET}
    ./compile.sh [options]

${BOLD}Options:${RESET}
    -c, --clean             Clean build artifacts before building
    -t, --target TARGET     Build target (default: native)
                            Supported: native, onedir
    -o, --output-dir DIR    Directory receiving the artifact (default:
                            native → dist/<os>-<arch>/; onedir → dist/onedir/)
    -h, --help              Show this help message

${BOLD}Examples:${RESET}
    ./compile.sh                                  # standalone binary (host)
    ./compile.sh -t onedir                        # onedir bundle (packaging)
    ./compile.sh -t onedir -o build/deb/pyinstaller

${BOLD}Output:${RESET}
    native:  ${OUTPUT_DIR}/${APP_NAME}${BIN_EXT}   (platform: ${PLATFORM})
    onedir:  <output-dir>/${APP_NAME}/
EOF
}

# Clean build artifacts
clean_artifacts() {
    log_step "Cleaning build artifacts..."
    local cleaned=0
    if [[ -d "${BUILD_DIR}" ]]; then
        rm -rf "${BUILD_DIR}"
        ((cleaned++))
    fi
    if [[ -d "${OUTPUT_BASE}" ]]; then
        rm -rf "${OUTPUT_BASE}"
        ((cleaned++))
    fi
    if [[ -f "${APP_NAME}.spec" ]]; then
        rm -f "${APP_NAME}.spec"
        ((cleaned++))
    fi
    if [[ ${cleaned} -gt 0 ]]; then
        log_ok "Cleaned ${cleaned} artifact(s)"
    else
        log_info "No artifacts to clean"
    fi
}

# Resolve the PyInstaller executable: in-project venv first, PATH fallback
# (the Docker build runs this script under `poetry run`, where the container
# venv is already first on PATH but the mounted host .venv still exists).
# HSYNC_PREFER_PATH_PYINSTALLER=1 forces the PATH lookup first: inside a
# cross-build container the mounted .venv belongs to the host architecture and
# must not shadow the container's own PyInstaller.
_resolve_pyinstaller() {
    if [[ "${HSYNC_PREFER_PATH_PYINSTALLER:-0}" == "1" ]] \
        && command -v pyinstaller >/dev/null 2>&1; then
        PYINSTALLER="$(command -v pyinstaller)"
        return 0
    fi
    [[ -x "${PYINSTALLER}" ]] && return 0
    if command -v pyinstaller >/dev/null 2>&1; then
        PYINSTALLER="$(command -v pyinstaller)"
        return 0
    fi
    return 1
}

# Check prerequisites
check_prerequisites() {
    if [[ ! -f "${PYPROJECT}" ]]; then
        log_error "${PYPROJECT} not found. Run this script from the python/ directory."
        exit 1
    fi
    if [[ ! -f "${ENTRY_POINT}" ]]; then
        log_error "Entry point not found: ${ENTRY_POINT}"
        exit 1
    fi
    if ! _resolve_pyinstaller; then
        log_error "PyInstaller not found at ${PYINSTALLER} and not on PATH."
        log_info "Install it with: .venv/bin/pip install pyinstaller"
        exit 1
    fi
    log_info "PyInstaller: ${PYINSTALLER}"
}

# Version override, settable via the HSYNC_VERSION environment variable
# (../compile.sh passes -v/--version through; binaries only log it).
VERSION_OVERRIDE=""
get_version() {
    if [[ -n "${VERSION_OVERRIDE}" ]]; then
        printf '%s' "${VERSION_OVERRIDE}"
    elif [[ -n "${HSYNC_VERSION:-}" ]]; then
        printf '%s' "${HSYNC_VERSION}"
    else
        grep -E '^version\s*=' "${PYPROJECT}" | head -1 | sed 's/.*"\(.*\)".*/\1/'
    fi
}

# PyInstaller flag set shared by the native and onedir builds. Word-split by
# the caller (unquoted expansion); never interpolated inside bash -c strings.
_pyi_flags() {
    local flags="--clean --noconfirm"
    if [[ -n "${STRIP_FLAG}" ]]; then
        flags+=" --strip"
    fi
    flags+=" --name ${APP_NAME}"
    flags+=" --log-level ERROR"
    # The package is a src-layout: static analysis needs src on the module
    # path to resolve hsync_bootnode/hsync_common imports.
    flags+=" --paths ${MODULE_PATHS}"
    flags+=" --collect-submodules hsync_bootnode"
    flags+=" --collect-submodules hsync_common"
    flags+=" --collect-submodules aioquic"
    flags+=" --exclude-module pytest --exclude-module pytest_asyncio"
    flags+=" --exclude-module pytest_cov --exclude-module tkinter"
    flags+=" --exclude-module unittest --exclude-module pdb"
    flags+=" --exclude-module doctest --exclude-module pip"
    flags+=" --exclude-module setuptools --exclude-module wheel"
    flags+=" --exclude-module pkg_resources"
    # Dev-only packages installed in the same venv (mypy pulls mypy_extensions;
    # PyInstaller follows the import graph otherwise). Kept in sync with the
    # dev group in pyproject.toml: pytest*, ruff, mypy.
    flags+=" --exclude-module mypy --exclude-module mypy_extensions"
    flags+=" --exclude-module ruff"
    printf '%s' "${flags}"
}

# Build the standalone single-file executable (PyInstaller --onefile).
# HSYNC_PYINSTALLER_WORKPATH, when set, relocates both --workpath and
# --specpath; the root compile.sh sets it for the rpi cross-build so the
# host-mounted source tree stays pristine (intermediates go to /tmp).
build_binary() {
    local version distpath workpath_flag="" specpath_flag=""
    version="$(get_version)"
    distpath="${OUTPUT_DIR_OVERRIDE:-${OUTPUT_DIR}}"
    mkdir -p "${distpath}"
    if [[ -n "${HSYNC_PYINSTALLER_WORKPATH:-}" ]]; then
        mkdir -p "${HSYNC_PYINSTALLER_WORKPATH}"
        workpath_flag="--workpath ${HSYNC_PYINSTALLER_WORKPATH}"
        specpath_flag="--specpath ${HSYNC_PYINSTALLER_WORKPATH}"
    fi
    log_step "Building ${APP_NAME} v${version} for ${PLATFORM} into ${distpath}..."
    LC_ALL=C PYTHONWARNINGS=ignore "${PYINSTALLER}" --onefile --distpath "${distpath}" ${workpath_flag} ${specpath_flag} $(_pyi_flags) "${ENTRY_POINT}"
    local bin_path="${distpath}/${APP_NAME}${BIN_EXT}"
    if [[ -f "${bin_path}" ]]; then
        local size
        size="$(du -h "${bin_path}" | cut -f1)"
        cleanup_temp_files
        echo
        log_ok "Build successful!"
        echo
        echo -e "  ${BOLD}Binary:${RESET}   ${bin_path}"
        echo -e "  ${BOLD}Platform:${RESET} ${PLATFORM}"
        echo -e "  ${BOLD}Size:${RESET}     ${size}"
        echo -e "  ${BOLD}Version:${RESET}  ${version}"
        echo
        echo -e "${DIM}Run with: ${bin_path} --version${RESET}"
    else
        log_error "Build failed: output binary not found at ${bin_path}"
        exit 1
    fi
}

# Build the onedir bundle consumed by ../compile.sh for the .deb payload.
# HSYNC_PYINSTALLER_WORKPATH, when set, relocates --workpath/--specpath exactly
# like the native build; the container builds set it so the host-mounted source
# tree stays pristine (intermediates go to /tmp/work).
build_onedir() {
    local version distpath workpath bundle
    version="$(get_version)"
    distpath="${OUTPUT_DIR_OVERRIDE:-${ONEDIR_DEFAULT_DIR}}"
    workpath="${HSYNC_PYINSTALLER_WORKPATH:-${BUILD_DIR}/onedir-work}"
    mkdir -p "${distpath}" "${workpath}"
    log_step "Building ${APP_NAME} v${version} onedir bundle into ${distpath}..."
    LC_ALL=C PYTHONWARNINGS=ignore "${PYINSTALLER}" --onedir --distpath "${distpath}" --workpath "${workpath}" --specpath "${workpath}" $(_pyi_flags) "${ENTRY_POINT}"
    bundle="${distpath}/${APP_NAME}"
    if [[ ! -d "${bundle}" ]]; then
        log_error "Build failed: onedir bundle not found at ${bundle}"
        exit 1
    fi
    log_ok "onedir bundle ready: ${bundle}"
}

# Clean up temporary files after a successful native build
cleanup_temp_files() {
    log_step "Cleaning up temporary files..."
    local cleaned=0
    if [[ -d "${BUILD_DIR}" ]]; then
        rm -rf "${BUILD_DIR}"
        ((cleaned++)) || true
    fi
    if [[ -f "${APP_NAME}.spec" ]]; then
        rm -f "${APP_NAME}.spec"
        ((cleaned++)) || true
    fi
    if [[ ${cleaned} -gt 0 ]]; then
        log_ok "Removed ${cleaned} temporary file(s)"
    fi
}

main() {
    local do_clean=false
    local target="native"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--clean)
                do_clean=true
                shift
                ;;
            -t|--target)
                [[ $# -ge 2 ]] || { log_error "--target requires a value"; exit 1; }
                target="$2"
                shift 2
                ;;
            -o|--output-dir)
                [[ $# -ge 2 ]] || { log_error "--output-dir requires a value"; exit 1; }
                OUTPUT_DIR_OVERRIDE="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information."
                exit 1
                ;;
        esac
    done

    cd "${SCRIPT_DIR}"

    echo -e "${BOLD}HSYNC Bootnode - Python Build${RESET}"
    echo -e "${DIM}────────────────────────${RESET}"
    echo

    case "${target}" in
        native)
            check_prerequisites
            if [[ "${do_clean}" == true ]]; then
                clean_artifacts
                echo
            fi
            build_binary
            ;;
        onedir)
            check_prerequisites
            if [[ "${do_clean}" == true ]]; then
                clean_artifacts
                echo
            fi
            build_onedir
            ;;
        *)
            log_error "Unknown target: ${target}"
            echo "Supported targets: native, onedir"
            exit 1
            ;;
    esac
}

main "$@"
