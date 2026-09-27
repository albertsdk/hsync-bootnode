#!/usr/bin/env bash
#
# HSYNC Bootnode - Debian/Ubuntu .deb Build Script
#
# Assembles the Debian/Ubuntu .deb package(s) of the bootnode. This script
# (repository root) selects WHICH implementation language the embedded
# executable is built from and delegates the binary build to the matching
# per-language script; the per-language scripts build binaries only.
#
#   python → python/compile.sh -t onedir -o <distpath>   (implemented)
#   rust   → planned v2 port of the same boot/1 protocol (not yet available)
#
# Usage:
#   ./compile_deb.sh [options]
#
# Options:
#   -c, --clean             Clean .deb build artifacts before building
#   -t, --target TARGET     Build target (default: deb)
#                           Supported:
#                               deb       .deb for the host architecture
#                               deb-all   .deb for amd64, arm64 and armhf
#                                         (via Docker)
#   -l, --language LANG     Implementation language of the executable
#                           (default: python). Values:
#                               python    current bootnode (implemented)
#                               rust      planned v2 port — not yet available
#                           Also settable via the DEB_LANGUAGE environment
#                           variable (the CLI flag takes precedence).
#   -v, --version VERSION   Override the version used for packages (default:
#                           the selected language's project file — for python
#                           python/pyproject.toml). Also settable via the
#                           HSYNC_VERSION environment variable. A prerelease
#                           (e.g. 1.2.0-alpha.1) is translated to the Debian
#                           form (1.2.0~alpha.1).
#   -h, --help              Show this help message
#
# Requirements:
#   - deb target: the selected language's toolchain (for python: the
#     committed python/.venv with PyInstaller) + dpkg-deb (dpkg-dev);
#     fakeroot optional
#   - deb-all: Docker with qemu-user-static (binfmt) configured
#
# Output:
#   deb:      dist/deb/hsync-bootnode_<ver>_<arch>.deb
#             Installable with dpkg -i / apt install
#   deb-all:  dist/deb/hsync-bootnode_<ver>_{amd64,arm64,armhf}.deb
#
# Author: Alberto Basso
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Host platform (used by the deb target; deb-all always cross-builds)
case "$(uname -s)" in
    Linux*)               readonly OS_NAME="linux" ;;
    Darwin*)              readonly OS_NAME="darwin" ;;
    MINGW*|CYGWIN*|MSYS*) readonly OS_NAME="windows" ;;
    *)                    readonly OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')" ;;
esac
case "$(uname -m)" in
    x86_64|amd64)   readonly ARCH_NAME="amd64" ;;
    aarch64|arm64)  readonly ARCH_NAME="arm64" ;;
    armv7l|armv7)   readonly ARCH_NAME="armv7" ;;
    i386|i686)      readonly ARCH_NAME="x86" ;;
    *)              readonly ARCH_NAME="$(uname -m)" ;;
esac
readonly PLATFORM="${OS_NAME}-${ARCH_NAME}"

readonly APP_NAME="hsync-bootnode"
readonly PYTHON_DIR="python"
readonly PYPROJECT="${PYTHON_DIR}/pyproject.toml"
readonly DEB_DIR="packaging/deb"
readonly DEB_SRC_CONTROL="${DEB_DIR}/DEBIAN"
readonly DEB_SRC_DATA="${DEB_DIR}"
readonly DEB_PKG_NAME="${APP_NAME}"
readonly OUTPUT_BASE="dist"
readonly DEB_OUTPUT_DIR="${OUTPUT_BASE}/deb"
readonly BUILD_DIR="build"
readonly DEB_BUILD_DIR="${BUILD_DIR}/deb"
readonly DEB_ALL_BUILD_DIR="${BUILD_DIR}/deb-all"
readonly DEB_ALL_BUILDER_IMAGE_PREFIX="hsync-bootnode-deb-builder"

# -----------------------------------------------------------------------------
# Package language — which implementation the .deb's executable is built from
# -----------------------------------------------------------------------------
# The dispatcher below delegates the binary build to the per-language script;
# add a new language by extending validate_language() and the two case blocks
# in _build_binary() / _container_build_cmd(). Precedence: --language flag >
# DEB_LANGUAGE env > "python".
readonly DEB_LANGUAGE_DEFAULT="python"
DEB_LANGUAGE="${DEB_LANGUAGE:-${DEB_LANGUAGE_DEFAULT}}"

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

# Report whether a binfmt_misc handler exists and is enabled.
# $1 = handler name (e.g. qemu-arm, qemu-aarch64)
qemu_handler_active() {
    [[ -d "/proc/sys/fs/binfmt_misc" ]] || return 1
    local f="/proc/sys/fs/binfmt_misc/$1"
    [[ -f "${f}" ]] && grep -q '^enabled' "${f}"
}

# Ensure the qemu-user-static binfmt handlers required for cross-arch Docker
# builds are registered and active. $@ = required handler names.
ensure_qemu_binfmt() {
    local handlers=("$@")
    [[ ${#handlers[@]} -eq 0 ]] && handlers=("qemu-arm")
    log_step "Ensuring qemu-user-static binfmt handlers are active: ${handlers[*]}"
    local missing=()
    local h
    for h in "${handlers[@]}"; do
        qemu_handler_active "${h}" || missing+=("${h}")
    done
    if [[ ${#missing[@]} -eq 0 ]]; then
        log_ok "binfmt handlers already active"
        return 0
    fi
    log_info "Registering qemu-user-static binfmt handlers..."
    if ! docker run --rm --privileged multiarch/qemu-user-static --reset -p yes >/dev/null 2>&1; then
        log_error "Failed to run multiarch/qemu-user-static (is the Docker daemon reachable?)."
        exit 1
    fi
    missing=()
    for h in "${handlers[@]}"; do
        qemu_handler_active "${h}" || missing+=("${h}")
    done
    if [[ ${#missing[@]} -ne 0 ]]; then
        log_error "binfmt handlers still inactive after registration: ${missing[*]}"
        log_error "Cross-arch emulation is unavailable; aborting now to avoid a"
        log_error "misleading 'exec format error' later in the build."
        exit 1
    fi
    log_ok "binfmt handlers registered and active"
}

# Display usage information
show_help() {
    cat << EOF
${BOLD}HSYNC Bootnode - Debian/Ubuntu .deb Build Script${RESET}

${BOLD}Usage:${RESET}
    ./compile_deb.sh [options]

${BOLD}Options:${RESET}
    -c, --clean              Clean .deb build artifacts before building
    -t, --target TARGET      Build target (default: deb)
                             Supported: deb, deb-all
    -l, --language LANGUAGE  Implementation language of the executable
                             (default: python). Supported: python, rust
    -v, --version VERSION    Override the package version (default: the
                             selected language's project file; python reads
                             python/pyproject.toml). Also settable via
                             HSYNC_VERSION.
    -h, --help               Show this help message

${BOLD}Examples:${RESET}
    ./compile_deb.sh                                  # .deb for the host arch
    ./compile_deb.sh --clean                          # clean and rebuild
    ./compile_deb.sh -t deb-all                       # amd64, arm64, armhf
    ./compile_deb.sh -l python -t deb                 # explicit language
    DEB_LANGUAGE=rust ./compile_deb.sh -t deb         # rejected until the
                                                      # Rust port exists

${BOLD}Output:${RESET}
    deb:      ${DEB_OUTPUT_DIR}/${DEB_PKG_NAME}_<ver>_<arch>.deb
    deb-all:  ${DEB_OUTPUT_DIR}/${DEB_PKG_NAME}_<ver>_{amd64,arm64,armhf}.deb
EOF
}

# Clean .deb build artifacts (staging trees and built packages)
clean_artifacts() {
    log_step "Cleaning .deb build artifacts..."
    local cleaned=0
    if [[ -d "${DEB_OUTPUT_DIR}" ]]; then
        rm -rf "${DEB_OUTPUT_DIR}"
        ((cleaned++))
    fi
    if [[ -d "${DEB_BUILD_DIR}" ]]; then
        rm -rf "${DEB_BUILD_DIR}"
        ((cleaned++))
    fi
    if [[ -d "${DEB_ALL_BUILD_DIR}" ]]; then
        rm -rf "${DEB_ALL_BUILD_DIR}"
        ((cleaned++))
    fi
    if [[ ${cleaned} -gt 0 ]]; then
        log_ok "Cleaned ${cleaned} artifact dir(s)"
    else
        log_info "No artifacts to clean"
    fi
}

# Version override, set by --version and/or the HSYNC_VERSION environment
# variable. Mutable (not readonly) so main() can assign it.
VERSION_OVERRIDE=""
get_version() {
    if [[ -n "${VERSION_OVERRIDE}" ]]; then
        printf '%s' "${VERSION_OVERRIDE}"
    elif [[ -n "${HSYNC_VERSION:-}" ]]; then
        printf '%s' "${HSYNC_VERSION}"
    else
        case "${DEB_LANGUAGE}" in
            python) grep -E '^version\s*=' "${PYPROJECT}" | head -1 | sed 's/.*"\(.*\)".*/\1/' ;;
        esac
    fi
}

# Translate a SemVer version into a Debian policy version so a prerelease
# sorts before the stable release: 1.2.0-alpha.1 -> 1.2.0~alpha.1.
_semver_to_debian() {
    printf '%s' "$1" | sed 's/-/~/'
}

# Map uname -m to Debian architecture name.
_arch_to_deb() {
    case "$1" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        armv7l|armv7)   echo "armhf" ;;
        *)              echo "$1" ;;
    esac
}

# Fail fast if the selected implementation language has no packaging path yet.
# When the Rust port lands, extend this function and the two dispatchers
# (_build_binary / _container_build_cmd).
validate_language() {
    case "${DEB_LANGUAGE}" in
        python) ;;  # implemented today
        rust)
            log_error "language 'rust' is not yet available (planned v2 port)."
            log_info "Use --language python (or unset DEB_LANGUAGE) for now."
            exit 1
            ;;
        *)
            log_error "unknown language: ${DEB_LANGUAGE}"
            echo "Supported languages: python (rust is planned)"
            exit 1
            ;;
    esac
}

# Build the onedir executable payload with the selected language's toolchain.
# Each implementation directory owns its binary build; this dispatcher only
# fixes the CONTRACT: the bundle must land at <distpath>/<APP_NAME>/.
# $1 = distpath (absolute) receiving the <APP_NAME>/ bundle directory.
_build_binary() {
    local distpath="$1"
    case "${DEB_LANGUAGE}" in
        python)
            ( cd "${SCRIPT_DIR}/${PYTHON_DIR}" && ./compile.sh -t onedir -o "${distpath}" )
            ;;
        *)
            validate_language
            ;;
    esac
    if [[ ! -d "${distpath}/${APP_NAME}" ]]; then
        log_error "onedir bundle not found at ${distpath}/${APP_NAME}"
        exit 1
    fi
}

# In-container command producing the onedir bundle for $1 (deb_arch). The
# bundle MUST land at build/deb-all/<arch>/pyinstaller/<APP_NAME> (paths are
# relative to the container workdir /repo/hsync-bootnode/python).
_container_build_cmd() {
    local deb_arch="$1"
    case "${DEB_LANGUAGE}" in
        python)
            printf '%s' "poetry install --only main --with build && poetry run ./compile.sh -t onedir -o build/deb-all/${deb_arch}/pyinstaller"
            ;;
        *)
            validate_language
            ;;
    esac
}

# Normalise a staged .deb payload so the resulting package is lintian-clean:
#   * root and directories 0755 / files 0644 under etc/ and usr/;
#   * the main executable keeps its 0755 bit;
#   * the man page is gzip-compressed (-n => reproducible header).
# /etc/hsync-bootnode (group-keys dir) is NOT shipped: postinst creates it.
_finalize_deb_stage() {
    local stage_dir="$1"
    chmod 0755 "${stage_dir}"
    find "${stage_dir}/etc" "${stage_dir}/usr" -type d -exec chmod 0755 {} + 2>/dev/null || true
    find "${stage_dir}/etc" "${stage_dir}/usr" -type f -exec chmod 0644 {} + 2>/dev/null || true
    chmod 0755 "${stage_dir}/usr/lib/${APP_NAME}/${APP_NAME}"
    local man="${stage_dir}/usr/share/man/man1/${APP_NAME}.1"
    [[ -f "${man}" ]] && gzip -n -9 -f "${man}"
    return 0
}

# Compute the shared-library dependency string for the staged main executable
# using dpkg-shlibdeps (e.g. "libc6 (>= 2.36)"); empty if unavailable. Must
# run in the target architecture's dpkg environment: on the host for
# build_deb, inside the per-arch container for build_deb_all.
# $1 = stage_dir
_compute_shlib_depends() {
    local stage_dir="$1"
    local bin="${stage_dir}/usr/lib/${APP_NAME}/${APP_NAME}"
    command -v dpkg-shlibdeps >/dev/null 2>&1 || { echo ""; return 0; }
    [[ -f "${bin}" ]] || { echo ""; return 0; }
    local tmp deps
    tmp="$(mktemp -d)"
    mkdir -p "${tmp}/debian"
    printf 'Source: %s\n\nPackage: %s\nArchitecture: any\n' "${DEB_PKG_NAME}" "${DEB_PKG_NAME}" > "${tmp}/debian/control"
    deps="$(cd "${tmp}" && dpkg-shlibdeps -O --ignore-missing-info "${bin}" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')"
    rm -rf "${tmp}"
    echo "${deps}"
}

# Append the computed shared-library dependencies to the Depends: line of the
# staged DEBIAN/control. No-op (with a warning) if none could be computed.
# $1 = stage_dir
_inject_shlib_depends() {
    local stage_dir="$1"
    local deps
    deps="$(_compute_shlib_depends "${stage_dir}")"
    if [[ -z "${deps}" ]]; then
        log_warn "dpkg-shlibdeps unavailable; libc6 dependency not added to control"
        return 0
    fi
    log_step "Adding shared-library dependencies: ${deps}"
    sed -i.bak "s/^Depends: \(.*\)$/Depends: \1, ${deps}/" "${stage_dir}/DEBIAN/control"
    rm -f "${stage_dir}/DEBIAN/control.bak"
}

# Build a .deb package for the host architecture (no Docker).
build_deb() {
    local version deb_version deb_arch
    version="$(get_version)"
    deb_version="$(_semver_to_debian "${version}")"
    deb_arch="$(_arch_to_deb "${ARCH_NAME}")"
    log_step "Building ${DEB_PKG_NAME} v${version} for ${deb_arch} (host build)..."
    if ! command -v dpkg-deb >/dev/null 2>&1; then
        log_error "dpkg-deb is required for the deb target."
        log_info "Install it with: apt install dpkg-dev"
        exit 1
    fi
    mkdir -p "${DEB_OUTPUT_DIR}" "${DEB_BUILD_DIR}"

    # --- onedir bundle via the language dispatcher ------------------------
    # Absolute distpath: python/compile.sh resolves -o relative to its own cwd.
    local bin_distpath="${DEB_BUILD_DIR}/pyinstaller"
    log_step "Building the ${DEB_LANGUAGE} executable payload..."
    _build_binary "$(pwd)/${bin_distpath}"
    local built_dir="${bin_distpath}/${APP_NAME}"

    # --- stage .deb tree ---------------------------------------------------
    local stage_dir="${DEB_BUILD_DIR}/${DEB_PKG_NAME}_${deb_version}_${deb_arch}"
    rm -rf "${stage_dir}"
    mkdir -p "${stage_dir}"
    log_step "Staging .deb tree at ${stage_dir}..."
    cp -a "${DEB_SRC_CONTROL}" "${stage_dir}/"
    chmod 0755 "${stage_dir}/DEBIAN"/*inst* "${stage_dir}/DEBIAN"/*rm* 2>/dev/null || true
    local item bn
    for item in "${DEB_SRC_DATA}"/*; do
        bn="$(basename "${item}")"
        if [[ "${bn}" == "DEBIAN" || "${bn}" == "Dockerfile.builder" ]]; then
            continue
        fi
        cp -a "${item}" "${stage_dir}/"
    done
    mkdir -p "${stage_dir}/usr/lib"
    cp -a "${built_dir}" "${stage_dir}/usr/lib/${APP_NAME}"
    chmod 0755 "${stage_dir}/usr/lib/${APP_NAME}/${APP_NAME}"
    mkdir -p "${stage_dir}/usr/bin"
    ln -sf "../lib/${APP_NAME}/${APP_NAME}" "${stage_dir}/usr/bin/${APP_NAME}"
    _finalize_deb_stage "${stage_dir}"

    # --- inject version / arch into control --------------------------------
    log_step "Injecting version ${deb_version} and arch ${deb_arch} into control..."
    sed -i.bak -e "s/__VERSION__/${deb_version}/g" -e "s/__ARCH__/${deb_arch}/g" "${stage_dir}/DEBIAN/control"
    rm -f "${stage_dir}/DEBIAN/control.bak"
    _inject_shlib_depends "${stage_dir}"

    # --- build .deb with dpkg-deb ------------------------------------------
    log_step "Building .deb package..."
    local deb_cmd=""
    if command -v fakeroot >/dev/null 2>&1; then
        deb_cmd="fakeroot"
    else
        log_warn "fakeroot not available — building .deb with current user ownership"
    fi
    ${deb_cmd} dpkg-deb --build "${stage_dir}" "${DEB_OUTPUT_DIR}"

    local deb_name="${DEB_PKG_NAME}_${deb_version}_${deb_arch}.deb"
    local deb_path="${DEB_OUTPUT_DIR}/${deb_name}"
    local size deb_abs
    size="$(du -h "${deb_path}" | cut -f1)"
    deb_abs="$(cd "$(dirname "${deb_path}")" && pwd)/$(basename "${deb_path}")"
    rm -rf "${DEB_BUILD_DIR}/pyinstaller" 2>/dev/null || true

    echo
    log_ok "Debian package built!"
    echo
    echo -e "  ${BOLD}Package:${RESET}  ${deb_name}"
    echo -e "  ${BOLD}Language:${RESET} ${DEB_LANGUAGE}"
    echo -e "  ${BOLD}Arch:${RESET}     ${deb_arch}"
    echo -e "  ${BOLD}Size:${RESET}     ${size}"
    echo -e "  ${BOLD}Version:${RESET}  ${deb_version}"
    echo
    echo -e "${DIM}Install with:  sudo dpkg -i ${deb_abs}${RESET}"
    echo
    local sep="────────────────────────────────────────────────────────────"
    echo -e "${GREEN}${BOLD}${sep}${RESET}"
    echo -e "${GREEN}${BOLD}  Installation package:${RESET}"
    echo -e "${GREEN}${BOLD}      ${deb_abs}${RESET}"
    echo -e "${GREEN}${BOLD}${sep}${RESET}"
}

# Build .deb packages for all 3 Debian/Ubuntu architectures (amd64, arm64,
# armhf) via Docker cross-builds — one build per arch:
#   amd64 → amd64/debian:bookworm
#   arm64 → arm64v8/debian:bookworm
#   armhf → arm32v7/debian:bookworm
# Output: dist/deb/hsync-bootnode_<ver>_<arch>.deb
build_deb_all() {
    local version deb_version
    version="$(get_version)"
    deb_version="$(_semver_to_debian "${version}")"
    log_step "Building ${DEB_PKG_NAME} v${version} for all 3 Debian/Ubuntu architectures..."
    if [[ ! -d "${DEB_SRC_CONTROL}" ]]; then
        log_error "DEBIAN control directory missing: ${DEB_SRC_CONTROL}"
        exit 1
    fi
    mkdir -p "${DEB_OUTPUT_DIR}"

    # Monorepo root: mounts hsync-bootnode AND hsync-common (the Poetry path
    # dependency) into the container at /repo.
    local repo_root
    repo_root="$(cd "${SCRIPT_DIR}/.." && pwd)"

    ensure_qemu_binfmt qemu-aarch64 qemu-arm

    local -A arch_docker_platform
    local -A arch_base_image
    arch_docker_platform["amd64"]="linux/amd64"
    arch_base_image["amd64"]="amd64/debian:bookworm"
    arch_docker_platform["arm64"]="linux/arm64"
    arch_base_image["arm64"]="arm64v8/debian:bookworm"
    arch_docker_platform["armhf"]="linux/arm/v7"
    arch_base_image["armhf"]="arm32v7/debian:bookworm"

    local -a deb_archs=("amd64" "arm64" "armhf")
    local out_abs
    out_abs="$(cd "${DEB_OUTPUT_DIR}" && pwd)"

    # Container-side staging script: everything is relative to the mounted
    # /repo/hsync-bootnode/python workdir, so it is arch-independent.
    local stage_script
    stage_script=$(cat <<'EOS'
set -eux
deb_arch="$1"; deb_version="$2"; host_uid="$3"; host_gid="$4"
APP_NAME=hsync-bootnode
stage="build/deb-all/${deb_arch}/stage"
built="build/deb-all/${deb_arch}/pyinstaller/${APP_NAME}"
rm -rf "${stage}"
mkdir -p "${stage}"
cp -a ../packaging/deb/DEBIAN "${stage}/"
chmod 0755 "${stage}/DEBIAN"/*inst* "${stage}/DEBIAN"/*rm* 2>/dev/null || true
for item in ../packaging/deb/*; do
    bn="$(basename "${item}")"
    if [ "${bn}" = "DEBIAN" ] || [ "${bn}" = "Dockerfile.builder" ]; then continue; fi
    cp -a "${item}" "${stage}/"
done
chmod 0755 "${stage}"
mkdir -p "${stage}/usr/lib"
cp -a "${built}" "${stage}/usr/lib/${APP_NAME}"
find "${stage}/usr" -type d -exec chmod 0755 {} +
find "${stage}/usr" -type f -exec chmod 0644 {} +
chmod 0755 "${stage}/usr/lib/${APP_NAME}/${APP_NAME}"
mkdir -p "${stage}/usr/bin"
ln -sf "../lib/${APP_NAME}/${APP_NAME}" "${stage}/usr/bin/${APP_NAME}"
man="${stage}/usr/share/man/man1/${APP_NAME}.1"
[ -f "${man}" ] && gzip -n -9 -f "${man}"
sed -i -e "s/__VERSION__/${deb_version}/g" -e "s/__ARCH__/${deb_arch}/g" "${stage}/DEBIAN/control"
bin="${stage}/usr/lib/${APP_NAME}/${APP_NAME}"
if command -v dpkg-shlibdeps >/dev/null 2>&1; then
    tmp="$(mktemp -d)"
    mkdir -p "${tmp}/debian"
    printf 'Source: %s\n\nPackage: %s\nArchitecture: any\n' "${APP_NAME}" "${APP_NAME}" > "${tmp}/debian/control"
    deps="$(cd "${tmp}" && dpkg-shlibdeps -O --ignore-missing-info "${bin}" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')"
    rm -rf "${tmp}"
    if [ -n "${deps}" ]; then
        sed -i "s/^Depends: \(.*\)$/Depends: \1, ${deps}/" "${stage}/DEBIAN/control"
        echo "Added shared-library dependencies: ${deps}"
    else
        echo 'WARNING: dpkg-shlibdeps resolved no dependencies' >&2
    fi
fi
fakeroot dpkg-deb --build "${stage}" dist/deb
chmod 0644 "dist/deb/${APP_NAME}_${deb_version}_${deb_arch}.deb"
chown -R "${host_uid}:${host_gid}" build "dist/deb/${APP_NAME}_${deb_version}_${deb_arch}.deb"
EOS
)

    for deb_arch in "${deb_archs[@]}"; do
        local docker_platform="${arch_docker_platform[${deb_arch}]}"
        local base_image="${arch_base_image[${deb_arch}]}"
        local builder_tag="${DEB_ALL_BUILDER_IMAGE_PREFIX}:${deb_arch}"
        local bin_dir="${DEB_ALL_BUILD_DIR}/${deb_arch}/pyinstaller"
        local work_dir="${DEB_ALL_BUILD_DIR}/${deb_arch}/work"
        mkdir -p "${bin_dir}" "${work_dir}"
        echo
        log_step "─── ${deb_arch} build ───────────────────────────────────────"

        log_step "Building Docker image ${builder_tag}..."
        docker build --platform "${docker_platform}" --build-arg BASE_IMAGE="${base_image}" --build-arg TARGET_PLATFORM="${docker_platform}" -t "${builder_tag}" -f "${DEB_DIR}/Dockerfile.builder" "${DEB_DIR}"

        # --- binary build in container (per-language dispatch) ----------------
        # Run as the host uid:gid so the bundle written under build/deb-all and
        # the poetry caches stay caller-owned; HOME/XDG_CACHE_HOME point at /tmp
        # because an arbitrary uid has no writable home.
        log_step "Compiling ${deb_arch} binary inside container (${DEB_LANGUAGE})..."
        local build_cmd
        build_cmd="$(_container_build_cmd "${deb_arch}")"
        docker run --rm --platform "${docker_platform}" -u "$(id -u):$(id -g)" -e HOME=/tmp -e XDG_CACHE_HOME=/tmp -v "${repo_root}:/repo" -w /repo/hsync-bootnode/python -e LC_ALL=C -e PYTHONWARNINGS=ignore -e PIP_DEFAULT_TIMEOUT=300 -e PIP_RETRIES=10 -e POETRY_REQUESTS_TIMEOUT=300 "${builder_tag}" bash -c "${build_cmd}"

        if [[ ! -d "${DEB_ALL_BUILD_DIR}/${deb_arch}/pyinstaller/${APP_NAME}" ]]; then
            log_error "onedir bundle not produced for ${deb_arch}"
            exit 1
        fi

        # --- stage + dpkg-deb in container (target-arch dpkg environment) ------
        log_step "Staging .deb tree and building package for ${deb_arch}..."
        docker run --rm --platform "${docker_platform}" -v "${repo_root}:/repo" -w /repo/hsync-bootnode/python "${builder_tag}" bash -c "${stage_script}" stage "${deb_arch}" "${deb_version}" "$(id -u)" "$(id -g)"

        local deb_name="${DEB_PKG_NAME}_${deb_version}_${deb_arch}.deb"
        local deb_path="${out_abs}/${deb_name}"
        if [[ ! -f "${deb_path}" ]]; then
            log_error ".deb not produced for ${deb_arch} at ${deb_path}"
            exit 1
        fi
        local pkg_size
        pkg_size="$(du -h "${deb_path}" | cut -f1)"
        log_ok "  → ${deb_name} (${pkg_size})"
    done

    echo
    log_ok "All 3 Debian packages built!"
    echo
    echo -e "  ${BOLD}Version:${RESET}   ${deb_version}"
    echo -e "  ${BOLD}Language:${RESET}  ${DEB_LANGUAGE}"
    echo -e "  ${BOLD}Output:${RESET}    ${out_abs}/"
    echo
    echo -e "${DIM}Install with:  sudo dpkg -i ${out_abs}/${DEB_PKG_NAME}_${deb_version}_<arch>.deb${RESET}"
}

# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------

main() {
    local do_clean=false
    local target="deb"

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
            -l|--language)
                [[ $# -ge 2 ]] || { log_error "--language requires a value"; exit 1; }
                DEB_LANGUAGE="$2"
                shift 2
                ;;
            -v|--version)
                [[ $# -ge 2 ]] || { log_error "--version requires a value"; exit 1; }
                VERSION_OVERRIDE="$2"
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

    echo -e "${BOLD}HSYNC Bootnode - .deb Build${RESET}"
    echo -e "${DIM}────────────────────────${RESET}"
    echo

    # The language must have a packaging path before any target runs.
    validate_language

    case "${target}" in
        deb)
            if [[ "${do_clean}" == true ]]; then
                clean_artifacts
                echo
            fi
            build_deb
            ;;
        deb-all)
            if ! command -v docker >/dev/null 2>&1; then
                log_error "docker is required for the deb-all target."
                exit 1
            fi
            if [[ "${do_clean}" == true ]]; then
                clean_artifacts
                docker image rm -f "${DEB_ALL_BUILDER_IMAGE_PREFIX}:amd64" "${DEB_ALL_BUILDER_IMAGE_PREFIX}:arm64" "${DEB_ALL_BUILDER_IMAGE_PREFIX}:armhf" >/dev/null 2>&1 || true
                echo
            fi
            build_deb_all
            ;;
        *)
            log_error "Unknown target: ${target}"
            echo "Supported targets: deb, deb-all"
            exit 1
            ;;
    esac
}

main "$@"
