#!/usr/bin/env bash

set -euo pipefail

readonly DEFAULT_VERSION="v1.0.0"
readonly DEFAULT_INSTALL_DIR="${HOME}/.local/share/hsync-bootnode"
readonly REPO="albertsdk/hsync-bootnode"
readonly IMAGE_REPO="ghcr.io/albertsdk/hsync-bootnode"
# The Sigstore identity this installer trusts: the release workflow that signs
# the image, authenticated through GitHub Actions OIDC. Both a tag push and a
# manual dispatch match.
readonly COSIGN_IDENTITY_REGEXP='^https://github\.com/albertsdk/hsync-bootnode/\.github/workflows/release\.yml@refs/(heads|tags)/.*$'
readonly COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"
# The container always binds this unprivileged UDP port; the host maps
# HSYNC_BOOTNODE_PORT to it.
readonly CONTAINER_PORT="8443"

INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
VERSION="${DEFAULT_VERSION}"
PUBLIC_PORT="443"
PUBLIC_PORT_SET=false
PRIVATE=false
KEYS_FILE=""
START_SERVER=true
DRY_RUN=false
VERIFY=true
IMAGE_DIGEST=""
# Resolved from --version/--image-digest in main() and written to .env.
IMAGE_REF=""

usage() {
    cat <<EOF
Install the HSYNC bootnode with Docker Compose.

Usage: ./install.sh [options]

Options:
  --version VERSION       Image version to install, or 'latest' to resolve the
                          latest stable release automatically (default: ${DEFAULT_VERSION})
  --install-dir PATH      Configuration directory
  --port PORT             Host UDP port clients connect to (default: 443)
  --private               Run a private node: every frame requires a bucket token
  --keys-file PATH        Group-keys file for protected buckets / private mode
  --image-digest DIGEST   Pin an exact image digest (sha256:…) instead of a tag
  --no-verify             Skip the container image signature verification
  --no-start              Generate and validate files without starting the node
  --dry-run               Show the planned configuration without changing files
  -h, --help              Show this help

By default the installer verifies the container image's Sigstore signature
before starting the node (keyless, signed by the release workflow). This needs
the 'cosign' tool on PATH; pass --no-verify to install without it.

The installer never installs Docker, invokes sudo, opens firewall ports, or
overwrites an existing partial installation. Re-running it updates the selected
image version while preserving the existing TLS identity.
EOF
}

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

validate_version() {
    [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] ||
        fail "invalid version '$1'; expected vX.Y.Z or 'latest'"
}

resolve_latest_version() {
    local url effective tag
    url="https://github.com/${REPO}/releases/latest"
    effective="$(curl -fsSIL -o /dev/null -w '%{url_effective}' "${url}")" ||
        fail "could not resolve the latest release from ${url}"
    tag="${effective##*/}"
    [[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] ||
        fail "unexpected latest release tag '${tag}' from ${url}"
    printf '%s' "${tag}"
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)) ||
        fail "invalid port '$1'; expected 1-65535"
}

validate_digest() {
    [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]] ||
        fail "invalid --image-digest '$1'; expected sha256:<64 lowercase hex>"
}

image_reference() {
    if [[ -n "${IMAGE_DIGEST}" ]]; then
        printf '%s@%s' "${IMAGE_REPO}" "${IMAGE_DIGEST}"
    else
        printf '%s:%s' "${IMAGE_REPO}" "${VERSION}"
    fi
}

verify_image() {
    local image_ref="$1"
    if [[ "${VERIFY}" != true ]]; then
        printf 'WARNING: image signature verification is disabled (--no-verify); the image is trusted on the registry reference alone.\n' >&2
        return 0
    fi
    require_command cosign
    printf 'Verifying the container image signature (Sigstore keyless)...\n'
    cosign verify \
        --certificate-identity-regexp "${COSIGN_IDENTITY_REGEXP}" \
        --certificate-oidc-issuer "${COSIGN_OIDC_ISSUER}" \
        "${image_ref}" >/dev/null ||
        fail "image signature verification failed for ${image_ref}; refusing to start an unverified node (use --no-verify to override)"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version)
                [[ -n "${2:-}" ]] || fail "$1 requires a value"
                VERSION="$2"
                shift 2
                ;;
            --install-dir)
                [[ -n "${2:-}" ]] || fail "$1 requires a value"
                INSTALL_DIR="$2"
                shift 2
                ;;
            --port)
                [[ -n "${2:-}" ]] || fail "$1 requires a value"
                PUBLIC_PORT="$2"
                PUBLIC_PORT_SET=true
                shift 2
                ;;
            --private)
                PRIVATE=true
                shift
                ;;
            --keys-file)
                [[ -n "${2:-}" ]] || fail "$1 requires a value"
                KEYS_FILE="$2"
                shift 2
                ;;
            --image-digest)
                [[ -n "${2:-}" ]] || fail "$1 requires a value"
                IMAGE_DIGEST="$2"
                shift 2
                ;;
            --no-verify)
                VERIFY=false
                shift
                ;;
            --no-start)
                START_SERVER=false
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                fail "unknown option: $1"
                ;;
        esac
    done
}

write_compose_file() {
    cat > "${INSTALL_DIR}/compose.yaml" <<'EOF'
name: hsync-bootnode

services:
  bootnode:
    image: ${HSYNC_BOOTNODE_IMAGE:?Set HSYNC_BOOTNODE_IMAGE in .env}
    restart: unless-stopped
    user: "${HSYNC_UID:-1000}:${HSYNC_GID:-1000}"
    command: ["run", "--host", "0.0.0.0", "--port", "8443"]
    ports:
      - "${HSYNC_BOOTNODE_PORT:-443}:8443/udp"
    env_file:
      - .env
    volumes:
      - ${HSYNC_BOOTNODE_DATA_DIR:-./hsync-data}:/var/lib/hsync-bootnode
      - ${HSYNC_BOOTNODE_KEYS_PATH:-/dev/null}:/keys:ro
    read_only: true
    tmpfs:
      - /tmp
EOF
}

write_env_file() {
    cat > "${INSTALL_DIR}/.env" <<EOF
# Generated by the HSYNC bootnode installer. Keep this file private.
HSYNC_BOOTNODE_IMAGE=${IMAGE_REF}
HSYNC_BOOTNODE_PORT=${PUBLIC_PORT}
# Host directory holding the persistent TLS identity and the readiness PID
# (bind-mounted into the container). Back it up to keep the fingerprint stable.
HSYNC_BOOTNODE_DATA_DIR=${INSTALL_DIR}/hsync-data
# Container runs under these host ids so the bind-mounted directory stays
# writable (it was created by this installer as the same user).
HSYNC_UID=$(id -u)
HSYNC_GID=$(id -g)
# Container paths for the persistent identity and the readiness PID.
HSYNC_BOOTNODE_IDENTITY=/var/lib/hsync-bootnode/identity.pem
HSYNC_BOOTNODE_READY_FILE=/var/lib/hsync-bootnode/ready.pid
EOF
    if [[ -n "${KEYS_FILE}" ]]; then
        printf 'HSYNC_BOOTNODE_KEYS_PATH=%s\n' "${KEYS_FILE}" >> "${INSTALL_DIR}/.env"
        printf 'HSYNC_BOOTNODE_KEYS_FILE=/keys\n' >> "${INSTALL_DIR}/.env"
    else
        printf 'HSYNC_BOOTNODE_KEYS_PATH=/dev/null\n' >> "${INSTALL_DIR}/.env"
    fi
    if [[ "${PRIVATE}" == true ]]; then
        printf 'HSYNC_BOOTNODE_PRIVATE=1\n' >> "${INSTALL_DIR}/.env"
    fi
    chmod 600 "${INSTALL_DIR}/.env"
}

update_env_value() {
    local key="$1"
    local value="$2"
    local env_file="${INSTALL_DIR}/.env"
    local temporary_file="${env_file}.tmp"

    while IFS= read -r line || [[ -n "${line}" ]]; do
        if [[ "${line}" == "${key}="* ]]; then
            printf '%s=%s\n' "${key}" "${value}"
        else
            printf '%s\n' "${line}"
        fi
    done < "${env_file}" > "${temporary_file}"
    mv "${temporary_file}" "${env_file}"
    chmod 600 "${env_file}"
}

read_env_value() {
    local wanted_key="$1"
    local key
    local value

    while IFS='=' read -r key value; do
        if [[ "${key}" == "${wanted_key}" ]]; then
            printf '%s\n' "${value}"
            return 0
        fi
    done < "${INSTALL_DIR}/.env"
    return 1
}

install_files() {
    local env_file="${INSTALL_DIR}/.env"
    local compose_file="${INSTALL_DIR}/compose.yaml"

    if [[ -e "${env_file}" || -e "${compose_file}" ]]; then
        [[ -f "${env_file}" && -f "${compose_file}" ]] ||
            fail "partial installation in ${INSTALL_DIR}; refusing to overwrite it"
        update_env_value HSYNC_BOOTNODE_IMAGE "${IMAGE_REF}"
        if [[ "${PUBLIC_PORT_SET}" == true ]]; then
            update_env_value HSYNC_BOOTNODE_PORT "${PUBLIC_PORT}"
        fi
        printf 'Reusing existing TLS identity in %s\n' "${INSTALL_DIR}"
        return
    fi

    mkdir -p "${INSTALL_DIR}"
    mkdir -p "${INSTALL_DIR}/hsync-data"
    write_compose_file
    write_env_file
    chmod 600 "${compose_file}"
}

wait_for_ready() {
    local ready_file="$1"
    local deadline=$(( $(date +%s) + 60 ))
    while (( $(date +%s) < deadline )); do
        [[ -s "${ready_file}" ]] && return 0
        sleep 1
    done
    return 1
}

main() {
    local data_dir
    local ready_file

    parse_args "$@"

    if [[ "${INSTALL_DIR}" != /* ]]; then
        INSTALL_DIR="$(pwd)/${INSTALL_DIR}"
    fi

    if [[ -f "${INSTALL_DIR}/.env" && "${PUBLIC_PORT_SET}" == false ]]; then
        PUBLIC_PORT="$(read_env_value HSYNC_BOOTNODE_PORT)" ||
            fail "HSYNC_BOOTNODE_PORT is missing from ${INSTALL_DIR}/.env"
    fi

    if [[ "${VERSION}" == "latest" ]]; then
        require_command curl
        VERSION="$(resolve_latest_version)"
    fi
    validate_version "${VERSION}"
    validate_port "${PUBLIC_PORT}"
    [[ -z "${IMAGE_DIGEST}" ]] || validate_digest "${IMAGE_DIGEST}"
    IMAGE_REF="$(image_reference)"
    if [[ -n "${KEYS_FILE}" && ! -f "${KEYS_FILE}" ]]; then
        fail "group-keys file not found: ${KEYS_FILE}"
    fi

    printf 'Install directory: %s\n' "${INSTALL_DIR}"
    printf 'Image: %s\n' "${IMAGE_REF}"
    printf 'Endpoint: udp/%s\n' "${PUBLIC_PORT}"

    if [[ "${DRY_RUN}" == true ]]; then
        printf 'Dry run: no files were changed.\n'
        exit 0
    fi

    require_command docker
    docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"

    umask 077
    install_files
    docker compose --project-directory "${INSTALL_DIR}" \
        --file "${INSTALL_DIR}/compose.yaml" config --quiet
    verify_image "${IMAGE_REF}"

    data_dir="$(read_env_value HSYNC_BOOTNODE_DATA_DIR)"
    ready_file="${data_dir}/ready.pid"

    if [[ "${START_SERVER}" == true ]]; then
        docker compose --project-directory "${INSTALL_DIR}" \
            --file "${INSTALL_DIR}/compose.yaml" pull
        rm -f "${ready_file}"
        docker compose --project-directory "${INSTALL_DIR}" \
            --file "${INSTALL_DIR}/compose.yaml" up -d
        if wait_for_ready "${ready_file}"; then
            printf 'HSYNC bootnode is live on udp/%s\n' "${PUBLIC_PORT}"
        else
            printf 'Started, but readiness was not reported within 60s; check the logs:\n' >&2
            printf '  docker compose --project-directory %q --file %q logs\n' \
                "${INSTALL_DIR}" "${INSTALL_DIR}/compose.yaml" >&2
        fi
    else
        printf 'Configuration validated. Start it with:\n'
        printf '  docker compose --project-directory %q --file %q up -d\n' \
            "${INSTALL_DIR}" "${INSTALL_DIR}/compose.yaml"
    fi
}

main "$@"
