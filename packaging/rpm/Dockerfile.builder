# syntax=docker/dockerfile:1.6
#
# HSYNC — RPM builder image (x86_64 / aarch64)
#
# Single-stage builder based on ``rockylinux:9`` (RHEL 9, glibc 2.34), the
# RHEL-family baseline for the .rpm targets. 64-bit only: RHEL/Rocky publish no
# armv7 userspace, so RPM covers x86_64 + aarch64 only (armv7 stays on the
# .deb armhf / rpi binaries).
#
# Rocky 9 AppStream ships CPython 3.14.8; the RPM must bundle the same 3.14.9
# as the Docker image and the release binaries, so the builder installs the
# pinned python-build-standalone 3.14.9 (glibc 2.17+ baseline, runs on Rocky
# 9/glibc 2.34) plus Poetry and rpm-build. Ready to:
#   1. invoke PyInstaller on the project sources mounted at /repo
#   2. assemble a .rpm with rpmbuild from a staged buildroot mounted at /pkg
#
# Multi-arch manifest, so ``--platform`` selects the arch:
#   linux/amd64  -> x86_64
#   linux/arm64  -> aarch64
#
# Built and consumed locally by:  compile.sh --target rpm-all
# Never published to any registry.

ARG BASE_IMAGE=rockylinux:9
ARG TARGET_PLATFORM=linux/amd64

FROM --platform=${TARGET_PLATFORM} ${BASE_IMAGE}

# BuildKit sets TARGETARCH (amd64 / arm64) from --platform.
ARG TARGETARCH

ENV LC_ALL=C.UTF-8 \
    PATH=/opt/python3.14/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=0 \
    POETRY_VIRTUALENVS_CREATE=true \
    POETRY_NO_INTERACTION=1

# binutils for PyInstaller --strip, rpm-build for packaging, tar/gzip for the
# pinned CPython download (the base image already ships curl-minimal). No C/Rust
# toolchain: cp314 manylinux wheels cover the native dependencies, so nothing is
# compiled from source.
RUN dnf -y install --setopt=install_weak_deps=False \
        ca-certificates \
        tar \
        gzip \
        binutils \
        rpm-build \
        redhat-rpm-config \
    && dnf clean all

# Pin the exact interpreter used to build the bundle: python-build-standalone
# release 20261021 ships CPython 3.14.9 for x86_64 and aarch64. The SHA256
# pins the artifact so the build is reproducible.
ARG PBS_RELEASE=20261021
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) pbs_arch=x86_64;  sha=dfa4c5a40c47f338f41658017be550c72247c391e6bfb1fa4da03ebc8451abdf ;; \
        arm64) pbs_arch=aarch64; sha=847895ba727440b012207bb0192282d7e182eb991ae5c7bb5c35c6a12a99e732 ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    asset="cpython-3.14.9+${PBS_RELEASE}-${pbs_arch}-unknown-linux-gnu-install_only.tar.gz"; \
    curl -fsSL --retry 3 -o /tmp/python.tar.gz \
        "https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_RELEASE}/${asset}"; \
    echo "${sha}  /tmp/python.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/python3.14; \
    tar -xzf /tmp/python.tar.gz -C /opt/python3.14 --strip-components=1; \
    rm -f /tmp/python.tar.gz; \
    /opt/python3.14/bin/python3.14 --version

RUN /opt/python3.14/bin/python3.14 -m pip install --no-cache-dir --prefer-binary "poetry==2.5.1"

WORKDIR /src

CMD ["bash"]
