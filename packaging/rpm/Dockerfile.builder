# syntax=docker/dockerfile:1.6
#
# HSYNC — RPM builder image (x86_64 / aarch64)
#
# Single-stage builder based on ``rockylinux:9`` (RHEL 9, glibc 2.34), the
# RHEL-family baseline for the .rpm targets. 64-bit only: RHEL/Rocky publish no
# armv7 userspace, so RPM covers x86_64 + aarch64 only (armv7 stays on the
# .deb armhf / rpi binaries).
#
# Installs Python 3.12 (AppStream), Poetry and rpm-build; ready to:
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

ENV LC_ALL=C.UTF-8 \
    PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=0 \
    POETRY_VIRTUALENVS_CREATE=true \
    POETRY_NO_INTERACTION=1

# Python 3.12 from AppStream, binutils for PyInstaller --strip, rpm-build for
# packaging. No Rust toolchain: x86_64 and aarch64 both get prebuilt wheels for
# the native dependencies, so nothing is compiled from source.
RUN dnf -y install --setopt=install_weak_deps=False \
        python3.12 \
        python3.12-pip \
        ca-certificates \
        binutils \
        rpm-build \
        redhat-rpm-config \
    && dnf clean all

RUN python3.12 -m pip install --no-cache-dir --prefer-binary "poetry==2.3.2"

WORKDIR /src

CMD ["bash"]
