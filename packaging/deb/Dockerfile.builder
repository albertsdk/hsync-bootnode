# syntax=docker/dockerfile:1.6
#
# hsync-bootnode — Debian/Ubuntu .deb builder image (amd64 / arm64 / armhf)
#
# Multi-stage build that produces a debian:bookworm (glibc 2.36) environment
# containing Python 3.12, Poetry, and dpkg-dev, ready to:
#   1. invoke PyInstaller on the project sources mounted at /repo
#   2. assemble a .deb package with dpkg-deb
#
# debian:bookworm targets Debian 12 / Ubuntu 22.04+ (glibc 2.36).
#
# Built and consumed locally by:
#   ../compile_deb.sh --target deb-all (from hsync-bootnode)
# Never published to any registry.

# PYTHON_VERSION and PYTHON_SHA256 are kept in sync with the upstream
# docker-library/python image (https://github.com/docker-library/python).
ARG PYTHON_VERSION=3.12.13
ARG PYTHON_SHA256=c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684

# Base image and target platform are parametrised so the same Dockerfile
# produces a builder for every CPU family:
#   amd64 → amd64/debian:bookworm
#   arm64 → arm64v8/debian:bookworm
#   armhf → arm32v7/debian:bookworm
ARG BASE_IMAGE=amd64/debian:bookworm
ARG TARGET_PLATFORM=linux/amd64

# -----------------------------------------------------------------------------
# Stage 1 — compile Python 3.12 from source (cached forever)
# -----------------------------------------------------------------------------
FROM --platform=${TARGET_PLATFORM} ${BASE_IMAGE} AS python-builder

ARG PYTHON_VERSION
ARG PYTHON_SHA256

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8

# Build dependencies required by the CPython source distribution.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        libssl-dev \
        zlib1g-dev \
        libbz2-dev \
        libreadline-dev \
        libsqlite3-dev \
        libncursesw5-dev \
        libffi-dev \
        liblzma-dev \
        uuid-dev \
        xz-utils \
        tk-dev \
    && rm -rf /var/lib/apt/lists/*

# Build & install CPython into /opt/python3.12. ``--enable-optimizations`` is
# intentionally omitted — PGO under qemu emulation is extremely slow and the
# gains are marginal for our use case (one-shot PyInstaller build).
#
# ``--with-system-ffi`` was removed in Python 3.12 (the bundled copy is now the
# only option and the flag produces a configure warning); it is omitted here.
#
# The download is retried up to 3 times to survive transient python.org / CDN
# failures seen on GitHub Actions runners. ``make -j`` is capped at 4 jobs
# instead of ``$(nproc)``: under qemu-user emulation (arm64/armhf) each gcc
# process has significant memory overhead, and the 16 GB Actions runner can OOM
# with the full ``$(nproc)`` (4) parallelism, killing the build with exit code 1.
#
# ``make`` is additionally wrapped in a retry loop (``-j4``, ``-j4``, then a
# final ``-j1``): under qemu-user emulation individual gcc invocations can crash
# with a SIGSEGV (exit code 139) on otherwise valid translation units (e.g.
# ``Python/_warnings.c``). These crashes are non-deterministic and depend on
# emulated thread scheduling / memory pressure, so simply re-running ``make``
# (which resumes from the already-produced ``.o`` files) succeeds; the ``-j1``
# fallback maximises the odds on the last attempt.
#
# ``ac_cv_sizeof_time_t`` is seeded explicitly: under qemu-user emulation the
# CPython ``configure`` runtime probe for ``sizeof(time_t)`` is unreliable and
# can leave ``SIZEOF_TIME_T`` undefined in ``pyconfig.h``. That makes both the
# ``#if SIZEOF_TIME_T == SIZEOF_LONG_LONG`` / ``== SIZEOF_LONG`` branches in
# ``Python/pytime.c`` evaluate ``SIZEOF_TIME_T`` as empty, so ``PY_TIME_T_MIN``
# is never ``#define``-d and compilation fails with
# ``error: 'PY_TIME_T_MIN' undeclared``. We instead measure the size with a
# tiny C program compiled by the (target-native under qemu) gcc and feed the
# result into configure's cache. The size is returned via the program's exit
# code, so ``|| TT_SIZE=$?`` is used to capture it without tripping ``set -e``.
RUN set -eux; \
    for attempt in 1 2 3; do \
        curl -fsSL "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tar.xz" \
            -o /tmp/python.tar.xz && break; \
        echo "curl attempt ${attempt}/3 failed, retrying in 5s..." >&2; \
        sleep 5; \
    done; \
    test -s /tmp/python.tar.xz; \
    echo "${PYTHON_SHA256} /tmp/python.tar.xz" | sha256sum -c -; \
    mkdir -p /tmp/python-src; \
    tar -xJf /tmp/python.tar.xz -C /tmp/python-src --strip-components=1; \
    cd /tmp/python-src; \
    printf '#include <time.h>\nint main(void){return (int)sizeof(time_t);}\n' > /tmp/tt.c; \
    gcc /tmp/tt.c -o /tmp/tt_bin; \
    TT_SIZE=0; /tmp/tt_bin || TT_SIZE=$?; \
    echo "detected sizeof(time_t) = ${TT_SIZE} bytes"; \
    test "${TT_SIZE}" = 4 -o "${TT_SIZE}" = 8; \
    ./configure \
        --prefix=/opt/python3.12 \
        --enable-shared \
        --with-ensurepip=install \
        ac_cv_sizeof_time_t="${TT_SIZE}" \
        LDFLAGS=-Wl,-rpath=/opt/python3.12/lib; \
    echo "=== pyconfig.h SIZEOF_TIME_T / SIZEOF_LONG ==="; \
    grep -E 'define SIZEOF_TIME_T|define SIZEOF_LONG' pyconfig.h || true; \
    for jobs in 4 4 1; do \
        echo "make -j${jobs} (attempt with ${jobs} job(s))"; \
        rc=0; make -j"${jobs}" || rc=$?; \
        if [ "${rc}" = 0 ]; then break; fi; \
        echo "make -j${jobs} failed with exit code ${rc}; retrying (qemu gcc segfaults are non-deterministic)..." >&2; \
        if [ "${jobs}" = 1 ]; then echo "make failed even with -j1, giving up" >&2; exit "${rc}"; fi; \
    done; \
    make install; \
    /opt/python3.12/bin/python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel; \
    rm -rf /tmp/python-src /tmp/python.tar.xz

# -----------------------------------------------------------------------------
# Stage 2 — runtime builder image
# -----------------------------------------------------------------------------
FROM --platform=${TARGET_PLATFORM} ${BASE_IMAGE} AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    PATH=/opt/python3.12/bin:/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=0 \
    POETRY_VIRTUALENVS_CREATE=true \
    POETRY_NO_INTERACTION=1

# Runtime dependencies for the produced binary + tooling for PyInstaller +
# dpkg-dev for .deb packaging + build-essential for native Python extensions.
# The *-dev packages are needed because on armhf PyPI does not publish wheels
# for ``cryptography``, requiring a source build.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        binutils \
        libsqlite3-0 \
        libbz2-1.0 \
        liblzma5 \
        libncursesw6 \
        libreadline8 \
        build-essential \
        pkg-config \
        libffi-dev \
        libssl-dev \
        zlib1g-dev \
        dpkg-dev \
        fakeroot \
    && rm -rf /var/lib/apt/lists/*

# Bring in the Python 3.12 install from the previous stage.
COPY --from=python-builder /opt/python3.12 /opt/python3.12

# Rust toolchain — ``cryptography`` >= 35 uses pyo3 for its native modules.
# Pinned to a known version so the cached layer is reproducible.
ENV RUSTUP_HOME=/opt/rust/rustup \
    CARGO_HOME=/opt/rust/cargo \
    PATH=/opt/rust/cargo/bin:/opt/python3.12/bin:/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN set -eux; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --profile minimal --default-toolchain 1.84.0; \
    rustc --version; \
    cargo --version

# Poetry — pinned to a known-good 2.x release for reproducibility. Version
# >= 2.0 is mandatory: the project declares its metadata via the PEP 621
# ``[project]`` table and the lock file is generated by Poetry 2.x; older
# 1.x releases ignore ``[project]`` and abort with "fields ... are required
# in package mode" while also rejecting the newer lock-file format.
RUN /opt/python3.12/bin/python3 -m pip install --no-cache-dir --prefer-binary \
        "poetry==2.3.2"

# Workdir is mounted by the caller (``-v "$PWD:/src"``).
WORKDIR /src

# Default command is a shell so the entrypoint can be overridden.
CMD ["bash"]
