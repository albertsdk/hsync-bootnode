# NOTE: The build context must be the repository root (the parent of
# hsync-bootnode), because the Python v1 depends on the local ../hsync-common
# package ({path = "../../hsync-common"} from python/). Build via
# `./docker.sh build`, which sets the correct context and passes
# `-f hsync-bootnode/Dockerfile`.

### Builder
FROM python:3.14.9-alpine3.23 AS builder

# Install build dependencies in a single layer
RUN apk add --no-cache \
    poetry \
    gcc \
    python3-dev \
    musl-dev \
    linux-headers \
    libffi-dev \
    git

WORKDIR /project/hsync-bootnode/python

# Set environment variables for Poetry
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

# Minimal files needed for poetry install
COPY hsync-bootnode/python/pyproject.toml hsync-bootnode/python/poetry.lock ./

# poetry install also builds/installs the root project, which declares
# `readme = "README.md"` in pyproject.toml, so the file must be present.
COPY hsync-bootnode/python/README.md ./

# The root project is installed (non-editable) to provide the `hsync-bootnode`
# console script the entrypoint runs, so its package source must be present too.
COPY hsync-bootnode/python/src ./src

# Copy the path dependency so Poetry can resolve hsync-common, declared as
# {path = "../../hsync-common"} -> /project/hsync-common at build time
COPY hsync-common /project/hsync-common

# Install dependencies (and the bootnode package, which provides the console
# script) and clean the cache in a single layer
RUN poetry env use python3.14 \
    && poetry install --only main --no-interaction \
    && rm -rf /tmp/poetry_cache

### Run Image
FROM python:3.14.9-alpine3.23

WORKDIR /project/hsync-bootnode/python

# Copy the virtual environment from the builder stage
COPY --from=builder /project/hsync-bootnode/python/.venv /venv

# Copy the editable path dependency to the same absolute path used at build
# time so the venv's editable install of hsync-common resolves at runtime
COPY hsync-common /project/hsync-common

# Copy application source code
COPY hsync-bootnode/python/src/hsync_bootnode /project/hsync-bootnode/python/src/hsync_bootnode

# Entrypoint wrapper: opens the mounted group-keys file as fd 3 (the node reads
# keys only from a file descriptor, never from a path inside its sandbox).
COPY hsync-bootnode/python/entrypoint.sh /entrypoint.sh

# Dedicated unprivileged user, venv on PATH, and the persistent-identity volume
RUN addgroup -S hsync \
    && adduser -S -G hsync -h /project hsync \
    && ln -s /venv /project/hsync-bootnode/python/.venv \
    && chmod +x /entrypoint.sh \
    && mkdir -p /var/lib/hsync-bootnode \
    && chown -R hsync:hsync /var/lib/hsync-bootnode

ENV PATH="/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HSYNC_BOOTNODE_IDENTITY=/var/lib/hsync-bootnode/identity.pem \
    HSYNC_BOOTNODE_READY_FILE=/var/lib/hsync-bootnode/ready.pid

# QUIC/UDP listener. The container binds the unprivileged port 8443 (the image
# runs as a non-root user); map the host's public port to it (see compose.yaml).
EXPOSE 8443/udp

USER hsync

ENTRYPOINT ["/entrypoint.sh"]
CMD ["run"]
