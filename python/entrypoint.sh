#!/bin/sh
# Container entrypoint for hsync-rendezvous.
#
# The daemon provisions group keys (protected buckets / private mode) only from a
# file descriptor, never from a path inside its sandbox. The host operator mounts
# the group-keys file and sets HSYNC_RENDEZVOUS_KEYS_PATH (see compose.yaml /
# install.sh / docker.sh); the container receives the mounted path as
# HSYNC_RENDEZVOUS_KEYS_FILE (typically /keys). When that in-container path is set,
# open it as fd 3 before starting the node; otherwise start the node as-is.

set -eu

# The readiness file is created with O_EXCL and survives a SIGKILL'd container:
# remove a stale one so the next start honors its ready-file seam (the node
# itself still refuses to overwrite a file owned by a RUNNING instance).
if [ -n "${HSYNC_RENDEZVOUS_READY_FILE:-}" ]; then
    rm -f "${HSYNC_RENDEZVOUS_READY_FILE}"
fi

if [ -n "${HSYNC_RENDEZVOUS_KEYS_FILE:-}" ]; then
    exec 3< "${HSYNC_RENDEZVOUS_KEYS_FILE}"
    export HSYNC_RENDEZVOUS_KEYS_FD=3
fi

exec hsync-rendezvous "$@"
