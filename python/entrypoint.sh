#!/bin/sh
# Container entrypoint for hsync-bootnode.
#
# The daemon provisions group keys (protected buckets / private mode) only from a
# file descriptor, never from a path inside its sandbox. If the operator mounted
# a group-keys file and pointed HSYNC_BOOTNODE_KEYS_FILE at it, open it as fd 3
# before starting the node; otherwise start the node as-is.

set -eu

# The readiness file is created with O_EXCL and survives a SIGKILL'd container:
# remove a stale one so the next start honors its ready-file seam (the node
# itself still refuses to overwrite a file owned by a RUNNING instance).
if [ -n "${HSYNC_BOOTNODE_READY_FILE:-}" ]; then
    rm -f "${HSYNC_BOOTNODE_READY_FILE}"
fi

if [ -n "${HSYNC_BOOTNODE_KEYS_FILE:-}" ]; then
    exec 3< "${HSYNC_BOOTNODE_KEYS_FILE}"
    export HSYNC_BOOTNODE_KEYS_FD=3
fi

exec hsync-bootnode "$@"
