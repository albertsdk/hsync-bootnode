#!/bin/sh
# Container entrypoint for hsync-bootnode.
#
# The daemon provisions group keys (protected buckets / private mode) only from a
# file descriptor, never from a path inside its sandbox. If the operator mounted
# a group-keys file and pointed HSYNC_BOOTNODE_KEYS_FILE at it, open it as fd 3
# before starting the node; otherwise start the node as-is.

set -eu

if [ -n "${HSYNC_BOOTNODE_KEYS_FILE:-}" ]; then
    exec 3< "${HSYNC_BOOTNODE_KEYS_FILE}"
    export HSYNC_BOOTNODE_KEYS_FD=3
fi

exec hsync-bootnode "$@"
