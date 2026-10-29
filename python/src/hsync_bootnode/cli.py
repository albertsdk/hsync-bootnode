"""Typer CLI for the ``hsync-bootnode`` Python v1 process.

Starts the single QUIC/UDP listener on ``--port`` (default 443), with RETRY +
address-validation tokens, the token policy (the operator's protected
buckets, or every bucket in node-wide ``--private`` mode), per-IP/per-bucket
rate limits, STUN-echo and optional zero-touch UPnP. No-log: nothing
peer-related is ever written to disk.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import ipaddress
import os
import select
import signal
import stat
import sys
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

import typer
from hsync_common import ssl_utils
from hsync_common.constants import BOOT_DEFAULT_PORT, BOOT_PORT_SET
from hsync_common.endpoint import parse_host_port, parse_port_list
from hsync_common.path_validation import is_valid_bucket_name
from hsync_common.protocol.boot_tokens import MIN_GROUP_KEY_CHARS, validate_group_key
from hsync_common.protocol.rest import REST_METRICS_PATH
from hsync_common.state_paths import state_path
from pydantic import SecretStr

from hsync_bootnode import __version__
from hsync_bootnode.diagnostics import configure_debug, debug_log, error_event, warn_event
from hsync_bootnode.handler import REQUEST_PATH_PRUNE_BUDGET, BootConfigError, BootHandler
from hsync_bootnode.metrics import MetricsEndpoint, MetricsServer
from hsync_bootnode.resources import ResourceLimits
from hsync_bootnode.server import (
    ConnectionGuard,
    IdentityError,
    NodeIdentity,
    load_identity,
    load_or_create_identity,
    rotate_identity,
    rotation_hint,
    start_servers,
)
from hsync_bootnode.stats import NodeStats
from hsync_bootnode.systemd import (
    notify_available,
    notify_ready,
    notify_status,
    notify_stopping,
    notify_watchdog,
    watchdog_interval,
)
from hsync_bootnode.upnp import UpnpManager

app = typer.Typer(
    help=(
        "HSYNC P2P bootstrap node (no-log, in-memory, zero-knowledge). "
        "Speaks 'boot/1' over QUIC/UDP 443."
    ),
    add_completion=False,
    # Multi-command mode ('run' subcommand) while still allowing top-level
    # 'hsync-bootnode --version'; a bare invocation prints the help.
    invoke_without_command=True,
    no_args_is_help=True,
)

# Group keys arrive on a file descriptor ('bucket=<hex-key>' lines) or an
# operator-managed file; envvar forms for the systemd/launchd/Windows wrappers.
# Read once, never written.
_DEFAULT_KEYS_FD_ENV = "HSYNC_BOOTNODE_KEYS_FD"
# Portable alternative for service managers that cannot inherit a descriptor
# (Windows/WinSW): an operator-managed file, read once and never written.
_DEFAULT_KEYS_FILE_ENV = "HSYNC_BOOTNODE_KEYS_FILE"
# Opt-in peer-aware stderr debug stream (see diagnostics.py).
_DEFAULT_DEBUG_ENV = "HSYNC_BOOTNODE_DEBUG"
# Readiness seam: PID written here once the listener is bound (no peer data).
_DEFAULT_READY_FILE_ENV = "HSYNC_BOOTNODE_READY_FILE"
# Node-wide private mode: require a valid bucket_token on every frame.
_DEFAULT_PRIVATE_ENV = "HSYNC_BOOTNODE_PRIVATE"
# Data relay (opt-in). One switch plus the bounds that keep a public node from
# becoming a free CDN: idle timeout, per-session byte cap and global byte rate.
_DEFAULT_RELAY_ENV = "HSYNC_BOOTNODE_RELAY"
_DEFAULT_RELAY_IDLE_TIMEOUT_ENV = "HSYNC_BOOTNODE_RELAY_IDLE_TIMEOUT"
_DEFAULT_RELAY_SESSION_BYTES_ENV = "HSYNC_BOOTNODE_RELAY_SESSION_BYTES"
_DEFAULT_RELAY_BANDWIDTH_ENV = "HSYNC_BOOTNODE_RELAY_BANDWIDTH"
# Persistent TLS identity path; the default XDG state path keeps the
# fingerprint stable and pin-able across restarts.
_DEFAULT_IDENTITY_ENV = "HSYNC_BOOTNODE_IDENTITY"
# Opt out of persistence: keep the TLS identity in memory (no disk writes).
_DEFAULT_EPHEMERAL_ENV = "HSYNC_BOOTNODE_EPHEMERAL"
# Metrics endpoint (loopback HTTP, bearer token) and the periodic aggregate
# sink. Both are opt-in: no listener and no file unless the operator asks.
_DEFAULT_METRICS_HOST_ENV = "HSYNC_BOOTNODE_METRICS_HOST"
_DEFAULT_METRICS_PORT_ENV = "HSYNC_BOOTNODE_METRICS_PORT"
_DEFAULT_METRICS_TOKEN_FD_ENV = "HSYNC_BOOTNODE_METRICS_TOKEN_FD"
_DEFAULT_METRICS_TOKEN_FILE_ENV = "HSYNC_BOOTNODE_METRICS_TOKEN_FILE"
_DEFAULT_STATS_FILE_ENV = "HSYNC_BOOTNODE_STATS_FILE"
_DEFAULT_STATS_INTERVAL_ENV = "HSYNC_BOOTNODE_STATS_INTERVAL"
# Warn this many days before the persisted identity's certificate expires.
_IDENTITY_EXPIRY_WARN_DAYS = 30
# Shared help for the ``--identity`` option (declared identically by every
# command that resolves the persisted identity file).
_IDENTITY_HELP = "Path of the persisted identity file (default: the standard state path)."
# Cap for the group-keys FD payload: anything bigger means the descriptor was
# misrouted (or is stuck open).
KEYS_FD_MAX_BYTES = 1 << 20
# Bounded wall-clock budget for reading that payload. Keys are a handful of
# short lines followed by EOF, so a descriptor that stays open without ever
# returning EOF (a pipe held open, a misrouted device) must fail fast instead of
# hanging startup. POSIX enforces it with select(); Windows only gets the byte
# cap above (select() does not cover pipes/files there).
KEYS_FD_READ_TIMEOUT_SECONDS = 5.0


def default_identity_path() -> Path:
    """Resolve the identity path: ``$HSYNC_BOOTNODE_IDENTITY`` or the state dir."""
    return state_path("bootnode", "identity.pem", override_env=_DEFAULT_IDENTITY_ENV)


def _resolve_identity(
    identity: str | None,
    ephemeral: bool,
    *,
    host: str,
    public_hosts: Sequence[str],
) -> NodeIdentity | None:
    """Resolve the TLS identity for ``run`` from ``--identity`` / ``--ephemeral``.

    ``--identity`` and ``--ephemeral`` are mutually exclusive. With neither, the
    identity persists at :func:`default_identity_path` (created on first run).
    Returns a persisted/loaded identity, or ``None`` for the in-memory case.
    """
    if identity is not None and ephemeral:
        raise BootConfigError("--identity and --ephemeral are mutually exclusive")
    if ephemeral:
        return None
    path = identity if identity is not None else str(default_identity_path())
    return load_or_create_identity(path, host=host, public_hosts=public_hosts)


def _config_error(exc: Exception) -> NoReturn:
    """Report a configuration/identity error on stderr and exit with code 2."""
    typer.echo(f"configuration error: {exc}", err=True)
    raise typer.Exit(code=2) from exc


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", help="Print version and exit."),
) -> None:
    """HSYNC P2P bootstrap node: no-log, in-memory, zero-knowledge (boot/1)."""
    if version:
        typer.echo(f"hsync-bootnode {__version__} (boot/1, Python v1)")
        raise typer.Exit()


def _parse_port_list(raw: str) -> list[int]:
    """Parse a ``--ports`` value (comma-separated UDP ports, order preserved).

    Thin strict wrapper over the shared ``hsync_common.endpoint.parse_port_list``
    SSOT, which the client reuses in its lenient ``HSYNC_BOOTNODE_PORTS`` policy.
    """
    try:
        ports = parse_port_list(raw, strict=True)
    except ValueError as exc:
        raise typer.BadParameter(f"--ports {exc}") from exc
    if not ports:
        raise typer.BadParameter("--ports requires at least one port")
    return list(ports)


def _resolve_listeners(
    host: str | None, port: int | None, ports: str | None
) -> tuple[str, list[int]]:
    """Resolve the bind address and ordered UDP port set.

    ``--ports`` (multi, comma-separated) is mutually exclusive with ``--port``
    and with a port carried in ``--host HOST:PORT``. Otherwise the single value
    comes from ``--port`` (or the host port) and defaults to
    ``BOOT_DEFAULT_PORT``. ``--host`` may carry a port; the returned host is
    always unbracketed.
    """
    resolved_host = "0.0.0.0"
    host_port: int | None = None
    if host is not None:
        try:
            hp = parse_host_port(host)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        resolved_host = hp.host
        host_port = hp.port
    if ports is not None:
        if port is not None or host_port is not None:
            raise typer.BadParameter(
                "--ports is mutually exclusive with --port and a port in --host HOST:PORT"
            )
        return resolved_host, _parse_port_list(ports)
    if port is not None and host_port is not None:
        raise typer.BadParameter(
            "specify the port either in --host HOST:PORT or with --port, not both"
        )
    single = port if port is not None else host_port
    return resolved_host, [single if single is not None else BOOT_DEFAULT_PORT]


def _near_expiry_reason(days_left: int, identity_path: str) -> str:
    """Operator-facing reason with the exact rotation command for this identity."""
    return f"{days_left}d remaining; rotate with '{rotation_hint(identity_path)}'"


@app.command()
def run(
    host: str | None = typer.Option(
        None,
        "--host",
        metavar="HOST[:PORT]",
        help=(
            "Address to bind the QUIC/UDP listener to, optionally with a port "
            "(HOST[:PORT], e.g. 0.0.0.0:443 or [::1]:443). Default: 0.0.0.0."
        ),
    ),
    port: int | None = typer.Option(
        None,
        "--port",
        min=1,
        max=65535,
        help=(
            f"UDP port (default {BOOT_DEFAULT_PORT} for QUIC/HTTP3). "
            "Mutually exclusive with a port in --host HOST:PORT. "
            "Use --ports to listen on several UDP ports at once "
            "(client-egress fallback). "
            "Ports below 1024 need root or CAP_NET_BIND_SERVICE."
        ),
    ),
    ports: str | None = typer.Option(
        None,
        "--ports",
        metavar="P1,P2,...",
        help=(
            "Comma-separated UDP ports to listen on (multi-port; one process, one "
            "routing table, so a peer on one port is visible to queries on another). "
            "Mutually exclusive with --port and a port in --host HOST:PORT. "
            f"Recommended reachability set: {','.join(map(str, BOOT_PORT_SET))} "
            "(443 QUIC + 53 DNS; freeing the local resolver is usually required for 53). "
            "Ports below 1024 need root or CAP_NET_BIND_SERVICE."
        ),
    ),
    protected_bucket: list[str] = typer.Option(
        [],
        "--protected-bucket",
        help="Bucket requiring a valid bucket_token (repeatable).",
    ),
    keys_fd: int | None = typer.Option(
        None,
        "--keys-fd",
        min=0,
        envvar=_DEFAULT_KEYS_FD_ENV,
        help="FD with group keys (one 'bucket=<hex-key>' per line). Env: HSYNC_BOOTNODE_KEYS_FD.",
    ),
    keys_file: str | None = typer.Option(
        None,
        "--keys-file",
        envvar=_DEFAULT_KEYS_FILE_ENV,
        help=(
            "File with group keys (one 'bucket=<hex-key>' per line), read once "
            "at startup. Alternative to --keys-fd for service managers that "
            "cannot pass a descriptor (Windows). Env: HSYNC_BOOTNODE_KEYS_FILE."
        ),
    ),
    private: bool = typer.Option(
        False,
        "--private",
        envvar=_DEFAULT_PRIVATE_ENV,
        help="Require a valid bucket_token on every frame (private node). Env: HSYNC_BOOTNODE_PRIVATE=1.",
    ),
    upnp: bool = typer.Option(
        False,
        "--upnp",
        help="Map every bound QUIC/UDP port with UPnP (opt-in; off by default).",
    ),
    relay: bool = typer.Option(
        False,
        "--relay",
        envvar=_DEFAULT_RELAY_ENV,
        help=(
            "Relay peers' opaque TLS through this node (opt-in; off by default). "
            "Two peers that no inbound NAT mapping reaches (mobile CGNAT, a "
            "hotspot behind a carrier) then still run the p2p data plane; the "
            "node never sees content and never terminates the peers' TLS. "
            "Env: HSYNC_BOOTNODE_RELAY=1."
        ),
    ),
    relay_idle_timeout: int = typer.Option(
        120,
        "--relay-idle-timeout",
        min=30,
        max=3600,
        envvar=_DEFAULT_RELAY_IDLE_TIMEOUT_ENV,
        metavar="SECONDS",
        help=(
            "Drop a relayed session (and a listener control stream) after this "
            "many seconds without traffic in either direction (default 120). "
            "Env: HSYNC_BOOTNODE_RELAY_IDLE_TIMEOUT."
        ),
    ),
    relay_session_bytes: int = typer.Option(
        0,
        "--relay-session-bytes",
        min=0,
        envvar=_DEFAULT_RELAY_SESSION_BYTES_ENV,
        metavar="BYTES",
        help=(
            "Close a relayed session after this many forwarded bytes (0 = no "
            "per-session cap; the byte rate remains the primary bound). "
            "Env: HSYNC_BOOTNODE_RELAY_SESSION_BYTES."
        ),
    ),
    relay_bandwidth: int = typer.Option(
        8192,
        "--relay-bandwidth",
        min=0,
        envvar=_DEFAULT_RELAY_BANDWIDTH_ENV,
        metavar="KIB_PER_SECOND",
        help=(
            "Aggregate relay throughput cap in KiB/s (default 8192 = 8 MiB/s; "
            "0 = unlimited). Excess traffic is throttled, never dropped. "
            "Env: HSYNC_BOOTNODE_RELAY_BANDWIDTH."
        ),
    ),
    ttl: int = typer.Option(
        60,
        "--ttl",
        min=1,
        max=3600,
        help="Record TTL in seconds (spec default: 60).",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        envvar=_DEFAULT_DEBUG_ENV,
        help=(
            "Emit the full operation log to stderr (opt-in; disabled by default): "
            "connections, frames, decisions and TTL sweeps, including the peer "
            "identity (CID, bucket, IP, port). Never written to disk."
        ),
    ),
    ready_file: str | None = typer.Option(
        None,
        "--ready-file",
        envvar=_DEFAULT_READY_FILE_ENV,
        help="Write the process PID to this path once the listener is bound.",
    ),
    metrics_host: str = typer.Option(
        "127.0.0.1",
        "--metrics-host",
        envvar=_DEFAULT_METRICS_HOST_ENV,
        help=(
            "Loopback address for the /metrics endpoint (only 127.0.0.1, ::1 or "
            "localhost; plain HTTP, never exposed). Env: HSYNC_BOOTNODE_METRICS_HOST."
        ),
    ),
    metrics_port: int | None = typer.Option(
        None,
        "--metrics-port",
        envvar=_DEFAULT_METRICS_PORT_ENV,
        metavar="PORT",
        help=(
            "Serve aggregate Prometheus metrics on --metrics-host:PORT (loopback "
            "TCP, Bearer token required). Off when omitted. Env: "
            "HSYNC_BOOTNODE_METRICS_PORT."
        ),
    ),
    metrics_token_fd: int | None = typer.Option(
        None,
        "--metrics-token-fd",
        envvar=_DEFAULT_METRICS_TOKEN_FD_ENV,
        help=(
            "File descriptor holding the metrics bearer token (one line, at least "
            "32 characters). Env: HSYNC_BOOTNODE_METRICS_TOKEN_FD."
        ),
    ),
    metrics_token_file: str | None = typer.Option(
        None,
        "--metrics-token-file",
        envvar=_DEFAULT_METRICS_TOKEN_FILE_ENV,
        help=(
            "File holding the metrics bearer token; portable alternative to "
            "--metrics-token-fd. Env: HSYNC_BOOTNODE_METRICS_TOKEN_FILE."
        ),
    ),
    stats_file: str | None = typer.Option(
        None,
        "--stats-file",
        envvar=_DEFAULT_STATS_FILE_ENV,
        help=(
            "Write the aggregate counters to this file in Prometheus text format "
            "(atomic replace; node_exporter textfile collector). Env: "
            "HSYNC_BOOTNODE_STATS_FILE."
        ),
    ),
    stats_interval: int = typer.Option(
        15,
        "--stats-interval",
        envvar=_DEFAULT_STATS_INTERVAL_ENV,
        metavar="SECONDS",
        help="Seconds between two STATUS=/stats-file publications (default 15).",
    ),
    no_rate_limit: bool = typer.Option(
        False,
        "--no-rate-limit",
        help="Disable rate limiting (benchmark/test seam; never in production).",
    ),
    identity: str | None = typer.Option(
        None,
        "--identity",
        envvar=_DEFAULT_IDENTITY_ENV,
        help=(
            "Path of the persistent TLS identity (key+cert). Defaults to "
            "HSYNC_BOOTNODE_IDENTITY or an XDG state path, created on first run "
            "so the certificate fingerprint is stable across restarts and can be "
            "pinned by clients."
        ),
    ),
    ephemeral: bool = typer.Option(
        False,
        "--ephemeral",
        envvar=_DEFAULT_EPHEMERAL_ENV,
        help=(
            "Keep the TLS identity in memory and write no identity file "
            "(read-only filesystems, throwaway nodes); the fingerprint changes on "
            "every restart, so clients cannot pin it. Env: HSYNC_BOOTNODE_EPHEMERAL=1."
        ),
    ),
    public_host: list[str] = typer.Option(
        [],
        "--public-host",
        help=(
            "Public hostname or IP to add to the certificate SAN, so clients can "
            "reach the node under a name that is not the bind address (repeatable)."
        ),
    ),
) -> None:
    """Run the bootstrap node: one or more QUIC/UDP listeners (boot/1)."""
    resolved_host, resolved_ports = _resolve_listeners(host, port, ports)
    limits = ResourceLimits.detect()
    # One aggregate counter object per process: the handler, the connection guard
    # and every sink (STATUS=, stats file, /metrics) share it.
    stats = NodeStats()
    configure_debug(debug)
    if debug:
        # Transparency (RFC 6973 §6.2): the operator opted into a stream that
        # may contain peer identity — say so once, on the always-on channel.
        warn_event("peer data logging enabled", reason="--debug")
    try:
        if metrics_port is not None and not 1 <= metrics_port <= 65535:
            raise BootConfigError("--metrics-port must be between 1 and 65535")
        if not 1 <= stats_interval <= 3600:
            raise BootConfigError("--stats-interval must be between 1 and 3600")
        keys = _load_keys(keys_fd, keys_file)
        handler = BootHandler(
            protected_buckets=protected_bucket,
            private=private,
            group_keys=keys,
            ttl=float(ttl),
            enforce_rate_limits=not no_rate_limit,
            limits=limits,
            stats=stats,
            relay_enabled=relay,
            relay_idle_timeout=float(relay_idle_timeout),
            relay_session_bytes=relay_session_bytes,
            relay_bytes_per_second=relay_bandwidth * 1024,
        )
        node_identity = _resolve_identity(
            identity, ephemeral, host=resolved_host, public_hosts=public_host
        )
        metrics_endpoint = _resolve_metrics(
            host=metrics_host,
            port=metrics_port,
            token_fd=metrics_token_fd,
            token_file=metrics_token_file,
        )
        if stats_file is not None:
            _check_stats_target(stats_file)
    except (BootConfigError, IdentityError) as exc:
        _config_error(exc)

    if no_rate_limit:
        warn_event("rate limiting disabled", reason="--no-rate-limit")
    _install_uvloop()
    _install_shutdown_handlers()

    if node_identity is not None:
        identity_path_display = identity or str(default_identity_path())
        identity_line = f"  identity  : {identity_path_display} (persisted)"
    else:
        identity_line = "  identity  : in-memory (ephemeral; clients cannot pin the fingerprint)"
    # Single-port startup: hint at the multi-port option that makes the node
    # reachable from a client network whose egress firewall blocks UDP 443.
    multi_hint = (
        " — add --ports 443,53 for client-egress reachability" if len(resolved_ports) == 1 else ""
    )
    banner = (
        f"hsync-bootnode {__version__} — boot/1, no-log, in-memory\n"
        f"  listener : {resolved_host}:{','.join(map(str, resolved_ports))} "
        f"(QUIC/UDP, TLS 1.3, RETRY+address-validation){multi_hint}\n"
        f"{identity_line}\n"
        f"  protected buckets: {', '.join(protected_bucket) or '(none)'}\n"
        f"  mode      : {'private (every frame needs a bucket_token)' if private else 'open'}\n"
        f"  group keys loaded: {len(keys)}\n"
        f"  ttl       : {ttl}s\n"
        f"  limits    : <= {limits.max_peer_records} peers "
        f"(<= {limits.max_records_per_bucket}/bucket), "
        f"<= {limits.max_active_connections} connections (host-derived)\n"
        f"  debug     : {'on (full operation log incl. peer identity, stderr only)' if debug else 'off (in-memory only)'}\n"
        f"  rate limit: {'disabled' if no_rate_limit else 'enabled'}\n"
        f"  upnp      : {'enabled (zero-touch)' if upnp else 'disabled'}\n"
        f"  relay     : {_relay_display(relay, relay_bandwidth, relay_session_bytes, relay_idle_timeout)}\n"
        f"  metrics   : {_metrics_display(metrics_endpoint)}\n"
        f"  stats     : {stats_file or '(off)'} every {stats_interval}s"
    )
    typer.echo(banner)

    if node_identity is not None:
        days_left = (node_identity.expires_at - datetime.now(UTC)).days
        if days_left <= _IDENTITY_EXPIRY_WARN_DAYS:
            warn_event(
                "identity certificate near expiry",
                path=str(identity_path_display),
                reason=_near_expiry_reason(days_left, identity_path_display),
            )
    try:
        asyncio.run(
            _async_main(
                resolved_host,
                resolved_ports,
                handler,
                upnp,
                ready_file,
                identity=node_identity,
                enforce_rate_limits=not no_rate_limit,
                limits=limits,
                stats=stats,
                metrics=metrics_endpoint,
                stats_file=stats_file,
                stats_interval=float(stats_interval),
            )
        )
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass  # graceful shutdown: transport closed in _async_main's finally
    except ListenerBindError as exc:
        typer.echo(_bind_error_message(exc), err=True)
        raise typer.Exit(code=3) from exc
    except MetricsBindError as exc:
        typer.echo(_metrics_bind_error_message(exc), err=True)
        raise typer.Exit(code=3) from exc
    except ReadyFileError as exc:
        error_event("readiness file not writable", path=exc.path, reason=exc.reason)
        typer.echo(_ready_file_error_message(exc), err=True)
        raise typer.Exit(code=4) from exc


identity_app = typer.Typer(help="Manage the persistent node identity (TLS key+cert).")
app.add_typer(identity_app, name="identity")


@identity_app.command("show")
def identity_show(
    identity: str | None = typer.Option(
        None,
        "--identity",
        envvar=_DEFAULT_IDENTITY_ENV,
        help=_IDENTITY_HELP,
    ),
    pem: bool = typer.Option(
        False, "--pem", help="Print the certificate PEM instead of the fingerprint."
    ),
) -> None:
    """Print the persisted identity fingerprint (or its certificate PEM)."""
    try:
        node = load_identity(identity or default_identity_path())
    except IdentityError as exc:
        _config_error(exc)
    if pem:
        typer.echo(ssl_utils.serialize_cert_pem(node.certificate).decode("ascii"))
    else:
        typer.echo(f"sha256:{node.fingerprint}")


@identity_app.command("rotate")
def identity_rotate(
    identity: str | None = typer.Option(
        None,
        "--identity",
        envvar=_DEFAULT_IDENTITY_ENV,
        help=_IDENTITY_HELP,
    ),
    public_host: list[str] = typer.Option(
        [],
        "--public-host",
        help="Public hostname or IP to add to the new certificate SAN (repeatable).",
    ),
) -> None:
    """Regenerate the persisted identity and print the new fingerprint."""
    path = identity or default_identity_path()
    try:
        rotate_identity(path, host="0.0.0.0", public_hosts=public_host)
        # Re-read what was written: load_identity() refuses a key that does not
        # match its certificate, so a half-completed rotation fails here instead
        # of being announced with a fingerprint the node cannot serve.
        node = load_identity(path)
    except IdentityError as exc:
        _config_error(exc)
    typer.echo(f"sha256:{node.fingerprint}")
    typer.echo(
        "distribute this fingerprint to clients; accept the old pin during the rotation window",
        err=True,
    )
    typer.echo(
        "restart the bootnode to serve the new identity, then verify it from a client "
        "with 'hsync trust bootnode fingerprint <host>'",
        err=True,
    )


class ListenerBindError(Exception):
    """The QUIC/UDP listener could not bind (privileged port, port in use, bad host)."""

    def __init__(self, host: str, port: int, errno_value: int | None) -> None:
        self.host = host
        self.port = port
        self.errno_value = errno_value
        super().__init__(f"cannot bind {host}:{port}")


class ReadyFileError(Exception):
    """The readiness PID file could not be written (missing directory, permission)."""

    def __init__(self, path: str, errno_value: int | None) -> None:
        self.path = path
        self.errno_value = errno_value
        self.reason = os.strerror(errno_value) if errno_value is not None else "write failed"
        super().__init__(f"cannot write the readiness file {path}: {self.reason}")


class MetricsBindError(Exception):
    """The metrics listener could not bind (port in use, address unavailable)."""

    def __init__(self, host: str, port: int, errno_value: int | None) -> None:
        self.host = host
        self.port = port
        self.errno_value = errno_value
        super().__init__(f"cannot bind {host}:{port}")


def _errno_from(exc: BaseException) -> int | None:
    """Return the OS errno behind a bind failure, from ``exc`` or its cause.

    ``aioquic`` wraps the underlying ``create_datagram_endpoint`` error in a bare
    ``OSError("could not bind to local_addr …")`` without an ``errno``; the real
    ``PermissionError``/``OSError`` (carrying the errno) is chained as
    ``__cause__``.
    """
    if isinstance(exc, OSError) and exc.errno is not None:
        return exc.errno
    cause = exc.__cause__
    if isinstance(cause, OSError):
        return cause.errno
    return None


def _bind_error_message(exc: ListenerBindError) -> str:
    """Actionable stderr message for a failed listener bind (exit code 3)."""
    target = f"{exc.host}:{exc.port}"
    if exc.errno_value in (errno.EACCES, errno.EPERM):
        return (
            f"error: cannot bind the QUIC/UDP listener on {target} — permission denied.\n"
            "       Ports below 1024 (the 443 default) need root or CAP_NET_BIND_SERVICE.\n"
            "       Fix: use an unprivileged port (hsync-bootnode run --port 8443), run as\n"
            "       root, or grant the capability to the binary:\n"
            "         sudo setcap cap_net_bind_service=+ep <hsync-bootnode>\n"
            "       The packaged systemd unit already grants CAP_NET_BIND_SERVICE."
        )
    if exc.errno_value == errno.EADDRINUSE:
        return (
            f"error: cannot bind the QUIC/UDP listener on {target} — address already in use.\n"
            "       Another process or another node instance is using that UDP port.\n"
            "       Stop it, or pick a free port: hsync-bootnode run --port <PORT>"
        )
    if exc.errno_value in (errno.EADDRNOTAVAIL, errno.EINVAL):
        return (
            f"error: cannot bind the QUIC/UDP listener on {target} — the address is not available.\n"
            "       --host must be a local interface address, or 0.0.0.0 to listen on all of them."
        )
    reason = os.strerror(exc.errno_value) if exc.errno_value is not None else "bind failed"
    return (
        f"error: cannot bind the QUIC/UDP listener on {target}: {reason}.\n"
        "       Check --host/--port; ports below 1024 need root or CAP_NET_BIND_SERVICE."
    )


def _ready_file_error_message(exc: ReadyFileError) -> str:
    """Actionable stderr message for an unwritable readiness file (exit code 4)."""
    target = exc.path
    if exc.errno_value == errno.ENOENT:
        return (
            f"error: cannot write the readiness file {target} — no such directory.\n"
            "       The parent directory must exist before the node starts: create it,\n"
            "       or drop --ready-file when nothing awaits the readiness signal."
        )
    if exc.errno_value in (errno.EACCES, errno.EPERM, errno.EROFS):
        return (
            f"error: cannot write the readiness file {target} — permission denied.\n"
            "       Point --ready-file at a path writable by the node's user."
        )
    if exc.errno_value == errno.EEXIST:
        return (
            f"error: cannot write the readiness file {target} — the path already exists.\n"
            "       A stale file from a previous run is not overwritten by design: remove it."
        )
    return (
        f"error: cannot write the readiness file {target}: {exc.reason}.\n"
        "       Check --ready-file (HSYNC_BOOTNODE_READY_FILE)."
    )


def _metrics_bind_error_message(exc: MetricsBindError) -> str:
    """Actionable stderr message for a failed metrics bind (exit code 3)."""
    target = f"{exc.host}:{exc.port}"
    if exc.errno_value == errno.EADDRINUSE:
        return (
            f"error: cannot bind the metrics listener on {target} — address already in use.\n"
            "       Pick another port (--metrics-port) or stop the process holding it."
        )
    reason = os.strerror(exc.errno_value) if exc.errno_value is not None else "bind failed"
    return (
        f"error: cannot bind the metrics listener on {target}: {reason}.\n"
        "       The endpoint only listens on a loopback address (--metrics-host)."
    )


async def _async_main(
    host: str,
    ports: list[int],
    handler: BootHandler,
    upnp: bool,
    ready_file: str | None = None,
    *,
    identity: NodeIdentity | None = None,
    enforce_rate_limits: bool = True,
    limits: ResourceLimits | None = None,
    stats: NodeStats | None = None,
    metrics: MetricsEndpoint | None = None,
    stats_file: str | None = None,
    stats_interval: float = 15.0,
) -> None:
    # The handler owns the aggregate counters; the guard and the exposition share
    # that instance so every sink reports the same numbers.
    stats = stats if stats is not None else handler.stats
    # The connection guard is the transport-level twin of the frame rate
    # limits: per-IP handshake budget, per-IP cap and a process-wide cap on
    # open connections, all sized from the host resources. Disabled together
    # with the frame limits by --no-rate-limit (the benchmark seam).
    guard_limits = limits if limits is not None else ResourceLimits.detect()
    connection_guard = (
        ConnectionGuard(
            active_max=guard_limits.max_active_connections_per_ip,
            global_max=guard_limits.max_active_connections,
            stats=stats,
        )
        if enforce_rate_limits
        else None
    )
    try:
        servers, bound_ports, identity, failures = await start_servers(
            host,
            ports,
            handler,
            retry=True,
            identity=identity,
            connection_guard=connection_guard,
        )
    except OSError as exc:
        raise ListenerBindError(host, ports[0], _errno_from(exc)) from exc
    # Best-effort: a requested port that could not bind (address in use, e.g. 53
    # held by the local resolver) is skipped with an always-on, peer-free warning
    # instead of failing the whole node.
    for failed_port, failure in failures:
        errno_value = _errno_from(failure)
        warn_event(
            "listener port unavailable",
            port=failed_port,
            reason=os.strerror(errno_value) if errno_value is not None else "bind failed",
        )
    bound_display = ",".join(str(p) for p in bound_ports)
    typer.echo(f"  running   : {host}:{bound_display} — cert fingerprint {identity.fingerprint}")
    debug_log(f"listeners bound {host}:{bound_display} (retry+address-validation)")

    tasks: list[asyncio.Task] = []
    upnp_managers: list[UpnpManager] = []
    metrics_server: MetricsServer | None = None
    # Only remove a readiness file THIS process created: with O_EXCL a pre-existing
    # path (another instance, a stale file) is left untouched on every exit path.
    ready_written = False
    try:
        if metrics is not None:
            # Bound before READY: a service manager must never see the unit active
            # while the endpoint the operator asked for is unreachable.
            try:
                metrics_server = await MetricsServer.start(endpoint=metrics, stats=stats)
            except OSError as exc:
                raise MetricsBindError(metrics.host, metrics.port, _errno_from(exc)) from exc
        if ready_file:
            _write_ready_file(ready_file)
            ready_written = True
            debug_log(f"readiness written to {ready_file}")

        # Readiness for the service manager: the same condition as the ready
        # file (every requested listener bound), so a Type=notify start waits
        # for the socket the clients actually use.
        notify_ready(stats.status_text())

        tasks.append(asyncio.create_task(_prune_loop(handler, connection_guard)))
        if stats_file is not None or notify_available():
            tasks.append(asyncio.create_task(_stats_loop(stats, stats_file, stats_interval)))
        watchdog = watchdog_interval()
        if watchdog is not None:
            tasks.append(asyncio.create_task(_watchdog_loop(watchdog)))
        if upnp:
            # One mapping per bound port: every offered door must also be mapped
            # on the router, not just the first. A client may reach the node on
            # any of them (e.g. 53 when its egress firewall blocks UDP 443), so a
            # single mapping would leave the extra doors unreachable from the WAN.
            for port in bound_ports:
                manager = UpnpManager(port)
                upnp_managers.append(manager)
                tasks.append(asyncio.create_task(manager.run()))

        await asyncio.Future()  # serve forever
    finally:
        # The stop is intentional and bounded: announce it before the transports
        # close, so the service manager does not treat the drop as a failure.
        notify_stopping()
        # Drop relayed sessions before the transports close, so every peer sees a
        # stream close instead of a half-open tunnel the QUIC stack tears down.
        handler.relay.close()
        for server in servers:
            server.close()
        if metrics_server is not None:
            await metrics_server.aclose()
        for task in tasks:
            task.cancel()
        # Stop the refresh loops before removing the mappings, so a cancelled
        # cycle cannot re-add what close() just deleted (best-effort, bounded).
        await asyncio.gather(*tasks, return_exceptions=True)
        for manager in upnp_managers:
            await manager.close()
        if ready_written and ready_file:
            _remove_ready_file(ready_file)


def _write_ready_file(path: str) -> None:
    """Write this process's PID to ``path`` (readiness seam, no peer data).

    Created with ``O_EXCL | O_NOFOLLOW`` so a predictable path in an
    attacker-writable directory cannot be redirected (symlink) to clobber an
    existing file under the node's privileges.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        # Actionable exit (code 4) instead of a traceback: the listener is up but
        # the operator's orchestration seam cannot be honoured.
        raise ReadyFileError(path, exc.errno) from exc
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))


def _remove_ready_file(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


async def _prune_loop(
    handler: BootHandler, connection_guard: ConnectionGuard | None = None
) -> None:
    """Spec: prune the TTL routing table every 15 s."""
    while True:
        await asyncio.sleep(handler.prune_interval)
        # Chunked: one unbudgeted sweep over a large stale backlog would block the
        # event loop for its whole duration, so the background sweep yields
        # between bounded batches instead (the request path is bounded too). An
        # explicit ``now`` keeps each chunk record-only; the limiter-state sweep
        # runs once per tick (``prune()`` is the only path that evicts it), never
        # once per chunk.
        now = time.monotonic()
        while handler.prune(now, max_remove=REQUEST_PATH_PRUNE_BUDGET) >= REQUEST_PATH_PRUNE_BUDGET:
            await asyncio.sleep(0)
        handler.prune()
        if connection_guard is not None:
            # Same cadence as the routing sweep: forget closed-and-quiet IPs so
            # the guard map cannot grow without bound under IP churn.
            connection_guard.evict_stale()


async def _watchdog_loop(interval: float) -> None:
    """Feed the service manager's watchdog at half the armed interval.

    ``interval`` is already half of ``WatchdogSec=`` (:func:`watchdog_interval`),
    so one missed ping still leaves a full period for the next one to arrive. A
    wedged event loop stops pinging and the service manager restarts the node.
    """
    while True:
        await asyncio.sleep(interval)
        notify_watchdog()


def _write_stats_file(path: str, body: str) -> None:
    """Replace the stats file atomically so a scraper never reads a partial file.

    ``O_NOFOLLOW`` on the temporary name keeps a symlink planted in the directory
    from redirecting the write, and ``os.replace`` leaves the reader with either
    the previous snapshot or the new one.
    """
    temporary = f"{path}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(temporary, flags, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)
        os.replace(temporary, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


async def _stats_loop(stats: NodeStats, stats_file: str | None, interval: float) -> None:
    """Publish the aggregates on a fixed cadence: ``STATUS=`` and the text file.

    Started only when a sink exists, so a node without a service manager and
    without ``--stats-file`` never wakes up for nothing.
    """
    while True:
        await asyncio.sleep(interval)
        notify_status(stats.status_text())
        if stats_file is None:
            continue
        try:
            _write_stats_file(stats_file, stats.render_prometheus())
        except OSError as exc:
            stats.stats_write_failed()
            warn_event(
                "stats file not writable",
                path=stats_file,
                reason=exc.strerror or "write failed",
            )


def _load_keys(keys_fd: int | None, keys_file: str | None = None) -> dict[str, SecretStr]:
    """Load 'bucket=<hex-key>' lines from a descriptor or an operator file.

    ``--keys-fd`` is the preferred source on POSIX service managers: the key
    payload never has a path inside the sandbox that the process could reopen.
    ``--keys-file`` is the portable alternative (a Windows service cannot
    inherit an arbitrary descriptor): the file is read once at startup, never
    written, and may be deleted by the operator afterwards. The two sources are
    mutually exclusive.
    """
    if keys_fd is not None and keys_file is not None:
        raise BootConfigError("--keys-fd and --keys-file are mutually exclusive")
    if keys_file is not None:
        return _load_keys_file(keys_file)
    if keys_fd is None or keys_fd < 0:
        return {}
    _reject_std_secret_fd(keys_fd, what="group keys", example="--keys-fd 5")
    return _parse_keys(_read_fd(keys_fd))


def _reject_std_secret_fd(fd: int, *, what: str, example: str) -> None:
    """Refuse stdout/stderr as a secret source (a misrouted descriptor)."""
    if fd in (1, 2):
        raise BootConfigError(
            f"refusing to read {what} from fd {fd} (stdout/stderr); "
            f"pass the descriptor of the actual secret file (e.g. {example})"
        )


def _read_secret_file(path: str, *, what: str) -> str:
    """Read an operator-managed secret file once (symlink and non-files refused).

    ``what`` names the secret in the messages ("group keys", "the metrics
    token"); the transport policy is shared and the strength rules stay with the
    caller, so both secrets are read with the same guarantees.
    """
    target = Path(path)
    if target.is_symlink():
        raise BootConfigError(f"refusing to read {what} from symlink {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags)
    except OSError as exc:
        raise BootConfigError(f"cannot open {what} file {path}: {exc.strerror}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise BootConfigError(f"{what} source {path} is not a regular file")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o037:
            # Group-write/execute or any world access is a real secret-handling
            # defect; 0640 (group read) is accepted for service accounts. The
            # file is the operator's (not peer data): warn on the always-on
            # channel and keep serving instead of refusing a working deployment.
            warn_event(
                f"{what} file permissions are too open",
                path=str(path),
                reason=f"mode {oct(mode)}; restrict it to 0600 or 0640",
            )
        return _read_fd(fd, source=f"file {path}")
    finally:
        os.close(fd)


def _load_keys_file(path: str) -> dict[str, SecretStr]:
    """Read an operator-managed keys file once (see :func:`_load_keys`)."""
    return _parse_keys(_read_secret_file(path, what="group keys"))


def _is_loopback_host(host: str) -> bool:
    """True for a loopback literal or ``localhost``; nothing else is accepted."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _read_token(token_fd: int | None, token_file: str | None) -> str:
    """Read the single-line metrics bearer token from its descriptor or file."""
    if token_fd is not None and token_file is not None:
        raise BootConfigError("--metrics-token-fd and --metrics-token-file are mutually exclusive")
    if token_file is not None:
        raw = _read_secret_file(token_file, what="the metrics token")
        source = f"file {token_file}"
    elif token_fd is not None:
        _reject_std_secret_fd(token_fd, what="the metrics token", example="--metrics-token-fd 6")
        raw = _read_fd(token_fd, source="--metrics-token-fd")
        source = "--metrics-token-fd"
    else:
        raise BootConfigError(
            "the metrics endpoint requires a bearer token: pass --metrics-token-fd "
            "(a systemd credential) or --metrics-token-file"
        )
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) != 1:
        raise BootConfigError(f"{source} must hold exactly one line: the bearer token")
    token = lines[0]
    if len(token) < MIN_GROUP_KEY_CHARS:
        # The token is the endpoint's only authorization, so it keeps the same
        # strength floor as a group key: it is the only entropy behind it.
        raise BootConfigError(
            f"the metrics token must be at least {MIN_GROUP_KEY_CHARS} characters "
            f"(got {len(token)}); mint one with: openssl rand -hex 32"
        )
    return token


def _resolve_metrics(
    *,
    host: str,
    port: int | None,
    token_fd: int | None,
    token_file: str | None,
) -> MetricsEndpoint | None:
    """Resolve the /metrics listener, or ``None`` when it is disabled.

    Rigid by design: the endpoint serves plain HTTP, so it only listens on a
    loopback address, and it always requires a bearer token. Loopback is not an
    authorization boundary (any local user, a proxy or an SSH tunnel can reach
    it), so an unauthenticated endpoint is a configuration error, never a mode.
    """
    if port is None:
        if token_fd is not None or token_file is not None:
            raise BootConfigError(
                "--metrics-token-fd / --metrics-token-file require --metrics-port"
            )
        return None
    if not _is_loopback_host(host):
        raise BootConfigError(
            f"--metrics-host {host} is not a loopback address: /metrics serves plain "
            "HTTP and only listens on 127.0.0.1 or ::1 (front it with a proxy or an "
            "SSH tunnel instead)"
        )
    return MetricsEndpoint(host=host, port=port, token=SecretStr(_read_token(token_fd, token_file)))


def _metrics_display(endpoint: MetricsEndpoint | None) -> str:
    """One banner line for the metrics endpoint (never the token)."""
    if endpoint is None:
        return "off"
    host = f"[{endpoint.host}]" if ":" in endpoint.host else endpoint.host
    return f"http://{host}:{endpoint.port}{REST_METRICS_PATH} (loopback, Bearer token)"


def _relay_display(enabled: bool, bandwidth_kib: int, session_bytes: int, idle_s: int) -> str:
    """One banner line for the data relay (never peer-identifying)."""
    if not enabled:
        return "disabled"
    rate = "unlimited" if bandwidth_kib == 0 else f"{bandwidth_kib} KiB/s"
    cap = "unlimited" if session_bytes == 0 else f"{session_bytes} bytes/session"
    return f"enabled (opaque TLS; {rate} total, {cap}, idle {idle_s}s)"


def _check_stats_target(path: str) -> None:
    """Fail fast on a stats-file path whose directory cannot exist."""
    parent = os.path.dirname(path) or "."
    if not os.path.isdir(parent):
        raise BootConfigError(
            f"--stats-file {path}: directory {parent} does not exist (create it, or "
            "point the flag at a writable directory)"
        )


def _parse_keys(raw: str) -> dict[str, SecretStr]:
    """Parse 'bucket=<hex-key>' lines (comments and blank lines ignored).

    Both halves are validated with their SSOT: the bucket name must be a
    canonical HSYNC bucket (otherwise the key could never authorize a wire
    frame) and the key must meet :func:`validate_group_key`'s strength floor
    (it is the bucket token's only entropy). A bucket may appear only once, and a
    malformed line is a configuration error rather than a silent skip.
    """
    keys: dict[str, SecretStr] = {}
    for line_number, raw_line in enumerate(raw.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        bucket, _, key = line.partition("=")
        bucket = bucket.strip()
        key = key.strip()
        if not bucket or not key:
            raise BootConfigError(
                f"malformed group key line {line_number}: expected 'bucket=<hex-key>'"
            )
        if not is_valid_bucket_name(bucket):
            raise BootConfigError(
                f"invalid bucket name {bucket!r} on line {line_number} "
                "(a canonical HSYNC bucket name is required)"
            )
        try:
            validate_group_key(key)
        except ValueError as exc:
            raise BootConfigError(f"{exc} (line {line_number})") from exc
        if bucket in keys:
            raise BootConfigError(f"duplicate group key for bucket {bucket!r} (line {line_number})")
        keys[bucket] = SecretStr(key)
    return keys


def _read_fd(fd: int, *, source: str | None = None) -> str:
    """Read all bytes from an integer file descriptor (fd 1/2 excluded upstream).

    The total payload is bounded (keys are finitely many short lines) and, on
    POSIX, the wait is bounded in time too: a descriptor that never returns EOF
    (a misrouted stdin, a pipe held open) fails fast instead of stalling startup
    or growing without bound. On Windows ``select`` does not cover pipes/files,
    so there only the byte cap applies. ``source`` only labels error messages
    (a descriptor or an operator file).
    """
    where = source or f"fd {fd}"
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + KEYS_FD_READ_TIMEOUT_SECONDS
    while True:
        if not _fd_readable_before(fd, deadline):
            raise BootConfigError(
                f"group keys not received within {KEYS_FD_READ_TIMEOUT_SECONDS:g}s on "
                f"{where}: the descriptor must present whole, short lines and then EOF"
            )
        chunk = os.read(fd, 4096)
        if not chunk:
            break
        total += len(chunk)
        if total > KEYS_FD_MAX_BYTES:
            raise BootConfigError(
                f"group keys payload exceeded {KEYS_FD_MAX_BYTES} bytes on {where}: "
                "the descriptor must present whole, short lines and EOF"
            )
        chunks.append(chunk)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        # A mangled key byte would silently derive a different token, so a
        # non-UTF-8 source is a configuration error instead of substituted text.
        raise BootConfigError(f"group keys on {where} are not valid UTF-8") from exc


def _fd_readable_before(fd: int, deadline: float) -> bool:
    """Whether ``fd`` reports readable before ``deadline`` (best effort).

    A selectable descriptor (a pipe, a socket, a regular file on POSIX) is waited
    on with ``select``; a timeout returns ``False``. On Windows, and for any
    descriptor ``select`` cannot cover, it reports ready so the byte cap — not a
    timer — bounds the read.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    if os.name == "nt":
        return True
    try:
        readable, _, _ = select.select([fd], [], [], remaining)
    except (OSError, ValueError):
        return True
    return bool(readable)


def _install_uvloop() -> None:
    """Use uvloop where available; the stdlib asyncio loop otherwise (Windows)."""
    if sys.platform == "win32":
        return
    try:
        import uvloop
    except ImportError:
        return
    uvloop.install()


def _install_shutdown_handlers() -> None:
    """Make SIGINT and SIGTERM run the same graceful teardown; ignore SIGHUP.

    SIGINT is installed explicitly because a non-interactive parent (nohup, a
    background job, some service managers) can start us with SIGINT ignored; the
    default handler would then never run. SIGTERM's default action would skip the
    ``finally`` in ``_async_main`` (transport close + ready-file removal).
    Raising ``KeyboardInterrupt`` from either handler reuses the graceful path
    caught around ``asyncio.run``.

    SIGHUP is ignored: a hangup (a terminal closed, an SSH session dropped, a PTY
    torn down) is not a stop request, so the node keeps serving instead of dying
    silently on the default disposition. Stopping stays on SIGTERM/SIGINT, which
    every service manager and Ctrl+C use.
    """

    def _handle(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal.SIG_IGN)


if __name__ == "__main__":
    app()
