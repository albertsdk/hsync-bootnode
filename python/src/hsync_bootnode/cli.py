"""Typer CLI for the ``hsync-bootnode`` Python v1 process (Fase 1).

Starts the single QUIC/UDP listener on ``--port`` (default 443), with RETRY +
address-validation tokens, the D11 protected buckets, per-IP/per-bucket rate
limits, STUN-echo and optional zero-touch UPnP. No-log: nothing peer-related is
ever written to disk.
"""

from __future__ import annotations

import asyncio
import os
import sys

import typer
from pydantic import SecretStr

from hsync_bootnode import __version__
from hsync_bootnode.handler import BootConfigError, BootHandler
from hsync_bootnode.server import start_server
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

# The group key payload arrives on a file descriptor ('bucket=<hex-key>' lines);
# ``HSYNC_BOOTNODE_KEYS_FD`` is the envvar form (plan §4), honoured by
# systemd/launchd/Windows service wrappers. Read once, never written.
_DEFAULT_KEYS_FD_ENV = "HSYNC_BOOTNODE_KEYS_FD"


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", help="Print version and exit."),
) -> None:
    """HSYNC P2P bootstrap node: no-log, in-memory, zero-knowledge (boot/1)."""
    if version:
        typer.echo(f"hsync-bootnode {__version__} (boot/1, Python v1)")
        raise typer.Exit()


@app.command()
def run(
    host: str = typer.Option("0.0.0.0", "--host", help="Address to bind the QUIC/UDP listener to."),
    port: int = typer.Option(
        443,
        "--port",
        min=1,
        max=65535,
        help="UDP port (default 443 for QUIC/HTTP3).",
    ),
    protected_bucket: list[str] = typer.Option(
        [],
        "--protected-bucket",
        help="Bucket requiring a valid bucket_token (repeatable). D11.",
    ),
    keys_fd: int | None = typer.Option(
        None,
        "--keys-fd",
        min=0,
        envvar=_DEFAULT_KEYS_FD_ENV,
        help="FD with group keys (one 'bucket=<hex-key>' per line). Env: HSYNC_BOOTNODE_KEYS_FD.",
    ),
    no_upnp: bool = typer.Option(False, "--no-upnp", help="Disable UPnP mapping."),
) -> None:
    """Run the bootstrap node: single QUIC/UDP listener (boot/1)."""
    try:
        keys = _load_keys(keys_fd)
        handler = BootHandler(
            protected_buckets=protected_bucket,
            group_keys=keys,
        )
    except BootConfigError as exc:
        typer.echo(f"configuration error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    _install_uvloop()

    banner = (
        f"hsync-bootnode {__version__} — boot/1, no-log, in-memory\n"
        f"  listener : {host}:{port} (QUIC/UDP, TLS 1.3, RETRY+address-validation)\n"
        f"  protected buckets: {', '.join(protected_bucket) or '(none)'}\n"
        f"  group keys loaded: {len(keys)}\n"
        f"  upnp      : {'disabled' if no_upnp else 'enabled (zero-touch)'}"
    )
    typer.echo(banner)
    try:
        asyncio.run(_async_main(host, port, handler, no_upnp))
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass  # graceful shutdown: transport closed in _async_main's finally


async def _async_main(host: str, port: int, handler: BootHandler, no_upnp: bool) -> None:
    server, bound_port, identity = await start_server(host, port, handler, retry=True)
    typer.echo(f"  running   : {host}:{bound_port} — cert fingerprint {identity.fingerprint}")

    tasks = [asyncio.create_task(_prune_loop(handler))]
    if not no_upnp:
        tasks.append(asyncio.create_task(UpnpManager(bound_port).run()))

    try:
        await asyncio.Future()  # serve forever
    finally:
        server.close()
        for task in tasks:
            task.cancel()


async def _prune_loop(handler: BootHandler) -> None:
    """Spec: prune the TTL routing table every 15 s."""
    while True:
        await asyncio.sleep(handler.prune_interval)
        handler.prune()


def _load_keys(keys_fd: int | None) -> dict[str, SecretStr]:
    """Load 'bucket=<hex-key>' lines from the given FD (cross-platform)."""
    if keys_fd is None or keys_fd < 0:
        return {}
    raw = _read_fd(keys_fd)
    keys: dict[str, SecretStr] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        bucket, _, key = line.partition("=")
        if bucket and key:
            keys[bucket.strip()] = SecretStr(key.strip())
    return keys


def _read_fd(fd: int) -> str:
    """Read all bytes from an integer file descriptor (fd 1/2 excluded)."""
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 4096)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _install_uvloop() -> None:
    """Use uvloop where available; the stdlib asyncio loop otherwise (Windows)."""
    if sys.platform == "win32":
        return
    try:
        import uvloop  # noqa: PLC0415
    except ImportError:
        return
    uvloop.install()


if __name__ == "__main__":
    app()
