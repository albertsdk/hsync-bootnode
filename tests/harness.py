"""Language-neutral black-box harness for the ``boot/1`` bootstrap node.

The black-box suite must stay independent of any implementation language:
it spawns the bootnode executable (path via ``HSYNC_BOOTNODE_BIN``, defaulting
to the Python build), waits for the ``HSYNC_BOOTNODE_READY_FILE`` readiness
seam, and drives it **only** through the public CLI and the ``boot/1`` wire
protocol (QUIC/UDP, NDJSON, ALPN ``hsync-boot/1``). Nothing in here imports
``hsync_bootnode`` — the same module will validate the future ``rust/`` port
unchanged.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import os
import random
import signal
import socket
import ssl
import string
import subprocess
import time
from collections.abc import Mapping, Sequence
from enum import Enum
from pathlib import Path
from typing import NamedTuple

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

REPO_ROOT = Path(__file__).resolve().parents[1]
BOOT_ALPN = "hsync-boot/1"
_CID_ALPHABET = string.ascii_letters + string.digits
_FP = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"

# Single-frame byte bound on the wire (spec: oversized frames are refused and the
# session dropped). Mirrors ``hsync_bootnode.server.MAX_FRAME_BYTES``; duplicated
# here so the language-neutral harness never imports the implementation.
MAX_FRAME_BYTES = 8192


def resolve_bin() -> str:
    """Bootnode executable path: ``HSYNC_BOOTNODE_BIN`` or the Python build."""
    return os.environ.get("HSYNC_BOOTNODE_BIN") or str(
        REPO_ROOT / "python" / ".venv" / "bin" / "hsync-bootnode"
    )


# Service-manager variables the suite always scrubs: a run inside a systemd
# session would otherwise leak the runner's own manager into the spawned node,
# which would then announce READY/WATCHDOG to it.
_SERVICE_MANAGER_VARS = frozenset({"NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"})


def scrub_environment() -> dict[str, str]:
    """Environment minus every ``HSYNC_*``/service-manager variable (isolation contract)."""
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("HSYNC_") and key not in _SERVICE_MANAGER_VARS
    }


def run_cli(args: Sequence[str], timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
    """Run the bootnode CLI once with a scrubbed environment (isolation contract).

    Black-box checks that only inspect the CLI surface (``--version``, fail-fast
    exit codes) must not spawn a process by hand: this helper resolves the
    executable with :func:`resolve_bin` and runs it with :func:`scrub_environment`,
    exactly like :func:`start_bootnode`.
    """
    return subprocess.run(
        [resolve_bin(), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=scrub_environment(),
    )


def free_udp_port(family: int = socket.AF_INET) -> int:
    """A free loopback UDP port (not reserved — the caller binds it).

    ``family`` selects the address family so an IPv6 listener
    (``--host [::1]``) can be given a free ``::1`` port, not an IPv4 one.
    """
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.bind(("::1", 0) if family == socket.AF_INET6 else ("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def client_config() -> QuicConfiguration:
    """QUIC client configuration for ``boot/1``.

    The bootnode's TLS identity is self-signed, so the client cannot verify it by
    chain; only ALPN ``hsync-boot/1`` is asserted (the fingerprint pin is the
    trust anchor, exercised by the identity black-box tests). Single definition
    shared by the black-box suite and every benchmark that opens a ``boot/1``
    connection.
    """
    return QuicConfiguration(is_client=True, alpn_protocols=[BOOT_ALPN], verify_mode=ssl.CERT_NONE)


def derive_bucket_token(key: bytes, bucket: str) -> str:
    """Spec §Auth: ``HMAC-SHA256(key, "boot/1" || bucket)[:32]`` hex (64 chars)."""
    return hmac.new(key, b"boot/1" + bucket.encode("utf-8"), hashlib.sha256).digest()[:32].hex()


def random_cid(rng: random.Random) -> str:
    """A fresh spec-compliant 21-char CID (``^[A-Za-z0-9]{21}$``)."""
    return "".join(rng.choice(_CID_ALPHABET) for _ in range(21))


def random_bucket(rng: random.Random) -> str:
    """A fresh bucket name so each test starts from a clean namespace."""
    return "bb-" + "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(10))


# ---------------------------------------------------------------------------
# Frame builders (wire-level dicts; no implementation imports)
# ---------------------------------------------------------------------------


def register_frame(
    cid: str,
    bucket: str,
    group: str | None = None,
    *,
    token: str | None = None,
    host: str = "198.51.100.7",
    port: int = 443,
    endpoints: bool = True,
    capacity: int = 20,
    **extra: object,
) -> dict:
    frame: dict = {
        "protocol_version": "boot/1",
        "type": "register",
        "cid": cid,
        "bucket": bucket,
        "cert_fp": _FP,
        "version": "1.0.0",
        "capacity": capacity,
        "connected": 3,
    }
    if group is not None:
        frame["group"] = group
    if endpoints:
        frame["endpoints"] = [{"proto": "tcp", "host": host, "port": port}]
    if token is not None:
        frame["bucket_token"] = token
    frame.update(extra)
    return frame


def refresh_frame(
    cid: str,
    bucket: str,
    group: str | None = None,
    *,
    token: str | None = None,
    connected: int | None = None,
) -> dict:
    frame: dict = {
        "protocol_version": "boot/1",
        "type": "refresh",
        "cid": cid,
        "bucket": bucket,
    }
    if group is not None:
        frame["group"] = group
    if token is not None:
        frame["bucket_token"] = token
    if connected is not None:
        frame["connected"] = connected
    return frame


def leave_frame(cid: str, bucket: str, *, token: str | None = None) -> dict:
    """A ``leave`` frame; ``token`` is optional on the wire (required by private nodes)."""
    frame = {"protocol_version": "boot/1", "type": "leave", "cid": cid, "bucket": bucket}
    if token is not None:
        frame["bucket_token"] = token
    return frame


def query_frame(
    bucket: str,
    group: str | None = None,
    *,
    token: str | None = None,
    limit: int = 20,
) -> dict:
    frame: dict = {
        "protocol_version": "boot/1",
        "type": "query",
        "bucket": bucket,
        "limit": limit,
    }
    if group is not None:
        frame["group"] = group
    if token is not None:
        frame["bucket_token"] = token
    return frame


# ---------------------------------------------------------------------------
# Process lifecycle
# ---------------------------------------------------------------------------


class BootnodeProc:
    """A running bootnode subprocess + its readiness/log handles."""

    def __init__(
        self,
        proc: subprocess.Popen,
        port: int,
        ready_file: Path | None,
        log_dir: Path,
        *,
        ports: Sequence[int] | None = None,
    ):
        self.proc = proc
        self.port = port
        # All bound UDP ports (multi-port, decision 57); ``port`` is the primary.
        self.ports: tuple[int, ...] = tuple(ports) if ports else (port,)
        self.ready_file = ready_file
        # PID of the bootnode *application* process, read from the readiness file
        # by ``wait_ready``. It can differ from ``pid`` (the launcher): a
        # onefile-packaged binary (PyInstaller) runs the app in a child process.
        self.node_pid: int | None = None
        self._stdout = log_dir / "stdout.log"
        self._stderr = log_dir / "stderr.log"

    @property
    def pid(self) -> int:
        """PID of the launched process (the packaging launcher, if any)."""
        return int(self.proc.pid)

    def stderr_text(self) -> str:
        if self._stderr.exists():
            return self._stderr.read_text(encoding="utf-8", errors="replace")
        return ""

    def stdout_text(self) -> str:
        """Banner/startup output the CLI printed before serving (non-PII)."""
        if self._stdout.exists():
            return self._stdout.read_text(encoding="utf-8", errors="replace")
        return ""


def start_bootnode(
    tmp_path: Path,
    *,
    port: int | None = None,
    ports: Sequence[int] | None = None,
    host: str = "127.0.0.1",
    args: Sequence[str] = (),
    keys: Mapping[str, str] | None = None,
    protected: Sequence[str] = (),
    ttl: int | None = None,
    debug: bool = False,
    ready: bool = True,
    no_rate_limit: bool = False,
    private: bool = False,
    ephemeral: bool = True,
    env_extra: Mapping[str, str] | None = None,
) -> BootnodeProc:
    """Start a bootnode subprocess; ``keys`` are provisioned via ``--keys-fd``.

    ``host`` is the ``--host`` bind address (default loopback IPv4); pass
    ``"[::1]"`` for an IPv6 listener (the free port is then reserved on ``::1``).
    ``private`` appends ``--private``; ``env_extra`` adds environment variables on
    top of the scrubbed environment (used to exercise the envvar form of a flag,
    e.g. ``HSYNC_BOOTNODE_PRIVATE=1``, exactly as the service units set it).
    ``ephemeral`` (default) appends ``--ephemeral`` so black-box tests never write
    to the operator's/CI's XDG state dir; pass ``ephemeral=False`` (with an
    explicit ``--identity``/``HSYNC_BOOTNODE_IDENTITY``) to test persistence.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    if ports is not None:
        resolved_ports = list(ports)
        port = resolved_ports[0]
        port_args = ["--ports", ",".join(str(p) for p in resolved_ports)]
    else:
        port = port or free_udp_port(family)
        resolved_ports = [port]
        port_args = ["--port", str(port)]
    ready_file = tmp_path / "ready.pid" if ready else None

    cmd = [resolve_bin(), "run", "--host", host, *port_args]
    if ephemeral:
        cmd += ["--ephemeral"]
    if ttl is not None:
        cmd += ["--ttl", str(ttl)]
    for bucket in protected:
        cmd += ["--protected-bucket", bucket]
    if debug:
        cmd += ["--debug"]
    if no_rate_limit:
        cmd += ["--no-rate-limit"]
    if private:
        cmd += ["--private"]
    cmd += list(args)

    env = scrub_environment()
    env.update(env_extra or {})
    if ready_file is not None:
        env["HSYNC_BOOTNODE_READY_FILE"] = str(ready_file)

    pass_fds: tuple[int, ...] = ()
    if keys:
        read_fd, write_fd = os.pipe()
        payload = b"".join(f"{b}={k}\n".encode() for b, k in keys.items())
        os.write(write_fd, payload)
        os.close(write_fd)
        cmd += ["--keys-fd", str(read_fd)]
        pass_fds = (read_fd,)

    stdout_f = (tmp_path / "stdout.log").open("wb")
    stderr_f = (tmp_path / "stderr.log").open("wb")
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=stdout_f,
        stderr=stderr_f,
        pass_fds=pass_fds,
        start_new_session=True,
    )
    stdout_f.close()
    stderr_f.close()
    if keys:
        os.close(read_fd)

    handle = BootnodeProc(proc, port, ready_file, tmp_path, ports=resolved_ports)
    if ready:
        try:
            wait_ready(handle)
        except BaseException:
            terminate(handle)
            raise
    return handle


def ready_node_pid(ready_file: Path) -> int | None:
    """Return the bootnode application PID once the ready file holds it, else ``None``.

    Readiness is signalled by the file containing a positive integer — the
    *application* PID (``os.getpid()``). For a onefile-packaged binary that is
    the child of the launcher process, so it must not be compared with
    ``subprocess.Popen.pid``.
    """
    try:
        text = ready_file.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not text.isdigit():
        return None
    pid = int(text)
    return pid if pid > 0 else None


def wait_ready(handle: BootnodeProc, timeout: float = 15.0) -> None:
    """Wait until the bootnode signals readiness through its ready file.

    The file must appear holding the application PID; on success it is stored on
    ``handle.node_pid``. Readiness is deliberately *not* keyed on the launcher
    PID: a onefile-packaged binary runs the app in a child process, so its PID
    differs from ``subprocess.Popen.pid``. The ready-file path is unique per
    test, so the file appearing is an unambiguous, packaging-independent signal.
    """
    assert handle.ready_file is not None, "readiness file not configured"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        node_pid = ready_node_pid(handle.ready_file)
        if node_pid is not None:
            handle.node_pid = node_pid
            return
        if handle.proc.poll() is not None:
            raise RuntimeError(
                f"bootnode exited before ready (rc={handle.proc.returncode})\n"
                f"stderr:\n{handle.stderr_text()}"
            )
        time.sleep(0.05)
    raise TimeoutError(f"bootnode not ready within {timeout}s\nstderr:\n{handle.stderr_text()}")


def terminate(handle: BootnodeProc) -> None:
    """Terminate the bootnode (SIGTERM, then SIGKILL fallback); no orphans.

    The process runs in its own session (``start_new_session=True``), so the
    whole group — including a onefile launcher's application child — is
    signalled and reaped together on every exit path.
    """
    proc = handle.proc
    if proc.poll() is not None:
        return
    if hasattr(os, "killpg"):
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    else:  # pragma: no cover - Windows fallback
        proc.terminate()
    try:
        proc.wait(timeout=10.0)
    except subprocess.TimeoutExpired:
        if hasattr(os, "killpg"):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:  # pragma: no cover - Windows fallback
            proc.kill()
        proc.wait(timeout=5.0)


def proc_rss_mb(pid: int) -> float:
    """Resident set size of ``pid`` in MiB (Linux ``/proc``); ``-1.0`` if unavailable.

    Mirrors ``bench/common.proc_rss_mb``; kept here as well so the test harness
    has no dependency on the stdlib-only benchmark helper and can run on any
    checkout. Used by the stress suite's leak bound.
    """
    try:
        status = (Path("/proc") / str(pid) / "status").read_text(encoding="utf-8")
    except OSError:
        return -1.0
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) / 1024.0
    return -1.0


# ---------------------------------------------------------------------------
# QUIC client (language-neutral: talks only boot/1 over the wire)
# ---------------------------------------------------------------------------


class RawOutcome(Enum):
    """Outcome of a raw send: the server's visible reaction, not the payload."""

    REPLY = "reply"  # a response line arrived
    SILENT = "silent"  # no response within timeout (stream left open)
    CLOSED = "closed"  # server closed the stream (EOF)


class RawResult(NamedTuple):
    outcome: RawOutcome
    data: bytes | None


class BootClient:
    """One loopback QUIC connection speaking ``boot/1`` NDJSON frames."""

    def __init__(self, port: int, host: str = "127.0.0.1") -> None:
        self._port = port
        self._host = host
        self._protocol = None
        self._stack: contextlib.AsyncExitStack | None = None

    async def __aenter__(self) -> BootClient:
        config = client_config()
        self._stack = contextlib.AsyncExitStack()
        await self._stack.__aenter__()
        self._protocol = await self._stack.enter_async_context(
            connect(self._host, self._port, configuration=config)
        )
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        stack = self._stack
        self._protocol = None
        self._stack = None
        if stack is not None:
            await stack.__aexit__(exc_type, exc, tb)

    async def exchange(self, frame: dict, timeout: float = 5.0) -> dict:
        """Send one frame and return the single reply frame."""
        reader, writer = await self._protocol.create_stream()  # type: ignore[union-attr]
        try:
            writer.write((json.dumps(frame) + "\n").encode("utf-8"))
            await writer.drain()
            raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
            return json.loads(raw)
        finally:
            writer.close()

    async def pipeline(self, frames: Sequence[dict], timeout: float = 5.0) -> list[dict]:
        """Send several frames on one stream; each gets its own reply, in order."""
        reader, writer = await self._protocol.create_stream()  # type: ignore[union-attr]
        try:
            payload = "".join(json.dumps(f) + "\n" for f in frames).encode("utf-8")
            writer.write(payload)
            await writer.drain()
            replies = []
            for _ in frames:
                raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
                replies.append(json.loads(raw))
            return replies
        finally:
            writer.close()

    async def send_raw(self, data: bytes, timeout: float = 1.0) -> RawResult:
        """Send raw bytes and classify the server's visible reaction.

        ``SILENT`` (timeout, stream open) vs ``CLOSED`` (EOF, stream closed) is
        a contract distinction: malformed/unknown frames are silently dropped
        with the stream kept open, while an oversized frame closes the stream.
        """
        reader, writer = await self._protocol.create_stream()  # type: ignore[union-attr]
        try:
            writer.write(data)
            await writer.drain()
            try:
                raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
            except TimeoutError:
                return RawResult(RawOutcome.SILENT, None)
            if not raw:
                return RawResult(RawOutcome.CLOSED, None)
            return RawResult(RawOutcome.REPLY, raw)
        finally:
            writer.close()
