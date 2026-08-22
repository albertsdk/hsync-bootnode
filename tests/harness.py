"""Language-neutral black-box harness for the ``boot/1`` bootstrap node.

The black-box suite must stay independent of any implementation language (D13):
it spawns the bootnode executable (path via ``HSYNC_BOOTNODE_BIN``, defaulting
to the Python build), waits for the ``HSYNC_BOOTNODE_READY_FILE`` readiness
seam, and drives it **only** through the public CLI and the ``boot/1`` wire
protocol (QUIC/UDP, NDJSON, ALPN ``hsync-boot/1``). Nothing in here imports
``hsync_bootnode`` — the same module will validate the future ``rust/`` and
``c/`` ports unchanged.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import os
import random
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
_FP = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"


def resolve_bin() -> str:
    """Bootnode executable path: ``HSYNC_BOOTNODE_BIN`` or the Python build."""
    return os.environ.get("HSYNC_BOOTNODE_BIN") or str(
        REPO_ROOT / "python" / ".venv" / "bin" / "hsync-bootnode"
    )


def scrub_environment() -> dict[str, str]:
    """Environment minus every ``HSYNC_*`` variable (isolation contract)."""
    return {k: v for k, v in os.environ.items() if not k.startswith("HSYNC_")}


def free_udp_port() -> int:
    """A free loopback UDP port (not reserved — the caller binds it)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


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
    **extra: object,
) -> dict:
    frame: dict = {
        "protocol_version": "boot/1",
        "type": "register",
        "cid": cid,
        "bucket": bucket,
        "cert_fp": _FP,
        "version": "1.0.0",
        "capacity": 20,
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


def leave_frame(cid: str, bucket: str) -> dict:
    return {"protocol_version": "boot/1", "type": "leave", "cid": cid, "bucket": bucket}


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

    def __init__(self, proc: subprocess.Popen, port: int, ready_file: Path | None, log_dir: Path):
        self.proc = proc
        self.port = port
        self.ready_file = ready_file
        self._stdout = log_dir / "stdout.log"
        self._stderr = log_dir / "stderr.log"

    @property
    def pid(self) -> int:
        return int(self.proc.pid)

    def stderr_text(self) -> str:
        if self._stderr.exists():
            return self._stderr.read_text(encoding="utf-8", errors="replace")
        return ""


def start_bootnode(
    tmp_path: Path,
    *,
    port: int | None = None,
    args: Sequence[str] = (),
    keys: Mapping[str, str] | None = None,
    protected: Sequence[str] = (),
    ttl: int | None = None,
    debug: bool = False,
    ready: bool = True,
    no_rate_limit: bool = False,
) -> BootnodeProc:
    """Start a bootnode subprocess; ``keys`` are provisioned via ``--keys-fd``."""
    port = port or free_udp_port()
    ready_file = tmp_path / "ready.pid" if ready else None

    cmd = [resolve_bin(), "run", "--host", "127.0.0.1", "--port", str(port), "--no-upnp"]
    if ttl is not None:
        cmd += ["--ttl", str(ttl)]
    for bucket in protected:
        cmd += ["--protected-bucket", bucket]
    if debug:
        cmd += ["--debug"]
    if no_rate_limit:
        cmd += ["--no-rate-limit"]
    cmd += list(args)

    env = scrub_environment()
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
    proc = subprocess.Popen(cmd, env=env, stdout=stdout_f, stderr=stderr_f, pass_fds=pass_fds)
    stdout_f.close()
    stderr_f.close()
    if keys:
        os.close(read_fd)

    handle = BootnodeProc(proc, port, ready_file, tmp_path)
    if ready:
        wait_ready(handle)
    return handle


def wait_ready(handle: BootnodeProc, timeout: float = 15.0) -> None:
    """Wait until the ready file contains exactly the subprocess PID."""
    assert handle.ready_file is not None, "readiness file not configured"
    deadline = time.monotonic() + timeout
    expected = str(handle.pid)
    while time.monotonic() < deadline:
        if handle.ready_file.exists() and handle.ready_file.read_text().strip() == expected:
            return
        if handle.proc.poll() is not None:
            raise RuntimeError(
                f"bootnode exited before ready (rc={handle.proc.returncode})\n"
                f"stderr:\n{handle.stderr_text()}"
            )
        time.sleep(0.05)
    raise TimeoutError(f"bootnode not ready within {timeout}s\nstderr:\n{handle.stderr_text()}")


def terminate(handle: BootnodeProc) -> None:
    """Terminate the bootnode (SIGTERM, then SIGKILL fallback); no orphans."""
    proc = handle.proc
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5.0)


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

    def __init__(self, port: int) -> None:
        self._port = port
        self._protocol = None
        self._stack: contextlib.AsyncExitStack | None = None

    async def __aenter__(self) -> BootClient:
        config = QuicConfiguration(
            is_client=True, alpn_protocols=[BOOT_ALPN], verify_mode=ssl.CERT_NONE
        )
        self._stack = contextlib.AsyncExitStack()
        await self._stack.__aenter__()
        self._protocol = await self._stack.enter_async_context(
            connect("127.0.0.1", self._port, configuration=config)
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
