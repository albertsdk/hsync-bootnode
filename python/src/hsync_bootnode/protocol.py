"""``boot/1`` wire-protocol frame models and strict validators.

This is the Python mirror of ``protocol-spec/boot-1.md`` (single source of
truth at the repository root). Values are validated with ``extra="forbid"`` so
any unknown field — including any targeted "file X" request — is rejected.

Every frame carries a mandatory ``type`` discriminator (plan §6: common header
``{protocol_version, type, ...}``); the server routes on it and never guesses
the frame kind from the payload shape.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

__all__ = [
    "PROTOCOL_VERSION_BOOT",
    "CID_PATTERN",
    "BUCKET_TOKEN_LEN",
    "BucketProto",
    "Endpoint",
    "ObservedEndpoint",
    "BootRegister",
    "BootRefresh",
    "BootLeave",
    "BootQuery",
    "BootAck",
    "BootPeer",
    "BootResponse",
    "BootFrame",
    "BOOT_FRAME_ADAPTER",
    "BOOT_ACK_ADAPTER",
    "BOOT_RESPONSE_ADAPTER",
]

# Per-channel protocol version. Bump the suffix on any breaking change to the
# bootstrap channel's wire shape; peers then hard-fail instead of drifting.
PROTOCOL_VERSION_BOOT: Literal["boot/1"] = "boot/1"

# CID shape mirrors hsync_common.models.event.CID_PATTERN (``^[A-Za-z0-9]{21}$``).
# Fase 2 (SSOT sync) replaces this local mirror with the hsync-common import.
CID_PATTERN = r"^[A-Za-z0-9]{21}$"
_CID_RE = re.compile(CID_PATTERN)

# hex(32 bytes) = 64 chars. Absent = open bucket (D11).
BUCKET_TOKEN_LEN = 64
_BUCKET_TOKEN_RE = re.compile(rf"^[0-9a-f]{{{BUCKET_TOKEN_LEN}}}$")

BucketProto = Literal["tcp", "udp"]


class Endpoint(BaseModel):
    """An advertised listen endpoint (register's ``endpoints[]``)."""

    model_config = ConfigDict(extra="forbid")

    proto: BucketProto
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)


class ObservedEndpoint(BaseModel):
    """The source endpoint observed by the server (STUN-echo in ``ack``)."""

    model_config = ConfigDict(extra="forbid")

    proto: BucketProto
    ip: str
    port: int = Field(ge=1, le=65535)


class _BootFrame(BaseModel):
    """Common shape: mandatory ``type`` discriminator + ``protocol_version``."""

    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal["boot/1"]
    type: str


class BootRegister(_BootFrame):
    """Client announces presence in a bucket (first contact)."""

    type: Literal["register"]
    cid: str = Field(pattern=CID_PATTERN)
    bucket: str = Field(min_length=1, max_length=128)
    group: str | None = Field(default=None, max_length=128)
    bucket_token: str | None = None
    cert_fp: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=64)
    capacity: int = Field(default=0, ge=0, le=1000)
    endpoints: list[Endpoint] = Field(default_factory=list, max_length=16)
    connected: int | None = Field(default=None, ge=0)


class BootRefresh(_BootFrame):
    """Client renews its TTL (and/or connected count) — authenticated like register."""

    type: Literal["refresh"]
    cid: str = Field(pattern=CID_PATTERN)
    bucket: str = Field(min_length=1, max_length=128)
    group: str | None = Field(default=None, max_length=128)
    bucket_token: str | None = None
    connected: int | None = Field(default=None, ge=0)


class BootLeave(_BootFrame):
    """Client announces departure.

    ``bucket_token`` is optional on the wire and only *enforced* by a private
    node (``--private``), where an unauthenticated leave would let anyone who
    knows a ``(cid, bucket)`` pair spoof a departure.
    """

    type: Literal["leave"]
    cid: str = Field(pattern=CID_PATTERN)
    bucket: str = Field(min_length=1, max_length=128)
    bucket_token: str | None = None


class BootQuery(_BootFrame):
    """Client asks for a random sample of peers. Only generic — no file targeting."""

    type: Literal["query"]
    bucket: str = Field(min_length=1, max_length=128)
    group: str | None = Field(default=None, max_length=128)
    bucket_token: str | None = None
    limit: int = Field(default=20, ge=1, le=50)


class BootAck(_BootFrame):
    """Server reply to register/refresh: STUN-echo observed endpoint + TTL."""

    type: Literal["ack"]
    observed_endpoint: ObservedEndpoint
    ttl: int = Field(ge=1, le=3600)
    server_time: str
    retry_after: int | None = Field(default=None, ge=1)


class BootPeer(BaseModel):
    """A single advertised peer in a BootResponse."""

    model_config = ConfigDict(extra="forbid")

    cid: str = Field(pattern=CID_PATTERN)
    ip: str
    port: int = Field(ge=1, le=65535)
    proto: BucketProto = "tcp"
    cert_fp: str = Field(min_length=1, max_length=256)
    bucket: str = Field(min_length=1, max_length=128)
    group: str | None = None
    version: str = Field(min_length=1, max_length=64)
    reachable: bool = True


class BootResponse(_BootFrame):
    """Server reply to query: random sample of peers (or a uniform refusal)."""

    type: Literal["response"]
    peers: list[BootPeer] = Field(default_factory=list)
    count: int = Field(ge=0)
    ttl: int = Field(ge=1, le=3600)
    error: Literal["token_required", "rate_limited"] | None = None
    retry_after: int | None = Field(default=None, ge=1)


# Client→server frames, dispatched on ``type``. ``BootResponse``/``BootAck``/
# ``BootPeer`` are server→client and deliberately excluded: they are never
# validated in the input path.
BootFrame = Annotated[
    BootRegister | BootRefresh | BootLeave | BootQuery,
    Field(discriminator="type"),
]
BOOT_FRAME_ADAPTER: TypeAdapter[BootFrame] = TypeAdapter(BootFrame)

# Server→client serializers: ``dump_json`` emits ``bytes`` directly, so the
# transport writes them verbatim instead of decoding to ``str`` and re-encoding.
BOOT_ACK_ADAPTER: TypeAdapter[BootAck] = TypeAdapter(BootAck)
BOOT_RESPONSE_ADAPTER: TypeAdapter[BootResponse] = TypeAdapter(BootResponse)


assert _CID_RE.fullmatch("A1b2C3d4E5f6G7h8I9j0K")
assert _BUCKET_TOKEN_RE.fullmatch("a" * BUCKET_TOKEN_LEN)
