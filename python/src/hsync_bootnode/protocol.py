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

from hsync_common.models.event import CID_PATTERN
from hsync_common.path_validation import is_valid_bucket_name
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, TypeAdapter

__all__ = [
    "BOOT_ACK_ADAPTER",
    "BOOT_FRAME_ADAPTER",
    "BOOT_RESPONSE_ADAPTER",
    "BUCKET_TOKEN_LEN",
    "CAPACITY_MAX",
    "CID_PATTERN",
    "PROTOCOL_VERSION_BOOT",
    "STARTUP_TIME_MAX",
    "BootAck",
    "BootFrame",
    "BootLeave",
    "BootPeer",
    "BootQuery",
    "BootRefresh",
    "BootRegister",
    "BootResponse",
    "BucketName",
    "BucketProto",
    "Endpoint",
    "ObservedEndpoint",
    "SyncDirection",
]

# Per-channel protocol version. Bump the suffix on any breaking change to the
# bootstrap channel's wire shape; peers then hard-fail instead of drifting.
PROTOCOL_VERSION_BOOT: Literal["boot/1"] = "boot/1"

# CID shape is the hsync-common SSOT (``hsync_common.models.event.CID_PATTERN``,
# ``^[A-Za-z0-9]{21}$``), re-exported here so ``from hsync_bootnode.protocol
# import CID_PATTERN`` keeps working. The ``boot/1`` spec documents the same
# value; ``test_cid_pattern_matches_boot1_spec`` pins the two together.
_CID_RE = re.compile(CID_PATTERN)

# hex(32 bytes) = 64 chars. Absent = open bucket.
BUCKET_TOKEN_LEN = 64
_BUCKET_TOKEN_RE = re.compile(rf"^[0-9a-f]{{{BUCKET_TOKEN_LEN}}}$")

BucketProto = Literal["tcp", "udp"]

# Advisory service-capacity hint domain (``0..32``; ``0`` = not a peer-download
# seeder). Mirrors the authenticated ``serve_slots`` range (1..32); the bootnode
# relays the value in ``query`` responses but never treats it as authoritative
# (ADR 0030) — the authoritative value stays on the authenticated WSS handshake.
CAPACITY_MAX = 32

# Canonical sync-direction vocabulary, mirrored from the client SSOT
# (``hsync_common.protocol.pairing`` + ``p2p``). The election advertisement
# below reuses the same tokens the mDNS TXT record carries so a bootnode-relayed
# peer ranks exactly like a LAN-discovered one.
SyncDirection = Literal["bidirectional", "upload-only", "download-only"]

# Bound on the advertised unix ``startup_time`` (kept inside the
# exactly-representable integer range of a JSON number). ``0.0`` = unknown.
STARTUP_TIME_MAX = float(2**53)


def _validate_bucket_name(value: str) -> str:
    """Reject any value that is not a canonical HSYNC bucket name.

    The ``boot/1`` ``bucket`` field is the same sync bucket the client, server
    and desktop use, so the daemon validates it with the shared hsync-common
    predicate instead of an ad-hoc length bound: ``[A-Za-z0-9]`` with ``-``/``_``
    only in the middle, 1..63 characters. A non-canonical value makes the frame
    invalid (silently dropped, like every other malformed frame).
    """
    if not is_valid_bucket_name(value):
        raise ValueError("invalid bucket name (canonical HSYNC bucket name required)")
    return value


# Canonical bucket-name field type, applied to every ``bucket`` on the wire.
BucketName = Annotated[str, AfterValidator(_validate_bucket_name)]


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
    """Client announces presence in a bucket (first contact).

    ``capacity`` is the advisory service-capacity hint: the number of
    concurrent peer-download reads the peer declares it can serve right now
    (``0`` = not a seeder). The bootnode relays it in ``query`` responses; the
    authoritative value is the authenticated ``serve_slots`` (ADR 0030).

    ``server_ready``/``force_master``/``never_master``/``startup_time``/
    ``sync_direction`` are the **election advertisement**: the same values the
    mDNS TXT record carries, relayed verbatim in ``query`` peers so a
    bootnode-discovered peer ranks exactly like a LAN-discovered one. The node
    never interprets them; they are not authenticated and not authoritative
    (the data plane authenticates identity by certificate pinning). A changed
    advertisement requires a new ``register`` — ``refresh`` never mutates them.
    """

    type: Literal["register"]
    cid: str = Field(pattern=CID_PATTERN)
    bucket: BucketName
    group: str | None = Field(default=None, max_length=128)
    bucket_token: str | None = None
    cert_fp: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=64)
    capacity: int = Field(default=0, ge=0, le=CAPACITY_MAX)
    endpoints: list[Endpoint] = Field(default_factory=list, max_length=16)
    connected: int | None = Field(default=None, ge=0)
    server_ready: bool = False
    force_master: bool = False
    never_master: bool = False
    startup_time: float = Field(default=0.0, ge=0, le=STARTUP_TIME_MAX)
    sync_direction: SyncDirection = "bidirectional"


class BootRefresh(_BootFrame):
    """Client renews its TTL (and/or connected count) — authenticated like register."""

    type: Literal["refresh"]
    cid: str = Field(pattern=CID_PATTERN)
    bucket: BucketName
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
    bucket: BucketName
    bucket_token: str | None = None


class BootQuery(_BootFrame):
    """Client asks for a random sample of peers. Only generic — no file targeting."""

    type: Literal["query"]
    bucket: BucketName
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
    """A single advertised peer in a BootResponse.

    ``capacity`` is the peer's advisory service-capacity hint as relayed from
    its ``register`` (``0`` = not a seeder). It is not authenticated and not
    authoritative: the requester must treat the authenticated ``serve_slots``
    as the source of truth (ADR 0030).

    The election-advertisement fields are the peer's own ``register`` values
    (documented defaults when it advertised none), relayed verbatim so the
    requester's master election sees the same inputs a mDNS-discovered peer
    would provide. They are unauthenticated claims — the data plane
    authenticates identity by certificate pinning.
    """

    model_config = ConfigDict(extra="forbid")

    cid: str = Field(pattern=CID_PATTERN)
    ip: str
    port: int = Field(ge=1, le=65535)
    proto: BucketProto = "tcp"
    cert_fp: str = Field(min_length=1, max_length=256)
    bucket: BucketName
    group: str | None = None
    version: str = Field(min_length=1, max_length=64)
    capacity: int = Field(default=0, ge=0, le=CAPACITY_MAX)
    reachable: bool = True
    server_ready: bool = False
    force_master: bool = False
    never_master: bool = False
    startup_time: float = Field(default=0.0, ge=0, le=STARTUP_TIME_MAX)
    sync_direction: SyncDirection = "bidirectional"


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
