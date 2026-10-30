"""Test-side pydantic mirror of the wire ``response`` frame (byte-parity oracle).

The daemon serializes ``response`` with the hand-assembled envelope in
``RendezvousHandler._response`` (cached peer fragments around fixed
server-controlled fields). This standalone mirror is the independent oracle
that pins that byte format; it deliberately lives under ``tests/`` instead of
``hsync_rendezvous.protocol`` so the production wire builder keeps exactly one
implementation.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from hsync_rendezvous.protocol import RdvError, RdvPeer

__all__ = ["RDV_RESPONSE_ADAPTER", "RdvResponse"]


class RdvResponse(BaseModel):
    """Server reply to query: random sample of peers (or a uniform refusal)."""

    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal["rdv/1"]
    type: Literal["response"]
    peers: list[RdvPeer] = Field(default_factory=list)
    count: int = Field(ge=0)
    ttl: int = Field(ge=1, le=3600)
    error: RdvError | None = None
    retry_after: int | None = Field(default=None, ge=1)


RDV_RESPONSE_ADAPTER: TypeAdapter[RdvResponse] = TypeAdapter(RdvResponse)
