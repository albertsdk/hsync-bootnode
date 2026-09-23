"""Boot/1 protocol model + routing + token tests (Fase 0 scaffold)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from hsync_bootnode.protocol import (
    CAPACITY_MAX,
    CID_PATTERN,
    BootAck,
    BootPeer,
    BootQuery,
    BootRegister,
    BootResponse,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_fixtures_match_boot1_models() -> None:
    """The shared SSOT fixtures must validate against the boot/1 models."""
    assert BootRegister.model_validate(_load_fixture("bootnode-register.json"))
    assert BootQuery.model_validate(_load_fixture("bootnode-query.json"))
    assert BootAck.model_validate(_load_fixture("bootnode-ack.json"))
    assert BootResponse.model_validate(_load_fixture("bootnode-response.json"))


from hsync_bootnode.ratelimit import TokenBucketLimiter
from hsync_bootnode.routing import PeerRecord, RoutingTable
from hsync_bootnode.tokens import derive_bucket_token, verify_bucket_token

CID = "A1b2C3d4E5f6G7h8I9j0K"


def test_cid_pattern_matches_boot1_spec() -> None:
    """CID shape is the hsync-common SSOT, pinned to the documented boot/1 value.

    ``CID_PATTERN`` is imported from ``hsync_common.models.event`` (Fase B): this
    test fails if an upstream change silently alters the documented wire shape.
    """
    assert CID_PATTERN == r"^[A-Za-z0-9]{21}$"
    assert re.fullmatch(CID_PATTERN, CID)
    assert re.fullmatch(CID_PATTERN, "A" * 20) is None
    assert re.fullmatch(CID_PATTERN, "A" * 22) is None


def test_bucket_uses_canonical_hsync_name_rule() -> None:
    """``bucket`` accepts the canonical HSYNC name and rejects everything else."""
    register = {
        "protocol_version": "boot/1",
        "type": "register",
        "cid": CID,
        "cert_fp": "AA:BB",
        "version": "1.0.0",
    }
    for good in ("shared", "a", "my-bucket_1", "b" * 63):
        assert BootRegister(**register, bucket=good).bucket == good
    for bad in ("", "-lead", "trail-", "has space", "dot.name", "a" * 64):
        with pytest.raises(ValueError):
            BootRegister(**register, bucket=bad)

    # query carries the same domain (no cid / cert_fp)
    assert BootQuery(protocol_version="boot/1", type="query", bucket="shared").bucket == "shared"
    with pytest.raises(ValueError):
        BootQuery(protocol_version="boot/1", type="query", bucket="has space")

    # BootPeer is validated on the same rule
    with pytest.raises(ValueError):
        BootPeer(
            cid=CID,
            ip="198.51.100.7",
            port=443,
            cert_fp="AA:BB",
            bucket="has space",
            version="1.0.0",
        )


def test_register_accepts_valid_and_rejects_unknown_fields() -> None:
    ok = BootRegister(
        protocol_version="boot/1",
        type="register",
        cid=CID,
        bucket="shared",
        group="home",
        cert_fp="AA:BB",
        version="1.0.0",
        endpoints=[{"proto": "tcp", "host": "198.51.100.7", "port": 443}],
    )
    assert ok.cid == CID
    assert ok.type == "register"

    # The schema must reject any targeted/unknown field (D3, agnostic).
    try:
        BootRegister(
            protocol_version="boot/1",
            type="register",
            cid=CID,
            bucket="shared",
            cert_fp="AA:BB",
            version="1.0.0",
            file_search="photo.jpg",  # type: ignore[call-arg]
        )
    except ValueError:
        pass
    else:  # pragma: no cover - expected to raise
        raise AssertionError("unknown field must be rejected")


def test_capacity_hint_domain_bounds() -> None:
    """The advisory capacity hint is 0..32 (0 = not a seeder); 33 is rejected."""
    register = {
        "protocol_version": "boot/1",
        "type": "register",
        "cid": CID,
        "bucket": "shared",
        "cert_fp": "AA:BB",
        "version": "1.0.0",
    }
    assert BootRegister(**register).capacity == 0  # absent → 0
    assert BootRegister(**register, capacity=CAPACITY_MAX).capacity == CAPACITY_MAX
    with pytest.raises(ValueError):
        BootRegister(**register, capacity=CAPACITY_MAX + 1)

    peer = {
        "cid": CID,
        "ip": "198.51.100.7",
        "port": 443,
        "cert_fp": "AA:BB",
        "bucket": "shared",
        "version": "1.0.0",
    }
    assert BootPeer(**peer).capacity == 0  # absent → 0
    assert BootPeer(**peer, capacity=CAPACITY_MAX).capacity == CAPACITY_MAX
    with pytest.raises(ValueError):
        BootPeer(**peer, capacity=CAPACITY_MAX + 1)


def test_bucket_token_derivation_and_verify() -> None:
    key = b"supersecret"
    token = derive_bucket_token(key, "shared")
    assert len(token) == 64
    assert token == derive_bucket_token(key, "shared")  # deterministic
    assert token != derive_bucket_token(key, "other")  # bucket-scoped
    assert verify_bucket_token(token, token) is True
    assert verify_bucket_token(token, None) is False
    assert verify_bucket_token(token, "0" * 64) is False
    assert verify_bucket_token(token, "short") is False


def test_routing_table_upsert_prune_sample() -> None:
    table = RoutingTable()
    # deterministic: record A expires at 2000, record B at 3000
    table.upsert(
        PeerRecord(
            cid=CID,
            bucket="shared",
            group=None,
            ip="198.51.100.7",
            port=443,
            proto="tcp",
            cert_fp="AA:BB",
            version="1.0.0",
            endpoints=[],
            expires_at=2000.0,
        )
    )
    table.upsert(
        PeerRecord(
            cid="Zz9y8Xx7Ww6Vv5Uu4Tt3Ss2R",
            bucket="shared",
            group=None,
            ip="198.51.100.8",
            port=443,
            proto="tcp",
            cert_fp="CC:DD",
            version="1.0.0",
            endpoints=[],
            expires_at=3000.0,
        )
    )
    assert len(table.sample("shared", limit=10, now=1000.0)) == 2
    assert table.count("shared") == 2
    assert table.prune(now=2500.0) == 1  # only A expired
    assert table.count("shared") == 1
    assert table.prune(now=3500.0) == 1  # B expired too
    assert table.count("shared") == 0


def test_token_bucket_burst_then_sustained() -> None:
    lim = TokenBucketLimiter(capacity=10, refill=5, window=60.0)
    now = 1000.0
    # burst: the full capacity is consumable at once
    assert all(lim.allow("a", now + i) for i in range(10))
    assert lim.allow("a", now + 10) is False  # exhausted
    # sustained: exactly 5 tokens have refilled after one window
    assert lim.allow("a", now + 60) is True
    assert lim.retry_after("a") >= 1
