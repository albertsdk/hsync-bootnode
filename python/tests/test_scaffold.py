"""Boot/1 protocol model + routing + token tests (Fase 0 scaffold)."""

from __future__ import annotations

import json
from pathlib import Path

from hsync_bootnode.protocol import (
    CID_PATTERN,
    BootAck,
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


def test_cid_pattern() -> None:
    assert __import__("re").fullmatch(CID_PATTERN, CID)


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
    table = RoutingTable(ttl=60.0)
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
