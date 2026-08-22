"""BootHandler behavioural tests: routing, D11 protected buckets, rate limits,
STUN-echo and frame rejection. Pure logic — no sockets involved.
"""

from __future__ import annotations

from unittest.mock import patch

from pydantic import SecretStr

from hsync_bootnode.handler import BootConfigError, BootHandler
from hsync_bootnode.tokens import derive_bucket_token

CID = "A1b2C3d4E5f6G7h8I9j0K"
CID2 = "abcdefghijklmnopqrstu"
FP = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
KEY = b"group-secret"


def make_handler(protected: tuple[str, ...] = ()) -> BootHandler:
    keys = {bucket: SecretStr("k" + bucket) for bucket in protected} if protected else None
    return BootHandler(protected_buckets=protected, group_keys=keys)


def register_frame(
    cid: str = CID,
    bucket: str = "shared",
    group: str | None = "home",
    token: str | None = None,
    host: str = "198.51.100.7",
    port: int = 443,
) -> dict:
    frame: dict = {
        "protocol_version": "boot/1",
        "type": "register",
        "cid": cid,
        "bucket": bucket,
        "cert_fp": FP,
        "version": "1.0.0",
        "capacity": 20,
        "endpoints": [{"proto": "tcp", "host": host, "port": port}],
    }
    if group is not None:
        frame["group"] = group
    if token is not None:
        frame["bucket_token"] = token
    return frame


def query_frame(
    bucket: str = "shared",
    group: str | None = "home",
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


def test_register_acks_with_stun_echo_and_creates_record() -> None:
    h = make_handler()
    response = h.handle(register_frame(), peer_ip="198.51.100.7", peer_port=54321)
    assert response is not None
    assert response["type"] == "ack"
    assert response["observed_endpoint"] == {
        "proto": "udp",
        "ip": "198.51.100.7",
        "port": 54321,
    }
    assert response["ttl"] == 60
    assert response["server_time"].endswith("Z")
    assert h.routing.count(bucket="shared") == 1


def test_query_returns_advertised_endpoint_random_sample() -> None:
    h = make_handler()
    h.handle(
        register_frame(cid=CID, host="198.51.100.7"),
        peer_ip="198.51.100.7",
        peer_port=54321,
    )
    h.handle(
        register_frame(cid=CID2, host="198.51.100.8"),
        peer_ip="198.51.100.8",
        peer_port=54322,
    )
    response = h.handle(query_frame(limit=10), peer_ip="10.0.0.1", peer_port=1111)
    assert response is not None
    assert response["type"] == "response"
    assert response["count"] == 2
    assert response["error"] is None
    peers = {(p["cid"], p["ip"], p["port"]) for p in response["peers"]}
    assert peers == {
        (CID, "198.51.100.7", 443),
        (CID2, "198.51.100.8", 443),
    }


def test_query_group_filter() -> None:
    h = make_handler()
    h.handle(register_frame(cid=CID, group="home"), peer_ip="10.0.0.1", peer_port=1111)
    h.handle(
        register_frame(cid=CID2, group=None, host="198.51.100.8"),
        peer_ip="10.0.0.2",
        peer_port=1112,
    )
    response = h.handle(query_frame(group="home"), peer_ip="10.0.0.3", peer_port=1113)
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == CID


def test_protected_bucket_uniform_token_required() -> None:
    h = make_handler(protected=("shared",))
    # anonymous query on a protected bucket → uniform refusal, empty list
    response = h.handle(query_frame(token=None), peer_ip="10.0.0.1", peer_port=1)
    assert response["error"] == "token_required"
    assert response["peers"] == []
    assert response["count"] == 0
    # wrong (but well-formed) token → same uniform refusal
    response = h.handle(query_frame(token="0" * 64), peer_ip="10.0.0.1", peer_port=1)
    assert response["error"] == "token_required"


def test_protected_bucket_correct_token_returns_peers() -> None:
    h = make_handler(protected=("shared",))
    token = derive_bucket_token(b"kshared", "shared")
    h.handle(register_frame(token=token), peer_ip="198.51.100.7", peer_port=1)
    response = h.handle(query_frame(token=token), peer_ip="10.0.0.1", peer_port=1)
    assert response["error"] is None
    assert response["count"] == 1


def test_protected_bucket_register_without_token_does_not_create() -> None:
    h = make_handler(protected=("shared",))
    response = h.handle(register_frame(token=None), peer_ip="10.0.0.1", peer_port=1)
    assert response["error"] == "token_required"
    assert h.routing.count(bucket="shared") == 0
    # a malformed token string is refused too: it fails the constant-time check
    response = h.handle(register_frame(token="not-a-token"), peer_ip="10.0.0.1", peer_port=1)
    assert response["error"] == "token_required"
    assert h.routing.count(bucket="shared") == 0


def test_open_bucket_needs_no_token() -> None:
    h = make_handler()  # no protected buckets → everything open
    assert h.handle(register_frame(), peer_ip="1.1.1.1", peer_port=1)["type"] == "ack"
    assert h.handle(query_frame(), peer_ip="2.2.2.2", peer_port=1)["error"] is None


def test_query_rate_limited_per_ip_bucket_pair() -> None:
    h = make_handler()
    results = []
    for _ in range(10):  # burst 10 for (IP, bucket)
        results.append(h.handle(query_frame(), peer_ip="10.0.0.9", peer_port=1))
    assert all(r["type"] == "response" and r["error"] is None for r in results)
    limited = h.handle(query_frame(), peer_ip="10.0.0.9", peer_port=1)
    assert limited["error"] == "rate_limited"
    assert limited["peers"] == []
    assert limited["count"] == 0
    assert limited["retry_after"] >= 1
    # a different IP is not throttled by the same bucket
    assert h.handle(query_frame(), peer_ip="10.0.0.8", peer_port=1)["error"] is None


def test_register_rate_limited_per_bucket() -> None:
    h = make_handler()
    for _ in range(10):  # 10/min per bucket
        assert h.handle(register_frame(cid=CID2), peer_ip="1.1.1.1", peer_port=1)["type"] == "ack"
    response = h.handle(register_frame(cid=CID2), peer_ip="1.1.1.1", peer_port=1)
    assert response["type"] == "response"
    assert response["error"] == "rate_limited"
    assert response["retry_after"] >= 1


def test_bad_token_attempts_rate_limited_per_ip() -> None:
    h = make_handler(protected=("shared",))
    for _ in range(5):  # 5 failed-token attempts/min per IP
        response = h.handle(query_frame(token="0" * 64), peer_ip="10.0.0.5", peer_port=1)
        assert response["error"] == "token_required"
    response = h.handle(query_frame(token="0" * 64), peer_ip="10.0.0.5", peer_port=1)
    assert response["error"] == "rate_limited"


def test_leave_removes_record_anonymously() -> None:
    h = make_handler()
    assert h.handle(register_frame(), peer_ip="10.0.0.1", peer_port=1)["type"] == "ack"
    assert h.routing.count(bucket="shared") == 1
    h.handle(
        {"protocol_version": "boot/1", "type": "leave", "cid": CID, "bucket": "shared"},
        peer_ip="10.0.0.1",
        peer_port=1,
    )
    assert h.routing.count(bucket="shared") == 0


def test_refresh_renews_ttl_but_never_creates() -> None:
    h = make_handler()
    # Freeze both clocks (routing + handler) so the TTL math and the periodic
    # prune inside handle() are deterministic regardless of the host clock.
    with (
        patch("hsync_bootnode.routing.time.monotonic", return_value=1_000.0),
        patch("hsync_bootnode.handler.time.monotonic", return_value=1_000.0),
    ):
        h.handle(register_frame(), peer_ip="10.0.0.1", peer_port=1)
    before = h.routing.get(CID, "shared", "home")
    assert before is not None
    before_expires = before.expires_at  # live record: touch() mutates it too
    with (
        patch("hsync_bootnode.routing.time.monotonic", return_value=1_030.0),
        patch("hsync_bootnode.handler.time.monotonic", return_value=1_030.0),
    ):
        refreshed = h.handle(
            {
                "protocol_version": "boot/1",
                "type": "refresh",
                "cid": CID,
                "bucket": "shared",
                "group": "home",
                "connected": 7,
            },
            peer_ip="10.0.0.1",
            peer_port=1,
        )
    assert refreshed["type"] == "ack"
    after = h.routing.get(CID, "shared", "home")
    assert after is not None
    assert after.connected == 7
    assert after.expires_at > before_expires
    assert before_expires == 1_060.0  # register: t + TTL
    assert after.expires_at == 1_090.0  # refresh: t + TTL from the new time
    # unknown CID: refresh must NOT create a record. Stays under the frozen clock
    # so the periodic prune (now=1030) does not expire the live CID (t+TTL 1090).
    with (
        patch("hsync_bootnode.routing.time.monotonic", return_value=1_030.0),
        patch("hsync_bootnode.handler.time.monotonic", return_value=1_030.0),
    ):
        dropped = h.handle(
            {
                "protocol_version": "boot/1",
                "type": "refresh",
                "cid": CID2,
                "bucket": "shared",
            },
            peer_ip="10.0.0.1",
            peer_port=1,
        )
    assert dropped is None
    assert h.routing.count(bucket="shared") == 1


def test_unknown_and_malformed_frames_are_dropped() -> None:
    h = make_handler()
    assert h.handle(None, peer_ip="10.0.0.1", peer_port=1) is None
    assert h.handle("not a dict", peer_ip="10.0.0.1", peer_port=1) is None
    assert h.handle({"protocol_version": "boot/1"}, peer_ip="10.0.0.1", peer_port=1) is None
    assert (
        h.handle({"protocol_version": "boot/1", "type": "pwn"}, peer_ip="10.0.0.1", peer_port=1)
        is None
    )
    # named targeted fields are rejected by the rigid schema (D3)
    bad = register_frame()
    bad["file_search"] = "photo.jpg"
    assert h.handle(bad, peer_ip="10.0.0.1", peer_port=1) is None


def test_generic_per_ip_admission_cap() -> None:
    h = make_handler()
    from hsync_bootnode.handler import OP_IP_BURST

    for _ in range(OP_IP_BURST):
        h.handle(register_frame(cid=CID2), peer_ip="9.9.9.9", peer_port=1)
    response = h.handle(register_frame(cid=CID2), peer_ip="9.9.9.9", peer_port=1)
    assert response["error"] == "rate_limited"


def test_protected_bucket_without_key_fails_fast() -> None:
    try:
        BootHandler(protected_buckets=("shared",), group_keys={})
    except BootConfigError:
        pass
    else:  # pragma: no cover - expected to raise
        raise AssertionError("protected bucket without a key must fail at startup")


def test_prune_removes_expired_records() -> None:
    from hsync_bootnode.routing import PeerRecord

    h = make_handler()
    h.routing.upsert(
        PeerRecord(
            cid=CID,
            bucket="shared",
            group="home",
            ip="10.0.0.1",
            port=1,
            proto="udp",
            cert_fp=FP,
            version="1.0.0",
            endpoints=[],
            expires_at=1000.0,
        )
    )
    assert h.prune(now=1500.0) == 1
    assert h.routing.count() == 0


def test_handle_prunes_periodically() -> None:
    """handle() sweeps expired records at most once per prune_interval.

    Regression for the bug where ``handle()`` never invoked ``prune()`` — expired
    records would linger until the next real frame arrived, so a quiet bucket
    kept stale peers in memory (and the soak failed its convergence check).
    """
    from hsync_bootnode.routing import PeerRecord

    h = make_handler()

    def add_expired(cid: str, expires_at: float, ip: str) -> None:
        h.routing.upsert(
            PeerRecord(
                cid=cid,
                bucket="shared",
                group="home",
                ip=ip,
                port=1,
                proto="udp",
                cert_fp=FP,
                version="1.0.0",
                endpoints=[],
                expires_at=expires_at,
            )
        )

    # An already-expired record must be swept by the FIRST handle() (the
    # last_prune is None, so the first call always sweeps).
    add_expired("expired-first", 1000.0, "10.0.0.1")
    with patch("hsync_bootnode.handler.time.monotonic", return_value=2000.0):
        h.handle(register_frame(cid=CID2), peer_ip="10.0.0.1", peer_port=1)
        assert h.routing.count() == 1  # "expired-first" swept, CID2 live
        # A second call within the same 15 s window must NOT re-sweep.
        h.handle(register_frame(cid=CID), peer_ip="10.0.0.2", peer_port=1)
        assert h.routing.count() == 2

    # A record that only expires AFTER the first sweep, then advance past
    # prune_interval: the interval sweep must remove it (not the register,
    # which targets a different CID).
    add_expired("expired-between", 2010.0, "10.0.0.3")
    assert h.routing.count() == 3
    with patch("hsync_bootnode.handler.time.monotonic", return_value=2020.0):
        h.handle(register_frame(cid=CID), peer_ip="10.0.0.4", peer_port=1)
    # "expired-between" swept by the interval prune; CID2 + CID remain.
    assert h.routing.count() == 2
    assert h.routing.get("expired-between", "shared", "home") is None
