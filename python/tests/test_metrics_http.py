"""The loopback ``/metrics`` endpoint: auth, routing, bounds and shutdown.

Every test drives a real listener on an ephemeral loopback port and speaks plain
HTTP/1.1, so the assertions cover what a scraper actually sees: status codes,
headers, the Prometheus body and the refusal of anything the contract does not
allow. The endpoint is loopback-only and always token-authenticated, so an
unauthenticated ``200`` anywhere here is a defect.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

import pytest
from pydantic import SecretStr

from hsync_rendezvous.metrics import PROMETHEUS_CONTENT_TYPE, MetricsEndpoint, MetricsServer
from hsync_rendezvous.stats import NodeStats

TOKEN = "0f" * 32
_AUTH = f"Authorization: Bearer {TOKEN}"


@contextlib.asynccontextmanager
async def _running() -> AsyncIterator[tuple[MetricsServer, int, NodeStats]]:
    """A started endpoint on an ephemeral loopback port, always closed."""
    stats = NodeStats()
    server = await MetricsServer.start(
        endpoint=MetricsEndpoint(host="127.0.0.1", port=0, token=SecretStr(TOKEN)),
        stats=stats,
    )
    try:
        yield server, int(server.sockets[0].getsockname()[1]), stats
    finally:
        await server.aclose()


async def _roundtrip(port: int, request: str) -> str:
    """Write one request, read the whole response (the server closes after it)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(request.encode("latin-1"))
        await writer.drain()
        return (await asyncio.wait_for(reader.read(), timeout=5)).decode("latin-1")
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def _status(response: str) -> int:
    return int(response.split(" ", 2)[1])


def _body(response: str) -> str:
    return response.split("\r\n\r\n", 1)[1]


async def test_authorized_scrape_returns_the_prometheus_body() -> None:
    async with _running() as (_, port, stats):
        response = await _roundtrip(port, f"GET /metrics HTTP/1.1\r\n{_AUTH}\r\n\r\n")
    assert _status(response) == 200
    assert f"Content-Type: {PROMETHEUS_CONTENT_TYPE}" in response
    assert "# TYPE hsync_rendezvous_peers_current gauge" in _body(response)
    assert 'hsync_rendezvous_metrics_requests_total{outcome="ok"} 1' in _body(response)
    assert stats.metrics_requests["ok"] == 1


@pytest.mark.parametrize(
    "raw_request",
    [
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
        f"GET /metrics HTTP/1.1\r\nAuthorization: Basic {TOKEN}\r\n\r\n",
        "GET /metrics HTTP/1.1\r\nAuthorization: Bearer wrong-token\r\n\r\n",
        "GET /metrics HTTP/1.1\r\nAuthorization: Bearer \r\n\r\n",
    ],
    ids=["missing", "wrong-scheme", "wrong-token", "empty-credentials"],
)
async def test_every_authentication_failure_is_the_same_401(raw_request: str) -> None:
    async with _running() as (_, port, stats):
        response = await _roundtrip(port, raw_request)
    assert _status(response) == 401
    assert "WWW-Authenticate: Bearer" in response
    assert "hsync_rendezvous_peers_current" not in _body(response)
    assert stats.metrics_requests["unauthorized"] == 1


async def test_a_head_returns_the_headers_without_a_body() -> None:
    async with _running() as (_, port, _):
        response = await _roundtrip(port, f"HEAD /metrics HTTP/1.1\r\n{_AUTH}\r\n\r\n")
    assert _status(response) == 200
    assert _body(response) == ""
    assert "Content-Length: " in response


async def test_an_unknown_path_is_404() -> None:
    async with _running() as (_, port, stats):
        response = await _roundtrip(port, f"GET /admin HTTP/1.1\r\n{_AUTH}\r\n\r\n")
    assert _status(response) == 404
    assert stats.metrics_requests["not_found"] == 1


async def test_a_non_read_method_is_405_with_the_allow_list() -> None:
    async with _running() as (_, port, stats):
        response = await _roundtrip(port, f"POST /metrics HTTP/1.1\r\n{_AUTH}\r\n\r\n")
    assert _status(response) == 405
    assert "Allow: GET, HEAD" in response
    assert stats.metrics_requests["method_not_allowed"] == 1


async def test_a_malformed_request_line_is_400() -> None:
    async with _running() as (_, port, _):
        response = await _roundtrip(port, f"GET\r\n{_AUTH}\r\n\r\n")
    assert _status(response) == 400


async def test_an_oversized_header_block_is_431() -> None:
    padded = "GET /metrics HTTP/1.1\r\nX-Pad: " + "a" * 9000 + "\r\n\r\n"
    async with _running() as (_, port, _):
        response = await _roundtrip(port, padded)
    assert _status(response) == 431


async def test_a_silent_client_is_cut_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("hsync_rendezvous.metrics._READ_TIMEOUT_SECONDS", 0.1)
    async with _running() as (_, port, _):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            response = (await asyncio.wait_for(reader.read(), timeout=5)).decode("latin-1")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    assert _status(response) == 408


async def test_a_request_burst_is_rate_limited() -> None:
    request = f"GET /metrics HTTP/1.1\r\n{_AUTH}\r\n\r\n"
    async with _running() as (_, port, stats):
        statuses = [(await _roundtrip(port, request)) for _ in range(5)]
    codes = [_status(response) for response in statuses]
    assert codes[:4] == [200, 200, 200, 200]
    assert codes[4] == 429
    assert "Retry-After: " in statuses[4]
    assert stats.metrics_requests["rate_limited"] == 1


async def test_the_concurrency_cap_answers_503(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("hsync_rendezvous.metrics._MAX_CONCURRENT", 1)
    async with _running() as (_, port, stats):
        # Given: one client that connected and never finished its request
        idle_reader, idle_writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await asyncio.sleep(0.1)
            # When: a second request arrives while the first is still in flight
            response = await _roundtrip(port, f"GET /metrics HTTP/1.1\r\n{_AUTH}\r\n\r\n")
        finally:
            idle_writer.close()
            with contextlib.suppress(Exception):
                await idle_writer.wait_closed()
            with contextlib.suppress(Exception):
                await idle_reader.read()
    assert _status(response) == 503
    assert stats.metrics_requests["unavailable"] == 1


async def test_closing_the_server_stops_serving() -> None:
    server = await MetricsServer.start(
        endpoint=MetricsEndpoint(host="127.0.0.1", port=0, token=SecretStr(TOKEN)),
        stats=NodeStats(),
    )
    port = int(server.sockets[0].getsockname()[1])
    await server.aclose()
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", port)
