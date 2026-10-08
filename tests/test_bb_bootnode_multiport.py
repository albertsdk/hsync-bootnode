"""Black-box multi-port tests: one process, N UDP listeners, ONE routing table.

Gated by ``HSYNC_BB_BOOTNODE=1`` (see ``conftest.py``). Language-neutral: only the
public CLI + ``boot/1`` wire are used, never an import of ``hsync_bootnode``.
"""

from __future__ import annotations

import socket

import pytest
from harness import BootClient, free_udp_port, query_frame, random_cid, register_frame


@pytest.mark.asyncio
async def test_multi_port_shares_one_routing_table(bootnode_factory, bucket, rng) -> None:
    """A peer registered via one port is visible to a query on another port.

    This is the whole point of multi-port (decision 57): the listeners share ONE
    in-memory routing table, so offering several inbound doors does not split the
    group across tables.
    """
    # Given: a node bound on two UDP ports in one process
    ports = [free_udp_port(), free_udp_port()]
    handle = bootnode_factory(ports=ports)
    assert handle.ports == tuple(ports)
    cid = random_cid(rng)

    # When: a peer registers on the FIRST port ...
    async with BootClient(ports[0]) as client:
        ack = await client.exchange(register_frame(cid, bucket))
        assert ack["type"] == "ack"

    # ... and a query is sent on the SECOND port
    async with BootClient(ports[1]) as client:
        response = await client.exchange(query_frame(bucket))

    # Then: the peer registered on the first port is visible on the second
    assert response["type"] == "response"
    assert response["error"] is None
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == cid


@pytest.mark.asyncio
async def test_multi_port_best_effort_skips_a_busy_port(bootnode_factory, bucket) -> None:
    """A requested port already in use is skipped; the node serves the rest."""
    # Given: one free port and one port already held by another UDP socket
    free = free_udp_port()
    busy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    busy_sock.bind(("127.0.0.1", 0))
    busy = busy_sock.getsockname()[1]
    try:
        # When: the node is asked for [busy, free]
        handle = bootnode_factory(ports=[busy, free])

        # Then: it starts anyway and serves on the free port ...
        async with BootClient(free) as client:
            response = await client.exchange(query_frame(bucket))
        assert response["type"] == "response"

        # ... and warns (always-on, peer-free) about the unavailable port
        assert "listener port unavailable" in handle.stderr_text()
    finally:
        busy_sock.close()
