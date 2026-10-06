"""UPnP-IGD for the bootnode: the shared IGD client plus the async manager.

The SSDP/SOAP implementation (including the SSRF hardening) is the
``hsync_common.upnp`` SSOT shared with ``hsync-client``; this module only adds
``UpnpManager`` — the asyncio loop that maps the QUIC listener's UDP port and
refreshes it, reporting through the bootnode diagnostics channel.

The node parses network data only with ElementTree on the bounded description
body (64 KiB) and never logs reply content (the no-log invariant).
"""

from __future__ import annotations

import asyncio
import socket

import hsync_common.upnp as _shared_upnp
from hsync_common.upnp import (
    UPNP_SSDP_ADDR,
    IgdService,
    UpnpError,
    _control_url_on_base,
    _igd_service_from_location,
    _location_host_matches_source,
    _parse_ssdp_response,
    _validated_http_url,
    add_port_mapping,
    build_add_mapping_soap,
    delete_port_mapping,
    discover_igd,
    is_lan_unicast_address,
    is_private_http_location,
    no_redirect_urlopen,
    parse_soap_error,
)

from hsync_bootnode.diagnostics import debug_event, warn_event

__all__ = [
    "UPNP_SSDP_ADDR",
    "IgdService",
    "UpnpError",
    "UpnpManager",
    "add_port_mapping",
    "build_add_mapping_soap",
    "delete_port_mapping",
    "discover_igd",
    "is_lan_unicast_address",
    "is_private_http_location",
    "no_redirect_urlopen",
    "parse_soap_error",
    # Private re-exports: the white-box tests and fuzz reach through the facade.
    "_control_url_on_base",
    "_location_host_matches_source",
    "_parse_ssdp_response",
    "_validated_http_url",
]


def _first_igd_location(sock: socket.socket, timeout: float, local_ip: str) -> IgdService | None:
    """Delegate to the shared reply gate, keeping the local fetch seam.

    ``_igd_service_from_location`` is resolved from this module so callers (and
    tests/fuzz) can monkeypatch the fetch without reaching into the shared SSOT.
    """
    return _shared_upnp._first_igd_location(
        sock,
        timeout,
        local_ip,
        fetch=_igd_service_from_location,
    )


class UpnpManager:
    """Asyncio zero-touch UPnP: map the QUIC listener port and refresh it.

    Stateless by design: discovery failure or an absent IGD is reported once on
    the always-on diagnostics channel and retried at the next cycle — the node
    keeps serving normally (the operator may instead open the port manually).
    """

    def __init__(
        self,
        internal_port: int,
        *,
        external_port: int | None = None,
        refresh_interval: float = 300.0,
    ) -> None:
        self.internal_port = internal_port
        self.external_port = external_port if external_port is not None else internal_port
        self.refresh_interval = refresh_interval
        self._active: IgdService | None = None
        self._reported_missing = False

    async def run(self) -> None:
        while True:
            try:
                await asyncio.get_running_loop().run_in_executor(None, self._ensure_mapped)
            except UpnpError as exc:
                # Transient: retry at the next cycle, the node keeps serving —
                # but a mapping that never succeeds is exactly what an operator
                # must see to understand why peers cannot reach the node.
                warn_event("upnp mapping unavailable", reason=exc)
            await asyncio.sleep(self.refresh_interval)

    def _ensure_mapped(self) -> None:
        service = self._active
        if service is None:
            service = discover_igd()
            if service is None:
                if not self._reported_missing:
                    warn_event("upnp no igd on lan", port=self.external_port)
                    self._reported_missing = True
                return
            add_port_mapping(
                service,
                internal_port=self.internal_port,
                external_port=self.external_port,
            )
            self._active = service
            debug_event("upnp mapping active", port=self.external_port, proto="udp")
            return
        # Refresh the existing mapping (idempotent AddPortMapping).
        add_port_mapping(
            service,
            internal_port=self.internal_port,
            external_port=self.external_port,
        )
