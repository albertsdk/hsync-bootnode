"""Minimal UPnP-IGD client (pure standard library, cross-platform).

Replaces the planned ``miniupnpc`` binding: that C extension cannot be built
without Python development headers (unavailable in this environment), and a
pure-Python IGD client keeps the v1 footprint dependency-free and byte-identical
on Linux/macOS/Windows (D12). The IGD protocol itself (SSDP + SOAP over HTTP)
is platform-independent.

Only the services a matchmaker needs are implemented: ``AddPortMapping`` /
``DeletePortMapping`` (UDP, the QUIC listener port). The mapping is refreshable
and every failure degrades to the documented "no UPnP" state (stateless) rather
than crashing the node.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urljoin
from xml.etree import ElementTree

__all__ = [
    "IgdService",
    "UpnpError",
    "UPNP_SSDP_ADDR",
    "UpnpManager",
    "discover_igd",
    "add_port_mapping",
    "delete_port_mapping",
    "build_add_mapping_soap",
    "build_delete_mapping_soap",
    "parse_soap_error",
]

logger = logging.getLogger("hsync_bootnode.upnp")

UPNP_SSDP_ADDR = ("239.255.255.250", 1900)
_SSDP_SEARCH_TARGET = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
_SERVICE_TYPES = (
    "urn:schemas-upnp-org:service:WANIPConnection:",
    "urn:schemas-upnp-org:service:WANPPPConnection:",
)
_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    f"ST: {_SSDP_SEARCH_TARGET}\r\n"
    "MX: 1\r\n"
    "\r\n"
).encode("ascii")

# IGD service namespace prefix used for SOAPAction and body element names.
_SERVICE_NS = "urn:schemas-upnp-org:service:WANIPConnection:1"


class UpnpError(RuntimeError):
    """A UPnP/IGD operation failed (device, network or protocol error)."""


@dataclass(frozen=True, slots=True)
class IgdService:
    """An InternetGatewayDevice offering a WAN connection service."""

    control_url: str
    local_ip: str
    service_type: str = _SERVICE_NS


def discover_igd(
    timeout: float = 2.0,
    *,
    ssdp_sock: socket.socket | None = None,
) -> IgdService | None:
    """Discover the LAN's IGD via SSDP M-SEARCH; return its WAN service.

    ``local_ip`` is captured from the sending socket (the LAN address a
    port mapping must target) — no extra route lookups, no packets beyond
    the obligatory M-SEARCH.
    """
    own: socket.socket | None = None
    sock = ssdp_sock if ssdp_sock is not None else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if ssdp_sock is None:
        own = sock
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.sendto(_MSEARCH, UPNP_SSDP_ADDR)
        local_ip = sock.getsockname()[0]
        return _first_igd_location(sock, timeout, local_ip)
    except OSError as exc:
        raise UpnpError(f"SSDP discovery failed: {exc}") from exc
    finally:
        if own is not None:
            own.close()


def _first_igd_location(sock: socket.socket, timeout: float, local_ip: str) -> IgdService | None:
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            data, _addr = sock.recvfrom(4096)
        except TimeoutError:
            return None
        location = _parse_ssdp_response(data)
        if location is None:
            continue
        service = _igd_service_from_location(location, local_ip)
        if service is not None:
            return service


def _parse_ssdp_response(data: bytes) -> str | None:
    """Extract the ``LOCATION`` header from an SSDP M-SEARCH reply."""
    try:
        text = data.decode("utf-8", errors="replace")
    except ValueError:
        return None
    first, _, rest = text.partition("\r\n")
    if not first.upper().startswith("HTTP/1.1 200"):
        return None
    for line in rest.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        if key.strip().lower() == "location":
            return value.strip()
    return None


def _igd_service_from_location(location: str, local_ip: str) -> IgdService | None:
    """Fetch the IGD description XML and locate a WAN connection control URL."""
    try:
        with urllib.request.urlopen(location, timeout=3.0) as response:
            xml_bytes = response.read(65536)
    except OSError:
        return None
    try:
        root = ElementTree.fromstring(xml_bytes)
    except ElementTree.ParseError:
        return None
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "service":
            continue
        entries = {child.tag.rsplit("}", 1)[-1]: (child.text or "").strip() for child in element}
        service_type = entries.get("serviceType", "")
        if not service_type.startswith(_SERVICE_TYPES):
            continue
        control = entries.get("controlURL")
        if not control:
            continue
        prefix = service_type.rsplit(":", 1)[0]
        return IgdService(
            control_url=urljoin(location, control),
            local_ip=local_ip,
            service_type=f"{prefix}:1",
        )
    return None


def build_add_mapping_soap(
    *,
    service_type: str,
    internal_client: str,
    internal_port: int,
    external_port: int,
    protocol: str = "UDP",
    description: str = "hsync-bootnode",
    lease_duration: int = 0,
) -> bytes:
    """Build the AddPortMapping SOAP envelope (pure builder, unit-testable)."""
    body = (
        '<?xml version="1.0"?>\n'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n'
        "  <s:Body>\n"
        f'    <u:AddPortMapping xmlns:u="{service_type}">\n'
        "      <NewRemoteHost></NewRemoteHost>\n"
        f"      <NewExternalPort>{external_port}</NewExternalPort>\n"
        f"      <NewProtocol>{protocol}</NewProtocol>\n"
        f"      <NewInternalPort>{internal_port}</NewInternalPort>\n"
        f"      <NewInternalClient>{internal_client}</NewInternalClient>\n"
        "      <NewEnabled>1</NewEnabled>\n"
        f"      <NewPortMappingDescription>{description}</NewPortMappingDescription>\n"
        f"      <NewLeaseDuration>{lease_duration}</NewLeaseDuration>\n"
        "    </u:AddPortMapping>\n"
        "  </s:Body>\n"
        "</s:Envelope>\n"
    )
    return body.encode("utf-8")


def build_delete_mapping_soap(
    *,
    service_type: str,
    external_port: int,
    protocol: str = "UDP",
) -> bytes:
    """Build the DeletePortMapping SOAP envelope (pure builder)."""
    body = (
        '<?xml version="1.0"?>\n'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n'
        "  <s:Body>\n"
        f'    <u:DeletePortMapping xmlns:u="{service_type}">\n'
        "      <NewRemoteHost></NewRemoteHost>\n"
        f"      <NewExternalPort>{external_port}</NewExternalPort>\n"
        f"      <NewProtocol>{protocol}</NewProtocol>\n"
        "    </u:DeletePortMapping>\n"
        "  </s:Body>\n"
        "</s:Envelope>\n"
    )
    return body.encode("utf-8")


def parse_soap_error(response_body: bytes) -> int | None:
    """Return the UPnP ``errorCode`` from a SOAP fault, or ``None`` if absent."""
    try:
        root = ElementTree.fromstring(response_body)
    except ElementTree.ParseError:
        return None
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "errorCode" and element.text and element.text.strip().isdigit():
            return int(element.text.strip())
    return None


def _soap_post(
    service: IgdService,
    action: str,
    soap_body: bytes,
    *,
    http_post: Callable[[str, str, bytes], None] | None = None,
) -> None:
    action_name = action.rsplit("}", 1)[-1]
    soap_action = f"{service.service_type}#{action_name}"
    request = urllib.request.Request(
        service.control_url,
        data=soap_body,
        method="POST",
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{soap_action}"',
        },
    )
    try:
        if http_post is None:
            with urllib.request.urlopen(request, timeout=5.0) as response:
                response.read()
        else:
            http_post(service.control_url, soap_action, soap_body)
    except urllib.error.HTTPError as exc:
        error_code = parse_soap_error(exc.read())
        message = f"SOAP {action_name} failed (HTTP {exc.code})"
        if error_code is not None:
            message += f" — errorCode {error_code}"
        raise UpnpError(message) from exc
    except OSError as exc:
        raise UpnpError(f"SOAP {action_name} transport failure: {exc}") from exc


def add_port_mapping(
    service: IgdService,
    *,
    internal_port: int,
    external_port: int | None = None,
    protocol: str = "UDP",
    description: str = "hsync-bootnode",
    lease_duration: int = 0,
    http_post: Callable[[str, str, bytes], None] | None = None,
) -> None:
    """Map ``external_port`` (default: same as internal) to this host (UDP)."""
    port = external_port if external_port is not None else internal_port
    soap = build_add_mapping_soap(
        service_type=service.service_type,
        internal_client=service.local_ip,
        internal_port=internal_port,
        external_port=port,
        protocol=protocol,
        description=description,
        lease_duration=lease_duration,
    )
    _soap_post(service, "AddPortMapping", soap, http_post=http_post)


def delete_port_mapping(
    service: IgdService,
    *,
    external_port: int,
    protocol: str = "UDP",
    http_post: Callable[[str, str, bytes], None] | None = None,
) -> None:
    """Remove a previously added port mapping (shutdown hygiene)."""
    soap = build_delete_mapping_soap(
        service_type=service.service_type,
        external_port=external_port,
        protocol=protocol,
    )
    _soap_post(service, "DeletePortMapping", soap, http_post=http_post)


class UpnpManager:
    """Asyncio zero-touch UPnP: map the QUIC listener port and refresh it.

    Stateless by design: discovery failure or an absent IGD is logged once and
    retried at the next cycle — the node keeps serving normally (the operator
    may instead open the port manually).
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
            except UpnpError:
                pass  # transient: retry at the next cycle, node keeps serving
            await asyncio.sleep(self.refresh_interval)

    def _ensure_mapped(self) -> None:
        service = self._active
        if service is None:
            service = discover_igd()
            if service is None:
                if not self._reported_missing:
                    logger.warning(
                        "UPnP: no IGD found on the LAN; port %s will not be "
                        "mapped. Open it manually or add --no-upnp.",
                        self.external_port,
                    )
                    self._reported_missing = True
                return
            add_port_mapping(
                service,
                internal_port=self.internal_port,
                external_port=self.external_port,
            )
            self._active = service
            logger.info(
                "UPnP: UDP %s -> %s mapped via %s",
                self.external_port,
                self.internal_port,
                service.control_url,
            )
            return
        # Refresh the existing mapping (idempotent AddPortMapping).
        add_port_mapping(
            service,
            internal_port=self.internal_port,
            external_port=self.external_port,
        )
