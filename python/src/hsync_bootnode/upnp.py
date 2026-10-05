"""Minimal UPnP-IGD client (pure standard library, cross-platform).

Replaces the planned ``miniupnpc`` binding: that C extension cannot be built
without Python development headers (unavailable in this environment), and a
pure-Python IGD client keeps the v1 footprint dependency-free and byte-identical
on Linux/macOS/Windows. The IGD protocol itself (SSDP + SOAP over HTTP)
is platform-independent.

Only the services a matchmaker needs are implemented: ``AddPortMapping``
(UDP, the QUIC listener port). The mapping is refreshable and every failure
degrades to the documented "no UPnP" state (stateless) rather than crashing the
node.

SSDP hardening (SSRF is a reply-by-anyone protocol): an M-SEARCH answer or its
``LOCATION`` URL comes from unauthenticated data, so both are validated before
any HTTP request is made —
    - the SSDP reply's source address must be a private, non-link-local,
      non-loopback unicast (the LAN; a host on the plain Internet has no LAN to
      discover and every unsolicited or spoofed reply is discarded unopened);
    - ``LOCATION`` must be an ``http(s)://`` URL whose host is an IP **literal**
      in the private range (no hostnames, so no DNS-rebinding paths, and no
      ``file:``/``ftp:`` URL handlers);
    - redirects are refused: the description and the SOAP POST are fetched with
      an opener whose redirect handler never follows a user-influenced URL.
The node itself parses network data only with ElementTree on the bounded
response body (64 KiB), and no reply content is ever logged (no-log).
"""

from __future__ import annotations

import asyncio
import ipaddress
import posixpath
import socket
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from xml.etree import ElementTree

from hsync_bootnode.diagnostics import debug_event, warn_event

__all__ = [
    "UPNP_SSDP_ADDR",
    "IgdService",
    "UpnpError",
    "UpnpManager",
    "add_port_mapping",
    "build_add_mapping_soap",
    "discover_igd",
    "is_lan_unicast_address",
    "is_private_http_location",
    "no_redirect_urlopen",
    "parse_soap_error",
]

UPNP_SSDP_ADDR = ("239.255.255.250", 1900)
_SSDP_SEARCH_TARGET = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
_SERVICE_TYPES = (
    "urn:schemas-upnp-org:service:WANIPConnection:",
    "urn:schemas-upnp-org:service:WANPPPConnection:",
)
_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {UPNP_SSDP_ADDR[0]}:{UPNP_SSDP_ADDR[1]}\r\n"
    'MAN: "ssdp:discover"\r\n'
    f"ST: {_SSDP_SEARCH_TARGET}\r\n"
    "MX: 1\r\n"
    "\r\n"
).encode("ascii")

# IGD service namespace prefix used for SOAPAction and body element names.
_SERVICE_NS = "urn:schemas-upnp-org:service:WANIPConnection:1"

# Networks an M-SEARCH reply and its LOCATION host must belong to. The IGD is a
# LAN device: private unicast ranges only (RFC 1918 + IPv6 ULA fc00::/7).
# Link-local (169.254/16, fe80::/10 — the range hosting cloud-metadata
# services) and loopback are deliberately excluded: no IGD answers from there
# and both would otherwise become SSDP-controlled SSRF targets.
_LAN_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)

# The redirect handler the whole module lands on: a location or control URL is
# attacker-influenced data, so an HTTP 3xx must never be followed.
_OPENER: urllib.request.OpenerDirector | None = None

# URL schemes a LOCATION may use. LAN IGDs publish plain ``http``; ``https`` is
# allowed as well because the host is pinned to a private IP literal either way
# (a certificate mismatch would simply fail the fetch). Everything else —
# ``file:``, ``ftp:``, data URIs — is refused before urlopen even runs.
_LOCATION_SCHEMES = ("http", "https")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: never follow a URL that came from an SSDP reply."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def no_redirect_urlopen(url: str | urllib.request.Request, timeout: float) -> Any:
    """Open ``url`` with the module's no-redirect opener (context manager use)."""
    global _OPENER
    if _OPENER is None:
        _OPENER = urllib.request.build_opener(_NoRedirect())
    return _OPENER.open(url, timeout=timeout)  # noqa: S310 - scheme validated before


def is_lan_unicast_address(text: str) -> bool:
    """True iff ``text`` parses to an address inside the private LAN ranges."""
    try:
        address = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return False
    return any(address in network for network in _LAN_NETWORKS)


def is_private_http_location(location: str) -> bool:
    """True iff ``location`` is an ``http://<private-IP-literal>/…`` URL.

    The LOCATION URL reported by an IGD is attacker-influenced data: allowing
    anything else would turn the SSDP reply into an SSRF primitive. Hostnames
    are rejected (an IGD publishes an IP literal; a hostname would add a
    DNS-resolved, DNS-rebindable target) and every non-HTTP(S) scheme is
    rejected, so ``file:``, ``ftp:`` and any other URL handler stays out of
    reach.
    """
    try:
        parts = urlsplit(location)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme not in _LOCATION_SCHEMES or parts.hostname is None:
        return False
    if parts.username is not None or parts.password is not None:
        return False
    if port is not None and not 1 <= port <= 65535:
        return False
    return is_lan_unicast_address(parts.hostname)


def _validated_http_url(location: str) -> str | None:
    """Return ``location`` normalised for a validated private-IP http(s) URL, else None."""
    if not is_private_http_location(location):
        return None
    parts = urlsplit(location)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


class UpnpError(RuntimeError):
    """A UPnP/IGD operation failed (device, network or protocol error)."""


@dataclass(frozen=True, slots=True)
class IgdService:
    """An InternetGatewayDevice offering a WAN connection service."""

    control_url: str
    local_ip: str
    service_type: str = _SERVICE_NS


def discover_igd(timeout: float = 2.0) -> IgdService | None:
    """Discover the LAN's IGD via SSDP M-SEARCH; return its WAN service.

    ``local_ip`` is captured from the sending socket (the LAN address a
    port mapping must target) — no extra route lookups, no packets beyond
    the obligatory M-SEARCH.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.sendto(_MSEARCH, UPNP_SSDP_ADDR)
        local_ip = sock.getsockname()[0]
        return _first_igd_location(sock, timeout, local_ip)
    except OSError as exc:
        raise UpnpError(f"SSDP discovery failed: {exc}") from exc
    finally:
        sock.close()


def _first_igd_location(sock: socket.socket, timeout: float, local_ip: str) -> IgdService | None:
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            data, addr = sock.recvfrom(4096)
        except TimeoutError:
            return None
        # An SSDP reply is unauthenticated data from anyone: only a source on
        # the private LAN may speak, so plain-Internet or spoofed replies are
        # discarded UNOPENED (no DNS lookup, no HTTP request, no parse).
        if not (isinstance(addr, tuple) and len(addr) == 2 and is_lan_unicast_address(addr[0])):
            continue
        location = _parse_ssdp_response(data)
        if location is None or not is_private_http_location(location):
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
    """Fetch the IGD description XML and locate a WAN connection control URL.

    ``location`` is re-validated here and every URL this function produces is
    built from the LOCATION's (validated) host netloc: a controlURL that tries
    to escape to another host (absolute URL or ``//host/path``) is refused, so
    the SOAP POST can never target a device other than the one that answered.
    """
    base = _validated_http_url(location)
    if base is None:
        return None
    try:
        with no_redirect_urlopen(base, timeout=3.0) as response:
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
        control_url = _control_url_on_base(base, control)
        if control_url is None:
            continue
        prefix = service_type.rsplit(":", 1)[0]
        return IgdService(
            control_url=control_url,
            local_ip=local_ip,
            service_type=f"{prefix}:1",
        )
    return None


def _control_url_on_base(base: str, control: str) -> str | None:
    """Resolve a relative ``controlURL`` against the validated base host only.

    A controlURL is usually a root-relative path (``/control/WANIPConnection``),
    sometimes device-relative. Anything that changes the host (an absolute URL,
    a ``//host`` netloc reference, a scheme designation) is refused instead of
    being followed: the control URL must stay on the device that answered the
    SSDP reply.
    """
    if "://" in control or control.startswith("//"):
        return None
    base_parts = urlsplit(base)
    if control.startswith("/"):
        path = control
    else:
        path = posixpath.join(posixpath.dirname(base_parts.path) or "/", control)
    resolved = f"/{posixpath.normpath(path).lstrip('/')}" if path.startswith("/") else path
    candidate = urlunsplit((base_parts.scheme, base_parts.netloc, resolved, "", ""))
    return candidate if is_private_http_location(candidate) else None


def _soap_envelope(inner: str) -> bytes:
    """Wrap *inner* in the SOAP 1.1 envelope shared by both builders."""
    body = (
        '<?xml version="1.0"?>\n'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n'
        "  <s:Body>\n"
        f"{inner}"
        "  </s:Body>\n"
        "</s:Envelope>\n"
    )
    return body.encode("utf-8")


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
    inner = (
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
    )
    return _soap_envelope(inner)


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
    soap_action = f"{service.service_type}#{action}"
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
            with no_redirect_urlopen(request, timeout=5.0) as response:
                response.read()
        else:
            http_post(service.control_url, soap_action, soap_body)
    except urllib.error.HTTPError as exc:
        error_code = parse_soap_error(exc.read())
        message = f"SOAP {action} failed (HTTP {exc.code})"
        if error_code is not None:
            message += f" — errorCode {error_code}"
        raise UpnpError(message) from exc
    except OSError as exc:
        raise UpnpError(f"SOAP {action} transport failure: {exc}") from exc


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
