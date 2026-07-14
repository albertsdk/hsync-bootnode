"""UPnP-IGD tests: SOAP builders, description parsing, injected transport.

No real network is touched: ``http_post``/``http_get`` are injected, SSDP parsing
is tested with canned responses, and the SOAP XML is verified field by field.
"""

from __future__ import annotations

from hsync_bootnode.upnp import (
    IgdService,
    UpnpError,
    _parse_ssdp_response,
    add_port_mapping,
    build_add_mapping_soap,
    build_delete_mapping_soap,
    delete_port_mapping,
    parse_soap_error,
)

NS = "urn:schemas-upnp-org:service:WANIPConnection:1"
SERVICE = IgdService(control_url="http://192.168.1.1:5000/ctl/IPConn", local_ip="192.168.1.10")


def test_add_mapping_soap_contains_expected_fields() -> None:
    soap = build_add_mapping_soap(
        service_type=NS,
        internal_client="192.168.1.10",
        internal_port=443,
        external_port=443,
    ).decode("utf-8")
    assert "AddPortMapping" in soap
    assert '"urn:schemas-upnp-org:service:WANIPConnection:1"' in soap
    assert "<NewExternalPort>443</NewExternalPort>" in soap
    assert "<NewInternalPort>443</NewInternalPort>" in soap
    assert "<NewProtocol>UDP</NewProtocol>" in soap
    assert "<NewInternalClient>192.168.1.10</NewInternalClient>" in soap
    assert "<NewEnabled>1</NewEnabled>" in soap
    assert "hsync-bootnode" in soap


def test_delete_mapping_soap_shape() -> None:
    soap = build_delete_mapping_soap(service_type=NS, external_port=443).decode("utf-8")
    assert "DeletePortMapping" in soap
    assert "<NewExternalPort>443</NewExternalPort>" in soap


def test_parse_soap_error_finds_error_code() -> None:
    fault = b"""<?xml version="1.0"?>
    <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
      <s:Body><s:Fault><detail>
        <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
          <errorCode>713</errorCode><errorDescription>Conflict</errorDescription>
        </UPnPError>
      </detail></s:Fault></s:Body>
    </s:Envelope>"""
    assert parse_soap_error(fault) == 713
    assert parse_soap_error(b"<not-soap/>") is None
    assert parse_soap_error(b"") is None


def test_ssdp_response_location_extraction() -> None:
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"CACHE-CONTROL: max-age=1800\r\n"
        b"LOCATION: http://192.168.1.1:1900/rootDesc.xml\r\n"
        b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
    )
    assert _parse_ssdp_response(response) == "http://192.168.1.1:1900/rootDesc.xml"
    assert _parse_ssdp_response(b"HTTP/1.1 404 Not Found\r\n\r\n") is None


def test_add_port_mapping_injects_transport() -> None:
    calls: list[tuple[str, str, bytes]] = []

    def fake_post(url: str, soap_action: str, body: bytes) -> None:
        calls.append((url, soap_action, body))

    add_port_mapping(
        SERVICE,
        internal_port=443,
        http_post=fake_post,
    )
    assert len(calls) == 1
    url, soap_action, body = calls[0]
    assert url == SERVICE.control_url
    assert soap_action == f"{NS}#AddPortMapping"
    assert b"AddPortMapping" in body


def test_delete_port_mapping_injects_transport() -> None:
    calls: list[tuple[str, str, bytes]] = []

    def fake_post(url: str, soap_action: str, body: bytes) -> None:
        calls.append((url, soap_action, body))

    delete_port_mapping(SERVICE, external_port=443, http_post=fake_post)
    assert calls[0][1] == f"{NS}#DeletePortMapping"


def test_upnp_error_code_downgrade_message() -> None:
    """A mapping failure surfaces as UpnpError (the manager logs + retries)."""

    def failing_post(url: str, soap_action: str, body: bytes) -> None:
        raise OSError("no route to host")

    try:
        add_port_mapping(SERVICE, internal_port=443, http_post=failing_post)
    except UpnpError as exc:
        assert "AddPortMapping" in str(exc)
    else:  # pragma: no cover - expected to raise
        raise AssertionError("transport failure must raise UpnpError")


def test_upnp_manager_stateless_when_no_igd(monkeypatch: object) -> None:
    import hsync_bootnode.upnp as upnp_mod

    monkeypatch.setattr(upnp_mod, "discover_igd", lambda *a, **k: None)
    manager = upnp_mod.UpnpManager(443, refresh_interval=3600.0)
    # No IGD on the LAN: the first run must not raise and must not mark the
    # mapping active, keeping the node serving.
    manager._ensure_mapped()
    assert manager._active is None
    assert manager._reported_missing is True
