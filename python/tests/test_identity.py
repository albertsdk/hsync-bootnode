# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Alberto Basso

"""White-box tests for the persistent bootnode TLS identity (ADR-0034/ADR-0037).

Service identities are ECDSA P-256, stored unencrypted under ``0600``/``0700``
permissions, with a 20-year validity; the loader accepts nothing else.
"""

import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec
from hsync_common import ssl_utils

from hsync_bootnode.server import (
    IdentityError,
    load_identity,
    load_or_create_identity,
    make_identity,
    rotate_identity,
)


def test_make_identity_is_ecdsa_p256():
    node = make_identity(host="127.0.0.1")
    assert isinstance(node.private_key, ec.EllipticCurvePrivateKey)
    assert isinstance(node.private_key.curve, ec.SECP256R1)


def test_make_identity_san_includes_bind_and_public_hosts():
    node = make_identity(host="127.0.0.1", public_hosts=["boot.example.com", "198.51.100.9"])
    san = node.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = {n.value for n in san}
    assert "boot.example.com" in names
    assert ipaddress.IPv4Address("198.51.100.9") in names
    assert ipaddress.IPv4Address("127.0.0.1") in names


def test_make_identity_wildcard_bind_uses_dns_name():
    node = make_identity(host="0.0.0.0")
    san = node.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = {n.value for n in san}
    assert "hsync-bootnode" in names


def test_make_identity_validity_is_twenty_years():
    from datetime import UTC, datetime, timedelta

    node = make_identity(host="127.0.0.1")
    assert node.expires_at == node.certificate.not_valid_after_utc
    assert node.expires_at > datetime.now(UTC) + timedelta(days=365 * 19)


def test_load_or_create_creates_with_restricted_permissions(tmp_path):
    path = tmp_path / "state" / "identity.pem"
    node = load_or_create_identity(path, host="127.0.0.1", public_hosts=["boot.example.com"])
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert isinstance(node.private_key, ec.EllipticCurvePrivateKey)
    assert len(str(node.fingerprint)) == 64


def test_load_or_create_is_stable_across_loads(tmp_path):
    path = tmp_path / "identity.pem"
    first = load_or_create_identity(path)
    data = path.read_bytes()
    second = load_or_create_identity(path)
    assert str(second.fingerprint) == str(first.fingerprint)
    assert path.read_bytes() == data  # no rewrite on an existing identity


def test_rotate_changes_fingerprint(tmp_path):
    path = tmp_path / "identity.pem"
    first = load_or_create_identity(path)
    rotated = rotate_identity(path, host="127.0.0.1")
    assert str(rotated.fingerprint) != str(first.fingerprint)
    assert str(load_identity(path).fingerprint) == str(rotated.fingerprint)


def test_rotate_requires_existing_file(tmp_path):
    with pytest.raises(IdentityError):
        rotate_identity(tmp_path / "missing.pem")


def test_load_identity_rejects_missing_and_garbage(tmp_path):
    with pytest.raises(IdentityError):
        load_identity(tmp_path / "missing.pem")
    garbage = tmp_path / "garbage.pem"
    garbage.write_text("this is not a PEM file")
    with pytest.raises(IdentityError):
        load_identity(garbage)


def test_load_identity_rejects_cert_without_key(tmp_path):
    node = make_identity(host="127.0.0.1")
    from hsync_common import ssl_utils

    cert_only = tmp_path / "cert-only.pem"
    cert_only.write_bytes(ssl_utils.serialize_cert_pem(node.certificate))
    with pytest.raises(IdentityError):
        load_identity(cert_only)


def _write_identity(path, key) -> None:
    cert = ssl_utils.build_self_signed_certificate(
        key,
        subject_attrs=[x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "hsync-bootnode")],
        san_list=[x509.DNSName("hsync-bootnode")],
        validity_days=30,
    )
    path.write_bytes(
        ssl_utils.serialize_cert_pem(cert)
        + b"\n"
        + ssl_utils.serialize_private_key_unencrypted(key)
    )


@pytest.mark.parametrize(
    "key_factory",
    [
        lambda: ssl_utils.generate_rsa_private_key(),
        lambda: ssl_utils.generate_ed25519_private_key(),
        lambda: dsa.generate_private_key(key_size=2048),
    ],
)
def test_load_identity_rejects_non_ecdsa(tmp_path, key_factory):
    """Service identities are ECDSA P-256 only; any other key type is refused."""
    path = tmp_path / "non-ecdsa.pem"
    _write_identity(path, key_factory())
    with pytest.raises(IdentityError):
        load_identity(path)


def test_make_identity_dns_bind_host_uses_dns_san():
    """A DNS-name bind host is recorded as a DNS SAN, not an IP SAN crash."""
    node = make_identity(host="localhost")
    san = node.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = {n.value for n in san}
    assert "localhost" in names
