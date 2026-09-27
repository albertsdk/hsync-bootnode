# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Copyright (C) 2025 Alberto Basso

"""White-box tests for the persistent bootnode TLS identity (ADR-0034)."""

import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519

from hsync_bootnode.server import (
    IdentityError,
    load_identity,
    load_or_create_identity,
    make_identity,
    rotate_identity,
)


def test_make_identity_is_ed25519_and_not_ca():
    node = make_identity(host="127.0.0.1")
    assert isinstance(node.private_key, ed25519.Ed25519PrivateKey)
    assert node.is_ca is False


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


def test_load_or_create_creates_with_restricted_permissions(tmp_path):
    path = tmp_path / "state" / "identity.pem"
    node = load_or_create_identity(path, host="127.0.0.1", public_hosts=["boot.example.com"])
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert isinstance(node.private_key, ed25519.Ed25519PrivateKey)
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
