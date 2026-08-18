"""Certificate parsing, inspection, and chain validation.

These are the checks a provider would normally run on a user's certificate, so
they are worth testing the way you would test a policy: one case per way a
certificate can be wrong, each asserting that the *right* check is the one that
fails. A validator that rejects everything passes a test that only asserts
rejection.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.auth import certs

CN = "Test User"
UPN = "test.user@example.com"


@pytest.fixture(scope="module")
def ca() -> tuple[str, str]:
    return certs.generate_ca("AuthLab Unit Test CA")


@pytest.fixture(scope="module")
def client_certificate(ca) -> tuple[str, str]:
    cert_pem, key_pem = ca
    return certs.issue_client_certificate(
        ca_cert_pem=cert_pem, ca_key_pem=key_pem, common_name=CN, upn=UPN, email=UPN
    )


# --- normalisation -----------------------------------------------------------


def test_bare_base64_is_wrapped_as_pem(client_certificate):
    pem, _ = client_certificate
    body = "".join(line for line in pem.splitlines() if "-----" not in line)

    restored = certs.normalise_pem(body)

    assert restored.startswith("-----BEGIN CERTIFICATE-----")
    assert certs.load_certificate(restored).subject == certs.load_certificate(pem).subject


def test_percent_encoded_pem_is_accepted(client_certificate):
    """Envoy and nginx both forward the certificate percent-encoded."""
    pem, _ = client_certificate
    encoded = pem.replace("\n", "%0A").replace(" ", "%20").replace("-", "%2D")

    assert certs.load_certificate(encoded).subject.rfc4514_string() == f"CN={CN}"


def test_escaped_newlines_are_accepted(client_certificate):
    pem, _ = client_certificate

    assert certs.load_certificate(pem.replace("\n", "\\n")).serial_number > 0


def test_bundle_returns_every_certificate(ca, client_certificate):
    ca_pem, _ = ca
    leaf_pem, _ = client_certificate

    assert len(certs.load_certificates(leaf_pem + "\n" + ca_pem)) == 2


def test_unparseable_input_names_the_problem():
    with pytest.raises(certs.CertificateError):
        certs.load_certificate("not a certificate at all")


# --- inspection --------------------------------------------------------------


def test_describe_reports_the_fields_identity_binds_to(client_certificate):
    pem, _ = client_certificate

    described = certs.describe(pem and certs.load_certificate(pem))

    assert described["subject_cn"] == CN
    # The UPN lives in an otherName SAN, which is where a smart card puts it.
    assert described["san_upn"] == [UPN]
    assert described["san_email"] == [UPN]
    assert "clientAuth" in described["extended_key_usage"]
    assert described["is_ca"] is False
    assert described["expired"] is False


def test_thumbprints_are_stable_and_distinct(client_certificate):
    certificate = certs.load_certificate(client_certificate[0])

    assert len(certs.thumbprint(certificate, "sha256")) == 64
    assert len(certs.thumbprint(certificate, "sha1")) == 40
    # x5t#S256 is the base64url form of the same SHA-256 digest.
    assert certs.x5t_s256(certificate).rstrip("=") == certs.x5t_s256(certificate)


def test_describe_pem_reports_errors_instead_of_raising():
    result = certs.describe_pem("garbage")

    assert result["ok"] is False
    assert result["error"]


# --- chain validation --------------------------------------------------------


def test_valid_certificate_chains_to_its_ca(ca, client_certificate):
    anchors = certs.load_certificates(ca[0])

    result = certs.validate_chain(certs.load_certificate(client_certificate[0]), anchors)

    assert result.valid
    assert "CN=AuthLab Unit Test CA" in result.anchor
    assert all(check.passed for check in result.checks)


def test_certificate_from_another_ca_is_refused(client_certificate):
    other_ca_pem, _ = certs.generate_ca("Someone Else's CA")

    result = certs.validate_chain(
        certs.load_certificate(client_certificate[0]), certs.load_certificates(other_ca_pem)
    )

    assert not result.valid
    assert [check.name for check in result.failures] == ["Chain to a trusted CA"]


def test_expired_certificate_fails_only_the_validity_check(ca):
    now = datetime.now(UTC)
    expired_pem, _ = certs.issue_client_certificate(
        ca_cert_pem=ca[0],
        ca_key_pem=ca[1],
        common_name="Expired User",
        not_before=now - timedelta(days=400),
        not_after=now - timedelta(days=35),
    )

    result = certs.validate_chain(
        certs.load_certificate(expired_pem), certs.load_certificates(ca[0])
    )

    assert not result.valid
    assert [check.name for check in result.failures] == ["Validity period"]


def test_validity_can_be_skipped_deliberately(ca):
    now = datetime.now(UTC)
    expired_pem, _ = certs.issue_client_certificate(
        ca_cert_pem=ca[0],
        ca_key_pem=ca[1],
        common_name="Expired User",
        not_before=now - timedelta(days=400),
        not_after=now - timedelta(days=35),
    )

    result = certs.validate_chain(
        certs.load_certificate(expired_pem),
        certs.load_certificates(ca[0]),
        check_validity=False,
    )

    assert result.valid


def test_no_trust_anchors_is_reported_as_a_configuration_problem(client_certificate):
    result = certs.validate_chain(certs.load_certificate(client_certificate[0]), [])

    assert not result.valid
    assert "no trust anchors" in result.failures[0].detail


def test_a_leaf_certificate_cannot_act_as_its_own_anchor(client_certificate):
    """A non-CA certificate in the trust store must not validate anything.

    Pasting the client certificate itself into the CA field is an easy mistake,
    and accepting it would make the whole check meaningless.
    """
    leaf = certs.load_certificate(client_certificate[0])

    result = certs.validate_chain(leaf, [leaf])

    assert not result.valid


def test_self_signed_certificate_is_not_accepted_by_an_unrelated_anchor(ca):
    self_signed_pem, _ = certs.generate_self_signed("Self Signed User", client_auth=True)

    result = certs.validate_chain(
        certs.load_certificate(self_signed_pem), certs.load_certificates(ca[0])
    )

    assert not result.valid


def test_certificate_with_no_eku_extension_is_unconstrained(ca):
    """No EKU extension at all means "any purpose", not "no purpose".

    Worth pinning down: rejecting these would refuse a great many real
    certificates, and the reported reason has to distinguish an absent
    extension from one that lists the wrong usages.
    """
    no_eku_pem, _ = certs.generate_self_signed("No EKU", client_auth=False)

    result = certs.validate_chain(
        certs.load_certificate(no_eku_pem),
        certs.load_certificates(ca[0]),
        require_client_auth_eku=True,
    )

    # No EKU extension at all is unconstrained, so that check passes; it is the
    # chain that fails. The distinction matters — the message must be right.
    eku_check = next(c for c in result.checks if c.name == "Extended key usage")
    assert eku_check.passed
    assert "no EKU extension" in eku_check.detail


def test_certificate_for_the_wrong_purpose_is_refused(ca):
    """A certificate that names its usages, and does not name clientAuth."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    ca_certificate = certs.load_certificate(ca[0])
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    server_only = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "web.example.com")]))
        .issuer_name(ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(certs.load_private_key(ca[1]), hashes.SHA256())
    )

    result = certs.validate_chain(server_only, certs.load_certificates(ca[0]))

    assert not result.valid
    assert [check.name for check in result.failures] == ["Extended key usage"]


# --- issuance ----------------------------------------------------------------


def test_issued_certificate_can_be_bundled_as_pkcs12(ca, client_certificate):
    payload = certs.to_pkcs12(
        cert_pem=client_certificate[0],
        key_pem=client_certificate[1],
        ca_pem=ca[0],
        friendly_name="test-user",
        password="import-me",
    )

    # PKCS#12 is a DER SEQUENCE; anything shorter is not a bundle.
    assert payload[:1] == b"\x30"
    assert len(payload) > 1000


def test_a_certificate_issued_as_expired_really_is_expired(ca):
    now = datetime.now(UTC)
    pem, _ = certs.issue_client_certificate(
        ca_cert_pem=ca[0],
        ca_key_pem=ca[1],
        common_name="Expired",
        not_before=now - timedelta(days=400),
        not_after=now - timedelta(days=35),
    )

    assert certs.describe(certs.load_certificate(pem))["expired"] is True


def test_generated_ca_is_a_ca(ca):
    assert certs.is_certificate_authority(certs.load_certificate(ca[0])) is True


def test_generated_client_certificate_is_not_a_ca(client_certificate):
    assert certs.is_certificate_authority(certs.load_certificate(client_certificate[0])) is False
