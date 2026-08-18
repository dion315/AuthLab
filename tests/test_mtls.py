"""Certificate-based sign-in: header handling, acceptance, and the routes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from sqlalchemy import select

from app.auth import certs, mtls
from app.auth.connections import redacted_config, store_settings
from app.models import IdpConnection, UserSession

UPN = "cert.user@example.com"


@pytest.fixture
def ca() -> tuple[str, str]:
    return certs.generate_ca("AuthLab mTLS Test CA")


@pytest.fixture
def mtls_connection(db, ca) -> IdpConnection:
    connection = IdpConnection(
        slug="certs",
        name="Client certificate",
        protocol="mtls",
        enabled=True,
        subject_claim="identity",
        email_claim="san_email",
        name_claim="subject_cn",
        role_claim="issuer_cn",
        default_role="user",
        role_rules=[{"operator": "contains", "value": "mTLS Test CA", "role": "power"}],
        config={},
    )
    store_settings(
        connection,
        {
            "header_name": "x-client-cert",
            "header_format": "auto",
            "trusted_ca_pem": ca[0],
            "ca_private_key": ca[1],
            "identity_sources": "san_upn,san_email,subject_cn",
        },
    )
    db.add(connection)
    db.commit()
    return connection


@pytest.fixture
def client_pem(ca) -> str:
    pem, _ = certs.issue_client_certificate(
        ca_cert_pem=ca[0], ca_key_pem=ca[1], common_name="Cert User", upn=UPN, email=UPN
    )
    return pem


# --- header decoding ---------------------------------------------------------


def test_xfcc_header_is_unwrapped(client_pem):
    """Envoy — and so Azure Container Apps — sends this shape."""
    header = f'Hash=abc123;Subject="CN=Cert User";Cert="{quote(client_pem)}"'

    assert certs.load_certificate(mtls.decode_header_value(header)).subject.rfc4514_string() == (
        "CN=Cert User"
    )


def test_xfcc_with_multiple_hops_uses_the_first(client_pem):
    other_pem, _ = certs.generate_self_signed("Other")
    header = f'Cert="{quote(client_pem)}",Cert="{quote(other_pem)}"'

    described = certs.describe(certs.load_certificate(mtls.decode_header_value(header)))

    assert described["subject_cn"] == "Cert User"


def test_url_encoded_pem_is_accepted(client_pem):
    """nginx's $ssl_client_escaped_cert, and AWS ALB's mTLS header."""
    assert mtls.decode_header_value(quote(client_pem)).startswith("-----BEGIN CERTIFICATE-----")


def test_base64_der_is_accepted(client_pem):
    """Azure App Service sends the DER body with no PEM armour."""
    body = "".join(line for line in client_pem.splitlines() if "-----" not in line)

    assert mtls.decode_header_value(body, "base64_der").startswith("-----BEGIN CERTIFICATE-----")


def test_empty_header_decodes_to_nothing():
    assert mtls.decode_header_value("") == ""


# --- acceptance --------------------------------------------------------------


def test_valid_certificate_is_accepted_and_bound_to_the_upn(mtls_connection, client_pem):
    result = mtls.evaluate(mtls_connection, client_pem)

    assert result.accepted
    assert result.identity == UPN
    assert result.identity_source == "san_upn"
    assert result.claims["amr"] == ["x509"]


def test_identity_falls_through_to_the_next_source(mtls_connection, ca):
    """A certificate with no UPN should still bind, via the next source."""
    pem, _ = certs.issue_client_certificate(
        ca_cert_pem=ca[0], ca_key_pem=ca[1], common_name="No UPN User"
    )

    result = mtls.evaluate(mtls_connection, pem)

    assert result.accepted
    assert result.identity == "No UPN User"
    assert result.identity_source == "subject_cn"


def test_certificate_from_an_untrusted_ca_is_refused(mtls_connection):
    other = certs.generate_ca("Unrelated CA")
    pem, _ = certs.issue_client_certificate(
        ca_cert_pem=other[0], ca_key_pem=other[1], common_name="Intruder", upn="intruder@evil.test"
    )

    result = mtls.evaluate(mtls_connection, pem)

    assert not result.accepted
    assert "Chain to a trusted CA" in result.reason


def test_expired_certificate_is_refused(mtls_connection, ca):
    now = datetime.now(UTC)
    pem, _ = certs.issue_client_certificate(
        ca_cert_pem=ca[0],
        ca_key_pem=ca[1],
        common_name="Expired",
        upn=UPN,
        not_before=now - timedelta(days=400),
        not_after=now - timedelta(days=35),
    )

    result = mtls.evaluate(mtls_connection, pem)

    assert not result.accepted
    assert "Validity period" in result.reason


def test_revoked_certificate_is_refused(db, mtls_connection, ca, client_pem):
    """Revocation is only checked against a CRL pasted into the connection."""
    certificate = certs.load_certificate(client_pem)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(certs.load_certificate(ca[0]).subject)
        .last_update(datetime.now(UTC) - timedelta(minutes=5))
        .next_update(datetime.now(UTC) + timedelta(days=7))
        .add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(certificate.serial_number)
            .revocation_date(datetime.now(UTC) - timedelta(minutes=1))
            .build()
        )
        .sign(certs.load_private_key(ca[1]), hashes.SHA256())
    )

    settings = redacted_config(mtls_connection)
    settings["crl_pem"] = crl.public_bytes(serialization.Encoding.PEM).decode("ascii")
    store_settings(mtls_connection, settings)
    db.commit()

    result = mtls.evaluate(mtls_connection, client_pem)

    assert not result.accepted
    assert "Revocation" in result.reason


def test_no_certificate_explains_what_is_missing(mtls_connection):
    result = mtls.evaluate(mtls_connection, "")

    assert not result.accepted
    assert "No client certificate was presented" in result.reason


def test_an_unreadable_trust_store_is_a_configuration_error(db, mtls_connection, client_pem):
    store_settings(mtls_connection, {"trusted_ca_pem": "not a certificate"})
    db.commit()

    with pytest.raises(mtls.MtlsError):
        mtls.evaluate(mtls_connection, client_pem)


# --- routes ------------------------------------------------------------------


def test_sign_in_with_a_certificate_creates_a_session(client, db, mtls_connection, client_pem):
    response = client.get(
        "/auth/mtls/certs/login",
        headers={"x-client-cert": quote(client_pem)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"

    session = db.execute(select(UserSession).where(UserSession.protocol == "mtls")).scalar_one()
    assert session.subject == UPN
    # The issuer CN matched the rule, so the certificate carried a role.
    assert session.role == "power"


def test_rejected_certificate_does_not_create_a_session(client, db, mtls_connection):
    other = certs.generate_ca("Unrelated CA")
    pem, _ = certs.issue_client_certificate(
        ca_cert_pem=other[0], ca_key_pem=other[1], common_name="Intruder"
    )

    response = client.get("/auth/mtls/certs/login", headers={"x-client-cert": quote(pem)})

    assert response.status_code == 403
    assert "Certificate rejected" in response.text
    assert db.execute(select(UserSession)).scalars().all() == []


def test_sign_in_without_a_certificate_explains_the_proxy_requirement(client, mtls_connection):
    response = client.get("/auth/mtls/certs/login")

    assert response.status_code == 403
    assert "No certificate presented" in response.text


def test_inspector_reports_a_certificate_under_a_different_header(client, mtls_connection, client_pem):
    """A proxy sending the right thing under the wrong name is a real case."""
    response = client.get(
        "/auth/mtls/certs/inspect", headers={"x-forwarded-client-cert": quote(client_pem)}
    )

    assert response.status_code == 200
    assert "Certificate accepted" in response.text


def test_inspector_lists_the_headers_that_did_arrive(client, mtls_connection):
    response = client.get("/auth/mtls/certs/inspect")

    assert response.status_code == 200
    assert "No certificate presented" in response.text


def test_mtls_connection_appears_on_the_sign_in_page(client, mtls_connection):
    response = client.get("/login")

    assert "/auth/mtls/certs/login" in response.text
    assert "Client certificate" in response.text


def test_admin_can_test_a_pasted_certificate(admin_client, db, mtls_connection, client_pem):
    response = admin_client.post(
        f"/admin/connections/{mtls_connection.id}/certificates/simulate",
        data={"certificate_pem": client_pem},
    )

    assert response.status_code == 200
    assert "Certificate accepted" in response.text
    # Simulation must not sign anyone in.
    assert db.execute(select(UserSession).where(UserSession.protocol == "mtls")).all() == []


def test_admin_can_generate_a_ca_and_issue_a_certificate(admin_client, db):
    created = admin_client.post(
        "/admin/connections",
        data={
            "protocol": "mtls",
            "name": "Smart cards",
            "slug": "smartcards",
            "enabled": "on",
            "header_name": "x-client-cert",
            "header_format": "auto",
            "identity_sources": "san_upn,subject_cn",
            "require_chain": "on",
            "check_validity": "on",
            "allow_pasted_certificate": "on",
            "default_role": "user",
        },
        follow_redirects=False,
    )
    assert created.status_code == 303

    connection = db.execute(
        select(IdpConnection).where(IdpConnection.slug == "smartcards")
    ).scalar_one()

    ca_response = admin_client.post(
        f"/admin/connections/{connection.id}/certificates/ca", follow_redirects=False
    )
    assert ca_response.status_code == 303

    db.refresh(connection)
    issued = admin_client.post(
        f"/admin/connections/{connection.id}/certificates/issue",
        data={"common_name": "PIV User", "upn": "piv.user@example.com", "validity": "valid"},
    )
    assert issued.status_code == 200
    assert "-----BEGIN CERTIFICATE-----" in issued.text
    # The private key is shown once here and never stored.
    assert "-----BEGIN PRIVATE KEY-----" in issued.text


def test_issuing_before_generating_a_ca_is_refused(admin_client, db, mtls_connection):
    """The fixture connection has a CA, so drop it to test the guard.

    The key is removed from the config directly rather than through
    store_settings, which treats an empty secret as "leave what is stored" —
    that rule is what stops the admin form wiping a secret it never renders.
    """
    config = dict(mtls_connection.config)
    config.pop("ca_private_key", None)
    mtls_connection.config = config
    db.commit()

    response = admin_client.post(
        f"/admin/connections/{mtls_connection.id}/certificates/issue",
        data={"common_name": "Nobody"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "no+test+CA+private+key" in response.headers["location"]


def test_ca_private_key_is_encrypted_at_rest(mtls_connection):
    assert mtls_connection.config["ca_private_key"].startswith("enc:v1:")
    assert "PRIVATE KEY" not in mtls_connection.config["ca_private_key"]
