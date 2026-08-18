"""Every page renders, for every kind of session.

A template that only breaks for one protocol is easy to ship: the OIDC path is
the one anybody exercises by hand. These tests render the dashboard once per
sign-in method, with claims present rather than empty, because the interesting
template branches are the ones that only run when there is something to show.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.auth.connections import store_settings
from app.config import get_settings
from app.models import IdpConnection, UserSession
from app.security import _serializer


def _sign_in_as(client, db, **fields) -> UserSession:
    """Put an arbitrary session in the database and hand the client its cookie."""
    now = datetime.now(UTC)
    session = UserSession(
        created_at=now, expires_at=now + timedelta(hours=1), **fields
    )
    db.add(session)
    db.commit()
    client.cookies.set(get_settings().session_cookie_name, _serializer().dumps(session.id))
    return session


@pytest.fixture
def saml_connection(db) -> IdpConnection:
    connection = IdpConnection(
        slug="okta",
        name="Okta Workforce",
        protocol="saml",
        enabled=True,
        role_claim="groups",
        subject_claim="nameId",
        default_role="user",
        role_rules=[{"operator": "equals", "value": "SEC-Admins", "role": "admin"}],
        config={},
    )
    store_settings(
        connection,
        {"idp_sso_url": "https://example.okta.com/sso", "idp_entity_id": "http://www.okta.com/x"},
    )
    db.add(connection)
    db.commit()
    return connection


def test_dashboard_renders_for_a_local_session(admin_client):
    response = admin_client.get("/dashboard")

    assert response.status_code == 200
    assert "Local account" in response.text
    # No provider was involved, so this must not be reported as a policy failure.
    assert "verdict-fail" not in response.text


def test_dashboard_renders_when_the_role_claim_was_found(client, db, oidc_connection):
    """The claim-found branch renders the matched values.

    This is the branch that fires whenever role mapping works, so a failure
    here breaks the dashboard for every successfully mapped user.
    """
    _sign_in_as(
        client,
        db,
        subject="jane@example.com",
        email="jane@example.com",
        display_name="Jane",
        role="admin",
        source="testidp",
        protocol="oidc",
        raw_claims={
            "sub": "jane@example.com",
            "groups": ["SEC-Admins", "Everyone"],
            "amr": ["pwd", "mfa"],
            "ipaddr": "203.0.113.7",
        },
    )

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "SEC-Admins" in response.text
    assert "matched on" in response.text
    assert "Multiple factors" in response.text


def test_dashboard_renders_when_the_role_claim_is_missing(client, db, oidc_connection):
    _sign_in_as(
        client,
        db,
        subject="jane@example.com",
        email="jane@example.com",
        role="user",
        source="testidp",
        protocol="oidc",
        raw_claims={"sub": "jane@example.com", "email": "jane@example.com"},
    )

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "not present in this token" in response.text
    # The claims that *are* present are the useful next clue.
    assert "Claims that" in response.text


def test_dashboard_renders_for_a_saml_session(client, db, saml_connection):
    _sign_in_as(
        client,
        db,
        subject="jane@example.com",
        email="jane@example.com",
        role="admin",
        source="okta",
        protocol="saml",
        raw_claims={
            "nameId": "jane@example.com",
            "groups": "SEC-Admins",
            "authnContextClassRef": "urn:oasis:names:tc:SAML:2.0:ac:classes:X509",
        },
    )

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "Certificate-based authentication" in response.text
    assert "Request smart card PKI" in response.text  # the SAML re-test presets


def test_dashboard_renders_for_a_certificate_session(client, db):
    _sign_in_as(
        client,
        db,
        subject="cert.user@example.com",
        email="cert.user@example.com",
        role="user",
        source="piv",
        protocol="mtls",
        raw_claims={
            "amr": ["x509"],
            "subject_cn": "Cert User",
            "issuer_cn": "AuthLab Test CA",
            "thumbprint_sha256": "ABCD",
        },
    )

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "Certificate-based authentication" in response.text


def test_admin_pages_render(admin_client, oidc_connection, saml_connection):
    for path in (
        "/admin",
        "/admin/scim",
        "/admin/events",
        "/admin/users",
        "/admin/sessions",
        "/admin/connections/new?protocol=oidc",
        "/admin/connections/new?protocol=saml",
        "/admin/connections/new?protocol=mtls",
        f"/admin/connections/{oidc_connection.id}",
        f"/admin/connections/{saml_connection.id}",
    ):
        assert admin_client.get(path).status_code == 200, path


def test_saml_metadata_failure_is_a_page_not_a_500(admin_client, db, saml_connection):
    """An unusable SP block must be reported, not raised.

    python3-saml raises its own exception type for this, which would otherwise
    escape as a 500 that names nothing.
    """
    settings = get_settings()
    original = settings.base_url
    try:
        settings.base_url = "not-a-url"
        response = admin_client.post(f"/admin/connections/{saml_connection.id}/test")
        assert response.status_code == 200
        assert "BASE_URL" in response.text
    finally:
        settings.base_url = original


def test_saml_error_pages_still_carry_the_csp(client, saml_connection):
    """Only the metadata endpoint is exempt, not everything under /auth/saml/.

    The ACS and SLS endpoints render HTML — a rejected assertion produces a page
    carrying the provider's own error text — so they need the policy too.
    """
    response = client.post("/auth/saml/okta/acs", data={"nothing": "here"})

    assert "content-security-policy" in response.headers
    assert client.get("/auth/saml/okta/metadata").headers.get("content-security-policy") is None


def test_theme_assets_are_served_as_files(client):
    """The strict CSP means these cannot be inlined, so they must exist."""
    for path in ("/static/app.css", "/static/app.js", "/static/theme.js", "/static/favicon.svg"):
        assert client.get(path).status_code == 200, path


def test_pages_carry_no_inline_styles(admin_client, oidc_connection):
    """`style-src 'self'` blocks style attributes, so one would silently do nothing."""
    for path in ("/dashboard", "/admin", f"/admin/connections/{oidc_connection.id}"):
        assert 'style="' not in admin_client.get(path).text, path
