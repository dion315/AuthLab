"""Every page renders.

Cheap, but it earns its place: the dashboard's role-mapping card carried a
`{{ claim_lookup.values }}` that Jinja resolved to the dict *method* rather than
the key, so any federated sign-in whose role claim was found produced a 500.
Nothing caught it because no test had ever rendered the dashboard with a
connection attached. These do.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.auth import connections as conn
from app.models import IdpConnection, ScimGroup, ScimUser, UserSession
from app.security import _serializer


@pytest.fixture
def oidc_conn(db):
    connection = IdpConnection(
        slug="entra",
        name="Contoso Entra",
        protocol="oidc",
        enabled=True,
        role_claim="groups",
        role_source="claims",
        subject_claim="preferred_username",
        default_role="user",
        role_rules=[{"operator": "equals", "value": "SEC-Admins", "role": "admin"}],
        expectations=[{"claim": "amr", "operator": "contains", "value": "mfa"}],
        expected_role="admin",
        stepup_claim="amr",
        stepup_operator="contains",
        stepup_value="mfa",
        stepup_acr_values="mfa",
        config={},
    )
    conn.store_settings(
        connection,
        {"issuer": "https://login.microsoftonline.com/tid/v2.0", "client_id": "abc"},
    )
    db.add(connection)
    db.commit()
    return connection


def federated_session(db, claims: dict, source: str = "entra") -> UserSession:
    now = datetime.now(UTC)
    row = UserSession(
        subject="alice@contoso.com",
        email="alice@contoso.com",
        display_name="Alice",
        role="admin",
        source=source,
        protocol="oidc",
        raw_claims=claims,
        created_at=now,
        expires_at=now + timedelta(hours=1),
        client_ip="203.0.113.4",
    )
    db.add(row)
    db.commit()
    return row


def adopt(client, row: UserSession) -> None:
    client.cookies.set("authlab_session", _serializer().dumps(row.id))


# --- dashboard ----------------------------------------------------------------


def test_dashboard_renders_for_the_local_account(admin_client):
    response = admin_client.get("/dashboard")
    assert response.status_code == 200
    assert "Local weather" in response.text


def test_dashboard_renders_with_a_found_role_claim(admin_client, db, oidc_conn):
    """The exact shape that used to 500."""
    row = federated_session(
        db,
        {
            "sub": "pairwise",
            "preferred_username": "alice@contoso.com",
            "groups": ["SEC-Admins", "Everyone"],
            "amr": ["pwd", "mfa"],
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
        },
    )
    adopt(admin_client, row)

    response = admin_client.get("/dashboard")
    assert response.status_code == 200
    assert "SEC-Admins" in response.text
    assert "matched on" in response.text


def test_dashboard_renders_when_the_role_claim_is_missing(admin_client, db, oidc_conn):
    row = federated_session(db, {"sub": "pairwise", "amr": ["pwd"]})
    adopt(admin_client, row)

    response = admin_client.get("/dashboard")
    assert response.status_code == 200
    assert "nothing found to match against" in response.text


def test_dashboard_shows_a_failed_expectation(admin_client, db, oidc_conn):
    row = federated_session(db, {"groups": ["SEC-Admins"], "amr": ["pwd"]})
    adopt(admin_client, row)

    response = admin_client.get("/dashboard")
    assert response.status_code == 200
    assert "Expected outcome" in response.text
    assert "1 failed" in response.text


def test_dashboard_shows_passing_expectations(admin_client, db, oidc_conn):
    row = federated_session(db, {"groups": ["SEC-Admins"], "amr": ["pwd", "mfa"]})
    adopt(admin_client, row)

    response = admin_client.get("/dashboard")
    assert "all passed" in response.text


def test_dashboard_shows_token_lifetimes(admin_client, db, oidc_conn):
    now = datetime.now(UTC)
    row = federated_session(
        db,
        {
            "groups": ["SEC-Admins"],
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
    )
    adopt(admin_client, row)

    response = admin_client.get("/dashboard")
    assert "Token and session lifetimes" in response.text
    # The session TTL is 60 minutes, so it outlives a 5-minute token.
    assert "outlives the token" in response.text


def test_dashboard_shows_the_scim_link_when_the_role_source_uses_it(
    admin_client, db, oidc_conn
):
    oidc_conn.role_source = "claims_then_scim"
    group = ScimGroup(display_name="SEC-Admins")
    user = ScimUser(user_name="alice@contoso.com", email="alice@contoso.com")
    user.groups.append(group)
    db.add_all([group, user])
    db.commit()

    row = federated_session(db, {"groups": []})
    adopt(admin_client, row)

    response = admin_client.get("/dashboard")
    assert response.status_code == 200
    assert "Provisioned identity" in response.text
    assert "linked" in response.text


def test_dashboard_explains_a_missing_scim_link(admin_client, db, oidc_conn):
    oidc_conn.role_source = "scim"
    db.commit()

    row = federated_session(db, {"groups": []})
    adopt(admin_client, row)

    response = admin_client.get("/dashboard")
    assert "No provisioned user matches this session" in response.text


def test_scim_group_membership_can_grant_a_role(admin_client, db, oidc_conn):
    """The whole point of the SCIM role source."""
    oidc_conn.role_source = "scim"
    group = ScimGroup(display_name="SEC-Admins")
    user = ScimUser(user_name="alice@contoso.com", email="alice@contoso.com")
    user.groups.append(group)
    db.add_all([group, user])
    db.commit()

    row = federated_session(db, {"groups": []})
    row.role = "user"
    db.commit()
    adopt(admin_client, row)

    response = admin_client.get("/dashboard")
    assert response.status_code == 200
    # Recomputed live, so the drift warning names the role SCIM would grant.
    assert "would assign" in response.text
    assert 'matched on "SEC-Admins"' in response.text
    assert 'class="badge">scim<' in response.text


# --- admin pages ---------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/admin",
        "/admin/scim",
        "/admin/events",
        "/admin/users",
        "/admin/sessions",
        "/admin/sessions/compare",
        "/admin/automation",
        "/admin/service-access",
        "/admin/connections/new?protocol=oidc",
        "/admin/connections/new?protocol=saml",
        "/account/password",
        "/step-up",
    ],
)
def test_admin_pages_render(admin_client, path):
    response = admin_client.get(path)
    assert response.status_code == 200, response.text[:400]


def test_connection_edit_pages_render(admin_client, db, oidc_conn):
    response = admin_client.get(f"/admin/connections/{oidc_conn.id}")
    assert response.status_code == 200
    assert "Expected outcome" in response.text
    assert "Step-up challenge" in response.text
    assert "Evaluate rules against" in response.text


def test_saml_connection_edit_page_shows_the_sls_url(admin_client, db):
    connection = IdpConnection(slug="okta-saml", name="Okta SAML", protocol="saml", config={})
    conn.store_settings(connection, {"idp_sso_url": "https://x.okta.com/sso"})
    db.add(connection)
    db.commit()

    response = admin_client.get(f"/admin/connections/{connection.id}")
    assert response.status_code == 200
    assert "/auth/saml/okta-saml/sls" in response.text


def test_connection_export_download(admin_client, db, oidc_conn):
    response = admin_client.get(f"/admin/connections/{oidc_conn.id}/export")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    payload = response.json()
    assert payload["connections"][0]["slug"] == "entra"


def test_creating_a_connection_stores_the_new_fields(admin_client, db):
    response = admin_client.post(
        "/admin/connections",
        data={
            "protocol": "oidc",
            "name": "New IdP",
            "slug": "new-idp",
            "enabled": "on",
            "issuer": "https://idp.example/",
            "client_id": "cid",
            "scopes": "openid",
            "role_claim": "groups",
            "role_source": "claims_then_scim",
            "default_role": "user",
            "expected_role": "admin",
            "expect_claim": "amr",
            "expect_operator": "contains",
            "expect_value": "mfa",
            "expect_description": "MFA must have happened",
            "stepup_claim": "amr",
            "stepup_operator": "contains",
            "stepup_value": "mfa",
            "stepup_acr_values": "mfa",
            "subject_claim": "preferred_username",
            "email_claim": "email",
            "name_claim": "name",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    created = conn.get_by_slug(db, "new-idp")
    assert created is not None
    assert created.role_source == "claims_then_scim"
    assert created.expected_role == "admin"
    assert created.expectations == [
        {
            "claim": "amr",
            "operator": "contains",
            "value": "mfa",
            "description": "MFA must have happened",
        }
    ]
    assert created.stepup_value == "mfa"


def test_an_invalid_role_source_falls_back_to_claims(admin_client, db):
    admin_client.post(
        "/admin/connections",
        data={
            "protocol": "oidc",
            "name": "Bad source",
            "slug": "bad-source",
            "issuer": "https://idp.example/",
            "role_source": "telepathy",
            "default_role": "user",
        },
        follow_redirects=False,
    )
    created = conn.get_by_slug(db, "bad-source")
    assert created.role_source == "claims"


def test_blank_expectation_rows_are_dropped(admin_client, db):
    admin_client.post(
        "/admin/connections",
        data={
            "protocol": "oidc",
            "name": "Blanks",
            "slug": "blanks",
            "issuer": "https://idp.example/",
            "default_role": "user",
            "expect_claim": ["", "amr"],
            "expect_operator": ["equals", "contains"],
            "expect_value": ["", "mfa"],
            "expect_description": ["", ""],
        },
        follow_redirects=False,
    )
    created = conn.get_by_slug(db, "blanks")
    assert len(created.expectations) == 1
    assert created.expectations[0]["claim"] == "amr"


# --- role gating ----------------------------------------------------------------


@pytest.mark.parametrize(
    "path", ["/admin/automation", "/admin/service-access", "/admin/sessions/compare"]
)
def test_new_admin_pages_are_not_reachable_without_a_session(client, path):
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
