"""The automation API: evidence export, connection portability, scoped tokens."""

from __future__ import annotations

import csv
import io
import json

import pytest

from app.auth import connections as conn
from app.models import ApiToken, IdpConnection
from app.security import generate_token, hash_token


@pytest.fixture
def api_token(db):
    """A token carrying every scope."""
    token = generate_token()
    db.add(
        ApiToken(
            name="ci",
            token_hash=hash_token(token),
            token_hint=token[:6],
            scopes=["events:read", "connections:read", "connections:write", "sessions:read"],
            enabled=True,
        )
    )
    db.commit()
    return token


@pytest.fixture
def narrow_token(db):
    """A token that can read events and nothing else."""
    token = generate_token()
    db.add(
        ApiToken(
            name="events-only",
            token_hash=hash_token(token),
            token_hint=token[:6],
            scopes=["events:read"],
            enabled=True,
        )
    )
    db.commit()
    return token


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- authentication and scoping -----------------------------------------------


def test_no_credentials_is_rejected(client):
    response = client.get("/api/admin/events")
    assert response.status_code == 401
    assert "API token" in response.json()["detail"]


def test_invalid_token_is_rejected(client):
    response = client.get("/api/admin/events", headers=auth("not-a-real-token"))
    assert response.status_code == 401


def test_a_token_without_the_scope_is_refused(client, narrow_token):
    """Scopes have to actually restrict, or they are decoration."""
    response = client.get("/api/admin/connections", headers=auth(narrow_token))
    assert response.status_code == 403
    assert "connections:read" in response.json()["detail"]


def test_a_token_with_the_scope_is_allowed(client, narrow_token):
    assert client.get("/api/admin/events", headers=auth(narrow_token)).status_code == 200


def test_a_disabled_token_stops_working(client, db, api_token):
    token_row = db.execute(__import__("sqlalchemy").select(ApiToken)).scalars().first()
    token_row.enabled = False
    db.commit()
    assert client.get("/api/admin/events", headers=auth(api_token)).status_code == 401


def test_an_admin_session_is_accepted_without_a_token(admin_client):
    """So the console's own download links work with no separate credential."""
    assert admin_client.get("/api/admin/events").status_code == 200


def test_a_non_admin_session_is_not_accepted(client, db):
    from app.models import LocalUser
    from app.security import hash_password

    db.add(
        LocalUser(
            email="plain@authlab.local",
            display_name="Plain",
            password_hash=hash_password("PlainUserPassword123"),
            role="user",
            is_active=True,
        )
    )
    db.commit()
    client.post(
        "/auth/local/login",
        data={"email": "plain@authlab.local", "password": "PlainUserPassword123"},
        follow_redirects=False,
    )
    assert client.get("/api/admin/events").status_code == 401


def test_last_used_is_recorded(client, db, api_token):
    client.get("/api/admin/events", headers=auth(api_token))
    row = db.execute(__import__("sqlalchemy").select(ApiToken)).scalars().first()
    db.refresh(row)
    assert row.last_used_at is not None


# --- events -------------------------------------------------------------------


def test_events_export_as_json(admin_client, api_token, client):
    # The admin sign-in above produced a login_success event.
    response = client.get("/api/admin/events", headers=auth(api_token))
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] >= 1
    assert any(event["kind"] == "login_success" for event in payload["events"])
    assert "generated_at" in payload


def test_events_can_be_filtered_by_kind(admin_client, api_token, client):
    response = client.get(
        "/api/admin/events?kind=login_success", headers=auth(api_token)
    )
    kinds = {event["kind"] for event in response.json()["events"]}
    assert kinds == {"login_success"}


def test_events_export_as_csv_keeps_detail(admin_client, api_token, client):
    """`detail` carries the IdP error code — dropping it would gut the export."""
    response = client.get("/api/admin/events?format=csv", headers=auth(api_token))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]

    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert rows
    assert "detail" in rows[0]
    json.loads(rows[0]["detail"])  # a valid JSON string, not a repr


# --- connections ---------------------------------------------------------------


def test_export_omits_secrets(admin_client, db, api_token, client):
    connection = IdpConnection(slug="entra", name="Entra", protocol="oidc", config={})
    conn.store_settings(
        connection,
        {
            "issuer": "https://login.microsoftonline.com/tid/v2.0",
            "client_id": "abc",
            "client_secret": "super-secret-value",
            "scopes": "openid profile email",
            "use_pkce": True,
        },
    )
    db.add(connection)
    db.commit()

    response = client.get("/api/admin/connections", headers=auth(api_token))
    assert response.status_code == 200
    body = response.text
    assert "super-secret-value" not in body

    exported = response.json()["connections"][0]
    assert exported["slug"] == "entra"
    assert "client_secret" not in exported["config"]
    assert exported["config"]["client_id"] == "abc"
    # Every secret-bearing OIDC field, not just the client secret: the DPoP
    # signing key and the ID-token decryption key are private keys too.
    assert exported["secrets_excluded"] == [
        "client_secret",
        "dpop_private_key",
        "jwe_private_key",
    ]
    assert "dpop_private_key" not in exported["config"]
    assert "jwe_private_key" not in exported["config"]


def test_export_then_import_round_trips(admin_client, db, api_token, client):
    connection = IdpConnection(
        slug="okta",
        name="Okta",
        protocol="oidc",
        role_claim="groups",
        role_source="claims_then_scim",
        expected_role="admin",
        expectations=[{"claim": "amr", "operator": "contains", "value": "mfa"}],
        role_rules=[{"operator": "equals", "value": "SEC-Admins", "role": "admin"}],
        config={},
    )
    conn.store_settings(connection, {"issuer": "https://x.okta.com/oauth2/default"})
    db.add(connection)
    db.commit()

    exported = client.get(
        "/api/admin/connections?slug=okta", headers=auth(api_token)
    ).json()

    # Change the slug so the import creates a second connection.
    exported["connections"][0]["slug"] = "okta-copy"
    exported["connections"][0]["name"] = "Okta copy"

    response = client.post(
        "/api/admin/connections", json=exported, headers=auth(api_token)
    )
    assert response.status_code == 200
    assert response.json()["results"][0]["created"] is True

    copy = conn.get_by_slug(db, "okta-copy")
    assert copy is not None
    assert copy.role_source == "claims_then_scim"
    assert copy.expected_role == "admin"
    assert copy.expectations == [{"claim": "amr", "operator": "contains", "value": "mfa"}]
    assert copy.role_rules == [{"operator": "equals", "value": "SEC-Admins", "role": "admin"}]


def test_import_updates_an_existing_slug_rather_than_duplicating(
    admin_client, db, api_token, client
):
    connection = IdpConnection(slug="dup", name="Before", protocol="oidc", config={})
    conn.store_settings(connection, {"issuer": "https://a.example/"})
    db.add(connection)
    db.commit()

    response = client.post(
        "/api/admin/connections",
        json={"slug": "dup", "protocol": "oidc", "name": "After", "config": {}},
        headers=auth(api_token),
    )
    assert response.status_code == 200
    assert response.json()["results"][0]["created"] is False

    from sqlalchemy import select

    rows = db.execute(select(IdpConnection).where(IdpConnection.slug == "dup")).scalars().all()
    assert len(rows) == 1
    db.refresh(rows[0])
    assert rows[0].name == "After"


def test_import_does_not_clear_an_existing_secret(admin_client, db, api_token, client):
    """An export carries no secret, so importing it must leave one alone."""
    connection = IdpConnection(slug="keep", name="Keep", protocol="oidc", config={})
    conn.store_settings(connection, {"issuer": "https://a.example/", "client_secret": "keepme"})
    db.add(connection)
    db.commit()

    client.post(
        "/api/admin/connections",
        json={"slug": "keep", "protocol": "oidc", "name": "Keep", "config": {"issuer": "https://a.example/"}},
        headers=auth(api_token),
    )

    refreshed = conn.get_by_slug(db, "keep")
    db.refresh(refreshed)
    assert conn.load_settings(refreshed).client_secret == "keepme"


def test_import_refuses_to_change_protocol(admin_client, db, api_token, client):
    connection = IdpConnection(slug="fixed", name="Fixed", protocol="oidc", config={})
    conn.store_settings(connection, {"issuer": "https://a.example/"})
    db.add(connection)
    db.commit()

    response = client.post(
        "/api/admin/connections",
        json={"slug": "fixed", "protocol": "saml", "name": "Fixed", "config": {}},
        headers=auth(api_token),
    )
    assert response.status_code == 400
    assert "refusing to change" in response.json()["detail"]


def test_import_rejects_an_unknown_protocol(admin_client, api_token, client):
    response = client.post(
        "/api/admin/connections",
        json={"slug": "x", "protocol": "kerberos", "config": {}},
        headers=auth(api_token),
    )
    assert response.status_code == 400
    assert "Unknown protocol" in response.json()["detail"]


def test_import_requires_a_slug(admin_client, api_token, client):
    response = client.post(
        "/api/admin/connections",
        json={"protocol": "oidc", "config": {}},
        headers=auth(api_token),
    )
    assert response.status_code == 400
    assert "slug" in response.json()["detail"]


def test_write_scope_is_required_to_import(admin_client, narrow_token, client):
    response = client.post(
        "/api/admin/connections",
        json={"slug": "x", "protocol": "oidc", "config": {}},
        headers=auth(narrow_token),
    )
    assert response.status_code == 403


def test_connection_test_reports_a_verdict_not_an_error_status(
    admin_client, db, api_token, client
):
    """A misconfigured provider is a result, not a failed request."""
    connection = IdpConnection(slug="broken", name="Broken", protocol="oidc", config={})
    conn.store_settings(connection, {"issuer": ""})
    db.add(connection)
    db.commit()

    response = client.post(
        "/api/admin/connections/broken/test", headers=auth(api_token)
    )
    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert "error" in response.json()


def test_connection_test_404s_for_an_unknown_slug(admin_client, api_token, client):
    response = client.post("/api/admin/connections/nope/test", headers=auth(api_token))
    assert response.status_code == 404


# --- sessions ------------------------------------------------------------------


def test_sessions_export(admin_client, api_token, client):
    response = client.get("/api/admin/sessions", headers=auth(api_token))
    assert response.status_code == 200
    assert response.json()["count"] >= 1
    assert "claims" in response.json()["sessions"][0]
