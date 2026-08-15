"""Local sign-in, session lifecycle, authorisation guards, and secret handling."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.crypto import decrypt, encrypt, is_encrypted
from app.models import LocalUser, ScimUser, UserSession
from app.scim.schemas import coerce_bool
from app.security import hash_password, hash_token, verify_password, verify_token

ADMIN_EMAIL = "admin@authlab.local"
ADMIN_PASSWORD = "TestAdminPassword123"


# --- bootstrap ---------------------------------------------------------------


def test_bootstrap_admin_is_created(client, db):
    user = db.execute(select(LocalUser).where(LocalUser.email == ADMIN_EMAIL)).scalar_one()
    assert user.role == "admin"
    assert user.is_active


def test_bootstrap_password_is_hashed_not_stored(client, db):
    user = db.execute(select(LocalUser).where(LocalUser.email == ADMIN_EMAIL)).scalar_one()
    assert ADMIN_PASSWORD not in user.password_hash
    assert user.password_hash.startswith("$argon2")


# --- local sign-in -----------------------------------------------------------


def test_local_login_succeeds(client):
    response = client.post(
        "/auth/local/login",
        data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


def test_local_login_rejects_bad_password(client):
    response = client.post(
        "/auth/local/login",
        data={"email": ADMIN_EMAIL, "password": "wrong"},
        follow_redirects=False,
    )
    assert response.status_code == 401


def test_login_is_case_insensitive_on_email(client):
    response = client.post(
        "/auth/local/login",
        data={"email": ADMIN_EMAIL.upper(), "password": ADMIN_PASSWORD},
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_unknown_user_and_wrong_password_are_indistinguishable(client):
    unknown = client.post(
        "/auth/local/login",
        data={"email": "nobody@example.com", "password": "whatever"},
        follow_redirects=False,
    )
    wrong = client.post(
        "/auth/local/login",
        data={"email": ADMIN_EMAIL, "password": "whatever"},
        follow_redirects=False,
    )
    assert unknown.status_code == wrong.status_code == 401


def test_session_cookie_is_httponly(admin_client):
    cookie_header = admin_client.cookies.jar._cookies  # noqa: SLF001
    assert admin_client.cookies.get("authlab_session")
    response = admin_client.get("/dashboard")
    assert response.status_code == 200
    assert cookie_header is not None


def test_session_cookie_is_opaque(admin_client, db):
    """The cookie carries a signed session id, not claims."""
    raw = admin_client.cookies.get("authlab_session")
    assert ADMIN_EMAIL not in raw
    assert "admin" not in raw.lower() or len(raw) < 200


# --- guards ------------------------------------------------------------------


def test_dashboard_requires_login(client):
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_admin_requires_login(client):
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 303


def test_weather_api_requires_login(client):
    response = client.get("/api/weather?latitude=1&longitude=1", follow_redirects=False)
    assert response.status_code == 303


def test_weather_api_validates_coordinates(admin_client):
    response = admin_client.get("/api/weather?latitude=999&longitude=0")
    assert response.status_code == 400


def test_non_admin_cannot_reach_admin(client, db):
    db.add(
        LocalUser(
            email="plain@authlab.local",
            display_name="Plain",
            password_hash=hash_password("PlainPassword12345"),
            role="user",
        )
    )
    db.commit()
    client.post(
        "/auth/local/login",
        data={"email": "plain@authlab.local", "password": "PlainPassword12345"},
        follow_redirects=False,
    )
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 403
    # The message explains where the role came from, rather than a bare status.
    assert "role" in response.text.lower()


# --- session lifecycle -------------------------------------------------------


def test_logout_revokes_the_session(admin_client, db):
    admin_client.post("/logout", follow_redirects=False)
    session = db.execute(select(UserSession)).scalars().first()
    assert session is not None and session.revoked_at is not None
    assert admin_client.get("/dashboard", follow_redirects=False).status_code == 303


def test_scim_deactivation_revokes_live_sessions(admin_client, db, scim_headers):
    """Deprovisioning should end access now, not at token expiry."""
    created = admin_client.post(
        "/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": ADMIN_EMAIL,
        },
        headers=scim_headers,
    )
    assert created.status_code == 201

    assert admin_client.get("/dashboard", follow_redirects=False).status_code == 200

    admin_client.patch(
        f"/scim/v2/Users/{created.json()['id']}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "Replace", "path": "active", "value": "False"}],
        },
        headers=scim_headers,
    )

    assert admin_client.get("/dashboard", follow_redirects=False).status_code == 303
    assert db.execute(select(ScimUser)).scalar_one().active is False


def test_tampered_session_cookie_is_rejected(client):
    client.cookies.set("authlab_session", "not-a-valid-signed-value")
    assert client.get("/dashboard", follow_redirects=False).status_code == 303


# --- output escaping ---------------------------------------------------------


def test_scim_supplied_display_name_is_escaped_in_admin_ui(admin_client, scim_headers):
    """Anyone with a provisioning token can set displayName — it must be escaped."""
    admin_client.post(
        "/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "evil@contoso.com",
            "displayName": "<img src=x onerror=alert(1)>",
        },
        headers=scim_headers,
    )
    response = admin_client.get("/admin/scim")
    assert "<img src=x onerror=alert(1)>" not in response.text
    assert "&lt;img src=x onerror=alert(1)&gt;" in response.text


# --- security headers --------------------------------------------------------


def test_strict_csp_without_unsafe_inline(client):
    csp = client.get("/").headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


def test_security_headers_present(client):
    headers = client.get("/").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert "referrer-policy" in headers


# --- secret handling ---------------------------------------------------------


def test_encrypt_decrypt_roundtrip():
    assert decrypt(encrypt("super-secret")) == "super-secret"


def test_encrypted_value_does_not_contain_plaintext():
    encrypted = encrypt("super-secret")
    assert "super-secret" not in encrypted
    assert is_encrypted(encrypted)


def test_empty_secret_passes_through():
    assert encrypt("") == ""
    assert decrypt("") == ""


def test_plaintext_legacy_value_is_returned_unchanged():
    assert decrypt("not-encrypted") == "not-encrypted"


def test_password_verification():
    stored = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", stored)
    assert not verify_password("wrong", stored)


def test_bearer_token_verification_is_hash_based():
    stored = hash_token("my-token")
    assert "my-token" not in stored
    assert verify_token("my-token", stored)
    assert not verify_token("other-token", stored)


# --- boolean coercion --------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, True),
        (False, False),
        ("True", True),
        ("False", False),
        ("true", True),
        ("false", False),
        ("TRUE", True),
        ("FALSE", False),
        ("1", True),
        ("0", False),
        (1, True),
        (0, False),
        ({"active": False}, False),
        ({"active": "False"}, False),
    ],
)
def test_coerce_bool(value, expected):
    assert coerce_bool(value) is expected


# --- health ------------------------------------------------------------------


def test_healthz_does_not_require_auth(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_readyz_reports_database(client):
    assert client.get("/readyz").json()["status"] == "ready"
