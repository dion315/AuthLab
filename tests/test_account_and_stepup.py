"""Self-service password change, step-up, SLS wiring, and the redirect guard."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models import IdpConnection, LocalUser
from app.redirects import safe_path
from app.routes.account import evaluate_stepup
from app.routes.admin import diff_claims
from app.security import verify_password
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD

NEW_PASSWORD = "ANewLongEnoughPassword1"


# --- open redirect guard -------------------------------------------------------


@pytest.mark.parametrize(
    "candidate",
    [
        "https://evil.example/steal",
        "//evil.example",
        "/\\evil.example",
        "javascript:alert(1)",
        "http://localhost:8000/dashboard",
        "dashboard",
        "",
        None,
        "/path\nLocation: https://evil.example",
    ],
)
def test_safe_path_rejects_anything_not_local(candidate):
    """A sign-in endpoint is the worst place to have an open redirect."""
    assert safe_path(candidate) == "/dashboard"


@pytest.mark.parametrize(
    "candidate", ["/dashboard", "/step-up", "/admin/connections?x=1", "/a/b/c"]
)
def test_safe_path_accepts_local_paths(candidate):
    assert safe_path(candidate) == candidate


def test_safe_path_honours_a_custom_default():
    assert safe_path("https://evil.example", default="/login") == "/login"


# --- password change ----------------------------------------------------------


def test_password_page_renders_for_a_local_account(admin_client):
    response = admin_client.get("/account/password")
    assert response.status_code == 200
    assert "Change your password" in response.text


def test_password_change_requires_the_current_password(admin_client, db):
    response = admin_client.post(
        "/account/password",
        data={
            "current_password": "wrong-password",
            "new_password": NEW_PASSWORD,
            "confirm_password": NEW_PASSWORD,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "was+not+accepted" in response.headers["location"]

    user = db.execute(select(LocalUser)).scalars().first()
    db.refresh(user)
    assert verify_password(ADMIN_PASSWORD, user.password_hash)


def test_password_change_requires_a_matching_confirmation(admin_client):
    response = admin_client.post(
        "/account/password",
        data={
            "current_password": ADMIN_PASSWORD,
            "new_password": NEW_PASSWORD,
            "confirm_password": "something-else-entirely",
        },
        follow_redirects=False,
    )
    assert "did+not+match" in response.headers["location"]


def test_password_change_enforces_a_minimum_length(admin_client):
    response = admin_client.post(
        "/account/password",
        data={
            "current_password": ADMIN_PASSWORD,
            "new_password": "short",
            "confirm_password": "short",
        },
        follow_redirects=False,
    )
    assert "at+least+12" in response.headers["location"]


def test_password_change_rejects_reusing_the_current_password(admin_client):
    response = admin_client.post(
        "/account/password",
        data={
            "current_password": ADMIN_PASSWORD,
            "new_password": ADMIN_PASSWORD,
            "confirm_password": ADMIN_PASSWORD,
        },
        follow_redirects=False,
    )
    assert "must+be+different" in response.headers["location"]


def test_password_change_succeeds_and_clears_the_flag(admin_client, db):
    user = db.execute(select(LocalUser)).scalars().first()
    user.must_change_password = True
    db.commit()

    response = admin_client.post(
        "/account/password",
        data={
            "current_password": ADMIN_PASSWORD,
            "new_password": NEW_PASSWORD,
            "confirm_password": NEW_PASSWORD,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith("/dashboard")

    db.refresh(user)
    assert verify_password(NEW_PASSWORD, user.password_hash)
    assert user.must_change_password is False


# --- must_change_password enforcement -----------------------------------------


def test_a_pending_password_change_blocks_every_other_page(admin_client, db):
    """The flag used to render a badge and enforce nothing."""
    user = db.execute(select(LocalUser)).scalars().first()
    user.must_change_password = True
    db.commit()

    response = admin_client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/account/password"

    response = admin_client.get("/admin", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/account/password"


def test_the_password_page_itself_is_reachable_while_blocked(admin_client, db):
    """Otherwise the redirect loops and the account is unusable."""
    user = db.execute(select(LocalUser)).scalars().first()
    user.must_change_password = True
    db.commit()

    assert admin_client.get("/account/password").status_code == 200


def test_sign_out_stays_reachable_while_blocked(admin_client, db):
    user = db.execute(select(LocalUser)).scalars().first()
    user.must_change_password = True
    db.commit()

    response = admin_client.post("/logout", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_a_bootstrapped_admin_starts_without_the_flag_when_password_was_configured(
    admin_client, db
):
    """conftest sets BOOTSTRAP_ADMIN_PASSWORD, so nothing was generated.

    The flag is only raised when the app invented the password itself — an
    operator who chose one has already made that decision.
    """
    user = db.execute(select(LocalUser).where(LocalUser.email == ADMIN_EMAIL)).scalars().first()
    assert user is not None
    assert user.must_change_password is False


# --- step-up ------------------------------------------------------------------


def make_connection(**kwargs) -> IdpConnection:
    defaults = dict(
        slug="s",
        name="S",
        protocol="oidc",
        stepup_claim="amr",
        stepup_operator="contains",
        stepup_value="",
        config={},
    )
    defaults.update(kwargs)
    return IdpConnection(**defaults)


def test_stepup_is_not_configured_without_a_required_value():
    result = evaluate_stepup(make_connection(), {"amr": ["mfa"]})
    assert result["configured"] is False


def test_stepup_satisfied_reports_what_matched():
    result = evaluate_stepup(
        make_connection(stepup_value="mfa"), {"amr": ["pwd", "mfa"]}
    )
    assert result["satisfied"] is True
    assert result["matched_on"] == "mfa"


def test_stepup_unsatisfied_reports_what_was_there():
    result = evaluate_stepup(make_connection(stepup_value="mfa"), {"amr": ["pwd"]})
    assert result["satisfied"] is False
    assert result["found_values"] == ["pwd"]


def test_stepup_handles_a_missing_claim():
    result = evaluate_stepup(make_connection(stepup_value="mfa"), {})
    assert result["satisfied"] is False
    assert result["found_values"] == []


def test_step_up_page_explains_the_local_account(admin_client):
    response = admin_client.get("/step-up")
    assert response.status_code == 200
    assert "local account" in response.text


def test_step_up_page_renders_a_challenge(admin_client, db):
    """A federated session that does not satisfy the condition gets a link."""
    connection = make_connection(
        slug="entra",
        name="Entra",
        stepup_value="mfa",
        stepup_acr_values="mfa",
    )
    db.add(connection)
    db.commit()

    session_row = _federated_session(db, "entra", {"amr": ["pwd"]})
    _adopt(admin_client, session_row)

    response = admin_client.get("/step-up")
    assert response.status_code == 200
    assert "Additional authentication required" in response.text
    assert "acr_values=mfa" in response.text
    assert "prompt=login" in response.text
    assert "return_to=%2Fstep-up" in response.text


def test_step_up_page_permits_a_satisfied_session(admin_client, db):
    connection = make_connection(slug="entra2", name="Entra2", stepup_value="mfa")
    db.add(connection)
    db.commit()

    session_row = _federated_session(db, "entra2", {"amr": ["pwd", "mfa"]})
    _adopt(admin_client, session_row)

    response = admin_client.get("/step-up")
    assert "Action permitted" in response.text


# --- SAML SLS wiring ----------------------------------------------------------


def test_sls_endpoint_exists_and_validates_input(admin_client, db):
    """The SP metadata has always advertised this URL; nothing served it."""
    db.add(IdpConnection(slug="samlidp", name="SAML", protocol="saml", config={}))
    db.commit()

    response = admin_client.get("/auth/saml/samlidp/sls", follow_redirects=False)
    assert response.status_code == 400
    assert "SAMLRequest or SAMLResponse" in response.text


def test_sls_endpoint_404s_for_an_unknown_connection(admin_client):
    response = admin_client.get("/auth/saml/nope/sls", follow_redirects=False)
    assert response.status_code == 404


def test_sls_endpoint_accepts_post(admin_client, db):
    """Some providers use the POST binding for logout messages."""
    db.add(IdpConnection(slug="samlpost", name="SAML", protocol="saml", config={}))
    db.commit()

    response = admin_client.post(
        "/auth/saml/samlpost/sls", data={}, follow_redirects=False
    )
    assert response.status_code == 400


def test_sp_settings_point_the_sls_at_a_real_route(db):
    """The advertised SLS URL has to be one the app actually serves.

    It always was advertised; nothing listened on it, so a provider's
    LogoutResponse landed on a 404 and SP-initiated single logout never
    completed.
    """
    from app.auth import connections as conn
    from app.auth import saml
    from app.main import app

    connection = IdpConnection(slug="samlmeta", name="SAML", protocol="saml", config={})
    conn.store_settings(
        connection,
        {
            "idp_entity_id": "https://idp.example/entity",
            "idp_sso_url": "https://idp.example/sso",
        },
    )
    db.add(connection)
    db.commit()

    advertised = saml.build_saml_settings(connection)["sp"]["singleLogoutService"]["url"]
    assert advertised == conn.sls_url("samlmeta")
    assert advertised.endswith("/auth/saml/samlmeta/sls")

    assert "/auth/saml/{slug}/sls" in _all_paths(app)


# --- session diff --------------------------------------------------------------


def test_diff_claims_classifies_every_state():
    rows = {
        row["claim"]: row
        for row in diff_claims(
            {"same": 1, "changed": "a", "only_left": True},
            {"same": 1, "changed": "b", "only_right": True},
        )
    }
    assert rows["same"]["state"] == "same"
    assert rows["changed"]["state"] == "changed"
    assert rows["only_left"]["state"] == "removed"
    assert rows["only_right"]["state"] == "added"


def test_diff_claims_is_sorted_and_complete():
    rows = diff_claims({"b": 1}, {"a": 2})
    assert [row["claim"] for row in rows] == ["a", "b"]


def test_compare_page_renders(admin_client, db):
    left = _federated_session(db, "x", {"amr": ["pwd"]})
    right = _federated_session(db, "x", {"amr": ["pwd", "mfa"]})

    response = admin_client.get(f"/admin/sessions/compare?a={left.id}&b={right.id}")
    assert response.status_code == 200
    assert "difference" in response.text
    assert "amr" in response.text


def test_compare_page_can_hide_identical_claims(admin_client, db):
    left = _federated_session(db, "x", {"amr": ["pwd"], "tid": "same"})
    right = _federated_session(db, "x", {"amr": ["mfa"], "tid": "same"})

    response = admin_client.get(
        f"/admin/sessions/compare?a={left.id}&b={right.id}&changed_only=1"
    )
    assert response.status_code == 200
    assert "1 difference" in response.text


# --- helpers -------------------------------------------------------------------


def _all_paths(app) -> set[str]:
    """Every route path, walking nested routers."""
    found: set[str] = set()

    def walk(routes):
        for route in routes:
            path = getattr(route, "path", None)
            if path:
                found.add(path)
            nested = getattr(route, "routes", None)
            if nested:
                walk(nested)
            original = getattr(route, "original_router", None)
            if original is not None:
                walk(original.routes)

    walk(app.routes)
    return found


def _federated_session(db, source: str, claims: dict):
    from datetime import UTC, datetime, timedelta

    from app.models import UserSession

    now = datetime.now(UTC)
    row = UserSession(
        subject="pairwise-sub",
        email="alice@contoso.com",
        display_name="Alice",
        role="admin",
        source=source,
        protocol="oidc",
        raw_claims=claims,
        created_at=now,
        expires_at=now + timedelta(hours=1),
    )
    db.add(row)
    db.commit()
    return row


def _adopt(client, session_row):
    """Point the test client's cookie at a specific session record."""
    from app.security import _serializer

    client.cookies.set("authlab_session", _serializer().dumps(session_row.id))
