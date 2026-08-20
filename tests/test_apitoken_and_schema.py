"""Access token validation (the resource-server side) and schema reconciliation."""

from __future__ import annotations

import time

import pytest
from authlib.jose import JsonWebKey, jwt
from sqlalchemy import inspect, select, text

from app.auth import apitoken, oidc
from app.auth import connections as conn
from app.db import engine
from app.models import Base, IdpConnection
from app.schema_sync import sync_schema

ISSUER = "https://idp.example/tenant"
CLIENT_ID = "api://authlab"


@pytest.fixture
def signing_key():
    """An RSA keypair standing in for the provider's signing key."""
    key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
    return key


@pytest.fixture
def fake_issuer(signing_key, monkeypatch):
    """Point discovery and JWKS at an in-memory provider.

    Faking at this seam rather than over HTTP keeps the test about token
    validation rather than about httpx.
    """
    public = signing_key.as_dict(is_private=False)
    public["kid"] = signing_key.thumbprint()
    key_set = JsonWebKey.import_key_set({"keys": [public]})

    async def fake_discovery(settings, *, force=False):
        return {
            "issuer": ISSUER,
            "jwks_uri": f"{ISSUER}/keys",
            "token_endpoint": f"{ISSUER}/token",
        }

    async def fake_jwks(discovery):
        return key_set

    monkeypatch.setattr(apitoken, "fetch_discovery", fake_discovery)
    monkeypatch.setattr(apitoken, "fetch_jwks", fake_jwks)
    return signing_key


@pytest.fixture
def connection(db):
    row = IdpConnection(slug="api", name="API", protocol="oidc", config={})
    conn.store_settings(row, {"issuer": ISSUER, "client_id": CLIENT_ID})
    db.add(row)
    db.commit()
    return row


def make_token(key, **overrides) -> str:
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-object-id",
        "exp": now + 3600,
        "iat": now,
        "nbf": now,
        "scp": "Files.Read",
        "appid": "client-app-id",
    }
    payload.update(overrides)
    header = {"alg": "RS256", "kid": key.thumbprint()}
    return jwt.encode(header, payload, key).decode("ascii")


def check(result, name):
    return next(item for item in result["checks"] if item["name"] == name)


# --- token validation ----------------------------------------------------------


@pytest.mark.asyncio
async def test_a_good_token_is_accepted(connection, fake_issuer):
    result = await apitoken.inspect_access_token(connection, make_token(fake_issuer))
    assert result["valid"] is True
    assert check(result, "signature")["passed"] is True
    assert check(result, "issuer")["passed"] is True
    assert check(result, "audience")["passed"] is True
    assert check(result, "expiry")["passed"] is True


@pytest.mark.asyncio
async def test_authorisation_claims_are_pulled_out(connection, fake_issuer):
    result = await apitoken.inspect_access_token(connection, make_token(fake_issuer))
    assert result["authorisation"]["scp"] == "Files.Read"
    assert result["authorisation"]["appid"] == "client-app-id"


@pytest.mark.asyncio
async def test_a_token_signed_by_the_wrong_key_is_rejected(connection, fake_issuer):
    other = JsonWebKey.generate_key("RSA", 2048, is_private=True)
    token = make_token(other)
    result = await apitoken.inspect_access_token(connection, token)
    assert result["valid"] is False
    assert check(result, "signature")["passed"] is False


@pytest.mark.asyncio
async def test_an_expired_token_is_rejected_and_says_how_long_ago(connection, fake_issuer):
    now = int(time.time())
    token = make_token(fake_issuer, exp=now - 120, iat=now - 3600, nbf=now - 3600)
    result = await apitoken.inspect_access_token(connection, token)
    assert result["valid"] is False
    expiry = check(result, "expiry")
    assert expiry["passed"] is False
    assert "ago" in expiry["detail"]


@pytest.mark.asyncio
async def test_the_wrong_issuer_is_rejected(connection, fake_issuer):
    token = make_token(fake_issuer, iss="https://somewhere.else/")
    result = await apitoken.inspect_access_token(connection, token)
    assert result["valid"] is False
    assert check(result, "issuer")["passed"] is False


@pytest.mark.asyncio
async def test_a_token_for_another_audience_is_rejected(connection, fake_issuer):
    """The classic mistake: a token that is valid, but not for you."""
    token = make_token(fake_issuer, aud="api://somebody-else")
    result = await apitoken.inspect_access_token(connection, token)
    assert result["valid"] is False
    audience = check(result, "audience")
    assert audience["passed"] is False
    assert "api://somebody-else" in audience["detail"]


@pytest.mark.asyncio
async def test_an_explicit_expected_audience_overrides_the_client_id(connection, fake_issuer):
    token = make_token(fake_issuer, aud="api://my-other-api")
    result = await apitoken.inspect_access_token(
        connection, token, expected_audience="api://my-other-api"
    )
    assert result["valid"] is True


@pytest.mark.asyncio
async def test_a_list_audience_is_handled(connection, fake_issuer):
    token = make_token(fake_issuer, aud=["api://other", CLIENT_ID])
    result = await apitoken.inspect_access_token(connection, token)
    assert check(result, "audience")["passed"] is True


@pytest.mark.asyncio
async def test_an_opaque_token_says_so_rather_than_failing_obscurely(connection, fake_issuer):
    result = await apitoken.inspect_access_token(connection, "not-a-jwt-at-all")
    assert result["valid"] is False
    assert "opaque" in result["error"]


@pytest.mark.asyncio
async def test_an_empty_token_is_reported(connection, fake_issuer):
    result = await apitoken.inspect_access_token(connection, "")
    assert result["valid"] is False
    assert "No token" in result["error"]


@pytest.mark.asyncio
async def test_the_header_is_shown_even_when_validation_fails(connection, fake_issuer):
    other = JsonWebKey.generate_key("RSA", 2048, is_private=True)
    result = await apitoken.inspect_access_token(connection, make_token(other))
    assert result["header"]["alg"] == "RS256"


def test_only_asymmetric_algorithms_are_accepted():
    """Allowing an HMAC alongside RSA is the classic JWT confusion attack."""
    assert "HS256" not in apitoken.ALLOWED_ALGORITHMS
    assert "none" not in apitoken.ALLOWED_ALGORITHMS
    assert all(alg[:2] in ("RS", "ES", "PS") for alg in apitoken.ALLOWED_ALGORITHMS)


@pytest.mark.asyncio
async def test_client_credentials_refuses_a_public_client(db, fake_issuer):
    row = IdpConnection(slug="public", name="Public", protocol="oidc", config={})
    conn.store_settings(row, {"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": ""})
    db.add(row)
    db.commit()

    with pytest.raises(oidc.OidcError) as excinfo:
        await apitoken.client_credentials_token(row)
    assert "public client" in str(excinfo.value.message)


# --- schema reconciliation -----------------------------------------------------


def test_sync_schema_is_a_no_op_when_everything_matches():
    assert sync_schema(engine) == []


def test_sync_schema_adds_a_missing_column_and_backfills_it(db):
    """An upgrade that adds a column must not orphan an existing database."""
    db.add(IdpConnection(slug="existing", name="Existing", protocol="oidc", config={}))
    db.commit()

    with engine.begin() as connection:
        connection.execute(text('ALTER TABLE idp_connections DROP COLUMN role_source'))

    assert "role_source" not in {
        col["name"] for col in inspect(engine).get_columns("idp_connections")
    }

    added = sync_schema(engine)
    assert "idp_connections.role_source" in added

    with engine.begin() as connection:
        value = connection.execute(
            text("SELECT role_source FROM idp_connections WHERE slug = 'existing'")
        ).scalar_one()
    # Backfilled with the model's default, not left NULL.
    assert value == "claims"


def test_sync_schema_backfills_a_json_column_as_json(db):
    """A JSON column must come back as [] and not as the string '[]' or None."""
    db.add(IdpConnection(slug="jsoncol", name="J", protocol="oidc", config={}))
    db.commit()

    with engine.begin() as connection:
        connection.execute(text('ALTER TABLE idp_connections DROP COLUMN expectations'))

    assert "idp_connections.expectations" in sync_schema(engine)

    db.expire_all()
    row = db.execute(
        select(IdpConnection).where(IdpConnection.slug == "jsoncol")
    ).scalar_one()
    assert row.expectations == []


def test_sync_schema_leaves_existing_data_alone(db):
    db.add(IdpConnection(slug="keepdata", name="Keep", protocol="oidc", config={}))
    db.commit()

    with engine.begin() as connection:
        connection.execute(text('ALTER TABLE idp_connections DROP COLUMN stepup_value'))
    sync_schema(engine)

    db.expire_all()
    row = db.execute(
        select(IdpConnection).where(IdpConnection.slug == "keepdata")
    ).scalar_one()
    assert row.name == "Keep"
    assert row.stepup_value == ""


def test_sync_schema_creates_nothing_for_a_missing_table():
    """Whole tables are create_all's job; this must not duplicate it."""
    Base.metadata.create_all(bind=engine)
    assert sync_schema(engine) == []
