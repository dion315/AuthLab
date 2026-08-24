"""DPoP, encrypted ID tokens, refresh tokens, and encrypted SAML assertions.

Each of these can be configured on both sides and still silently not happen —
a provider accepts the setting and issues an ordinary bearer token, or sends a
plaintext ID token, or never issues a refresh token at all. So the tests care
as much about *reporting the absence* as about the happy path: "you asked for
this and did not get it" is the finding, and swallowing it would defeat the
feature.
"""

from __future__ import annotations

import time

import pytest
from authlib.jose import JsonWebEncryption, JsonWebKey, jwt

from app.auth import connections as conn
from app.auth import dpop, oidc, tokencrypto
from app.auth.schemas import SECRET_FIELDS, OidcSettings
from app.models import IdpConnection


def make_oidc(db, **config) -> IdpConnection:
    connection = IdpConnection(
        slug=config.pop("slug", "idp"),
        name="IdP",
        protocol="oidc",
        enabled=True,
        config={},
    )
    base = {"issuer": "https://idp.example/", "client_id": "cid"}
    base.update(config)
    conn.store_settings(connection, base)
    db.add(connection)
    db.commit()
    return connection


# --- DPoP -----------------------------------------------------------------------


def test_a_proof_carries_the_public_key_in_its_header():
    """That is how the server learns which key to bind the token to."""
    key = dpop.generate_key()
    proof = dpop.create_proof(key, method="POST", url="https://idp.example/token")
    described = dpop.describe_proof(proof)

    assert described["header"]["typ"] == "dpop+jwt"
    assert described["header"]["alg"] == "ES256"
    assert described["header"]["jwk"]["kty"] == "EC"
    # The private half must never travel.
    assert "d" not in described["header"]["jwk"]


def test_a_proof_binds_the_method_and_url():
    key = dpop.generate_key()
    proof = dpop.create_proof(key, method="post", url="https://idp.example/token")
    payload = dpop.describe_proof(proof)["payload"]

    assert payload["htm"] == "POST"
    assert payload["htu"] == "https://idp.example/token"
    assert payload["jti"]
    assert abs(payload["iat"] - int(time.time())) < 5


def test_htu_drops_the_query_string():
    """RFC 9449 requires it, and leaving it on is a common silent rejection."""
    key = dpop.generate_key()
    proof = dpop.create_proof(key, method="GET", url="https://idp.example/token?x=1#frag")
    assert dpop.describe_proof(proof)["payload"]["htu"] == "https://idp.example/token"


def test_a_nonce_is_included_when_the_server_demands_one():
    key = dpop.generate_key()
    proof = dpop.create_proof(key, method="POST", url="https://idp.example/token", nonce="abc123")
    assert dpop.describe_proof(proof)["payload"]["nonce"] == "abc123"


def test_presenting_a_token_adds_its_hash():
    """`ath` stops a proof captured from one call being replayed against another."""
    key = dpop.generate_key()
    proof = dpop.create_proof(
        key, method="GET", url="https://api.example/x", access_token="a-token"
    )
    payload = dpop.describe_proof(proof)["payload"]
    assert payload["ath"]
    assert "a-token" not in proof


def test_two_keys_have_different_thumbprints():
    assert dpop.thumbprint(dpop.generate_key()) != dpop.thumbprint(dpop.generate_key())


def test_the_proof_verifies_against_the_embedded_key():
    """A proof the server cannot verify is worthless; check ours actually does."""
    key = dpop.generate_key()
    proof = dpop.create_proof(key, method="POST", url="https://idp.example/token")
    embedded = dpop.describe_proof(proof)["header"]["jwk"]

    claims = jwt.decode(proof, JsonWebKey.import_key(embedded))
    assert claims["htm"] == "POST"


def test_binding_matches_when_the_provider_used_our_key():
    key = dpop.generate_key()
    result = dpop.check_binding({"cnf": {"jkt": dpop.thumbprint(key)}}, key)
    assert result["bound"] is True


def test_binding_reports_a_token_that_was_never_bound():
    """The common real outcome: DPoP not enabled for the client at the provider."""
    key = dpop.generate_key()
    result = dpop.check_binding({"sub": "x"}, key)
    assert result["bound"] is False
    assert result["actual"] == ""
    assert "ignored the proof" in result["detail"]


def test_binding_reports_a_token_bound_to_someone_else():
    key = dpop.generate_key()
    other = dpop.generate_key()
    result = dpop.check_binding({"cnf": {"jkt": dpop.thumbprint(other)}}, key)
    assert result["bound"] is False
    assert result["actual"] == dpop.thumbprint(other)
    assert "different key" in result["detail"]


def test_a_missing_key_is_a_readable_error():
    with pytest.raises(dpop.DpopError, match="No DPoP key"):
        dpop.thumbprint("")


def test_enabling_dpop_generates_and_keeps_a_key(db):
    connection = make_oidc(db, use_dpop=True)
    first = conn.load_settings(connection).dpop_private_key
    assert first

    # Editing something else must not roll the key — a changing thumbprint
    # would be indistinguishable from the provider misbehaving.
    conn.store_settings(connection, {"issuer": "https://idp.example/", "client_id": "cid2",
                                     "use_dpop": True})
    assert conn.load_settings(connection).dpop_private_key == first


def test_the_dpop_key_is_encrypted_at_rest(db):
    connection = make_oidc(db, use_dpop=True)
    assert "dpop_private_key" in SECRET_FIELDS["oidc"]
    assert connection.config["dpop_private_key"].startswith("enc:v1:")


def test_the_dpop_key_is_never_rendered_back(db):
    connection = make_oidc(db, use_dpop=True)
    assert conn.redacted_config(connection)["dpop_private_key"] == "********"


# --- encrypted ID tokens ---------------------------------------------------------


def encrypted_id_token(serialised_key: str, inner: str) -> str:
    public = JsonWebKey.import_key(tokencrypto.public_jwks(serialised_key)["keys"][0])
    return JsonWebEncryption().serialize_compact(
        {"alg": "RSA-OAEP", "enc": "A256GCM"}, inner.encode("utf-8"), public
    ).decode("ascii")


def test_a_jwe_is_recognised_by_shape():
    assert tokencrypto.looks_encrypted("a.b.c.d.e") is True
    assert tokencrypto.looks_encrypted("a.b.c") is False


def test_an_encrypted_token_round_trips():
    key = tokencrypto.generate_key()
    token = encrypted_id_token(key, "inner.jws.value")
    inner, report = tokencrypto.decrypt_id_token(token, key)

    assert inner == "inner.jws.value"
    assert report["encrypted"] is True
    assert report["alg"] == "RSA-OAEP"
    assert report["enc"] == "A256GCM"


def test_the_wrong_key_produces_a_readable_error():
    token = encrypted_id_token(tokencrypto.generate_key(), "x")
    with pytest.raises(tokencrypto.TokenCryptoError, match="different key"):
        tokencrypto.decrypt_id_token(token, tokencrypto.generate_key())


def test_published_jwks_carries_only_the_public_half():
    key = tokencrypto.generate_key()
    published = tokencrypto.public_jwks(key)
    entry = published["keys"][0]

    assert entry["kty"] == "RSA"
    assert "d" not in entry and "p" not in entry and "q" not in entry
    # Providers will not select a key without these and fall back to plaintext.
    assert entry["use"] == "enc"
    assert entry["alg"] == "RSA-OAEP"
    assert entry["kid"]


def test_a_plain_token_passes_through_and_says_so():
    """A provider ignoring the request must be visible, not fatal."""
    settings = OidcSettings(accept_encrypted_id_token=True, jwe_private_key=tokencrypto.generate_key())
    inner, report = tokencrypto.unwrap("a.b.c", settings)

    assert inner == "a.b.c"
    assert report["encrypted"] is False
    assert report["expected_encrypted"] is True


def test_an_encrypted_token_without_the_feature_enabled_explains_itself():
    key = tokencrypto.generate_key()
    token = encrypted_id_token(key, "x")
    with pytest.raises(tokencrypto.TokenCryptoError, match="not enabled"):
        tokencrypto.unwrap(token, OidcSettings())


def test_enabling_encryption_generates_and_keeps_a_key(db):
    connection = make_oidc(db, accept_encrypted_id_token=True)
    first = conn.load_settings(connection).jwe_private_key
    assert first
    conn.store_settings(
        connection,
        {"issuer": "https://idp.example/", "client_id": "cid", "accept_encrypted_id_token": True},
    )
    assert conn.load_settings(connection).jwe_private_key == first


def test_the_jwks_endpoint_publishes_the_key(admin_client, db):
    make_oidc(db, slug="enc", accept_encrypted_id_token=True)
    response = admin_client.get("/auth/oidc/enc/jwks.json")

    assert response.status_code == 200
    entry = response.json()["keys"][0]
    assert entry["use"] == "enc"
    assert "d" not in entry


def test_the_jwks_endpoint_is_empty_when_encryption_is_off(admin_client, db):
    make_oidc(db, slug="plain")
    assert admin_client.get("/auth/oidc/plain/jwks.json").json() == {"keys": []}


def test_the_jwks_endpoint_never_publishes_the_dpop_key(admin_client, db):
    """DPoP keys are proved by use, not published."""
    connection = make_oidc(db, slug="both", use_dpop=True, accept_encrypted_id_token=True)
    keys = admin_client.get("/auth/oidc/both/jwks.json").json()["keys"]

    # Assert on the key material rather than on substrings of the response:
    # RSA moduli are base64url and will occasionally contain any short string
    # you care to search for.
    assert len(keys) == 1
    assert keys[0]["kty"] == "RSA"
    assert all(key.get("kty") != "EC" for key in keys)
    assert all("crv" not in key for key in keys)

    dpop_thumbprint = dpop.thumbprint(conn.load_settings(connection).dpop_private_key)
    assert all(key.get("kid") != dpop_thumbprint for key in keys)


def test_an_unknown_connection_returns_an_empty_key_set(admin_client):
    assert admin_client.get("/auth/oidc/nope/jwks.json").status_code == 404


# --- refresh tokens ---------------------------------------------------------------


def test_offline_access_is_added_only_when_requested():
    assert "offline_access" not in oidc.requested_scopes(OidcSettings())
    assert "offline_access" in oidc.requested_scopes(
        OidcSettings(request_refresh_token=True)
    )


def test_offline_access_is_not_duplicated():
    scopes = oidc.requested_scopes(
        OidcSettings(scopes="openid offline_access", request_refresh_token=True)
    )
    assert scopes.split().count("offline_access") == 1


def test_the_configured_scopes_are_preserved():
    scopes = oidc.requested_scopes(
        OidcSettings(scopes="openid profile groups", request_refresh_token=True)
    )
    assert scopes.split() == ["openid", "profile", "groups", "offline_access"]


def test_a_refresh_token_is_encrypted_at_rest(db, client):
    from datetime import UTC, datetime, timedelta

    from app.models import UserSession
    from app.security import read_refresh_token

    now = datetime.now(UTC)
    row = UserSession(
        subject="a", email="a@b.c", display_name="A", role="user",
        source="idp", protocol="oidc", raw_claims={},
        created_at=now, expires_at=now + timedelta(hours=1),
    )
    from app.crypto import encrypt

    row.refresh_token = encrypt("the-secret-refresh-token")
    db.add(row)
    db.commit()

    assert "the-secret-refresh-token" not in row.refresh_token
    assert row.refresh_token.startswith("enc:v1:")
    assert read_refresh_token(row) == "the-secret-refresh-token"


@pytest.mark.asyncio
async def test_refreshing_without_a_token_says_what_to_do(db):
    connection = make_oidc(db, request_refresh_token=True)
    with pytest.raises(oidc.OidcError, match="no refresh token"):
        await oidc.refresh_tokens(connection, refresh_token="")


def test_refresh_is_refused_for_a_saml_session(admin_client, db):
    from datetime import UTC, datetime, timedelta

    from app.models import UserSession
    from app.security import _serializer

    make_oidc(db, slug="samlish")
    now = datetime.now(UTC)
    row = UserSession(
        subject="a", email="a@b.c", display_name="A", role="user",
        source="nothing-here", protocol="saml", raw_claims={},
        created_at=now, expires_at=now + timedelta(hours=1),
    )
    db.add(row)
    db.commit()
    admin_client.cookies.set("authlab_session", _serializer().dumps(row.id))

    response = admin_client.post("/auth/oidc/samlish/refresh", follow_redirects=False)
    assert response.status_code == 400
    assert "did not come from an OIDC connection" in response.text


def test_refresh_requires_a_session(client, db):
    make_oidc(db, slug="idp2")
    response = client.post("/auth/oidc/idp2/refresh", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


# --- SAML assertion encryption ------------------------------------------------------


def test_saml_settings_carry_the_encryption_flags_through(db):
    from app.auth import saml

    connection = IdpConnection(slug="s", name="S", protocol="saml", config={})
    conn.store_settings(
        connection,
        {
            "idp_entity_id": "https://idp.example/e",
            "idp_sso_url": "https://idp.example/sso",
            "want_assertions_encrypted": True,
            "want_nameid_encrypted": True,
        },
    )
    db.add(connection)
    db.commit()

    security = saml.build_saml_settings(connection)["security"]
    assert security["wantAssertionsEncrypted"] is True
    assert security["wantNameIdEncrypted"] is True


def test_saml_encryption_is_off_by_default(db):
    from app.auth import saml

    connection = IdpConnection(slug="s2", name="S", protocol="saml", config={})
    conn.store_settings(connection, {"idp_sso_url": "https://idp.example/sso"})
    db.add(connection)
    db.commit()

    security = saml.build_saml_settings(connection)["security"]
    assert security["wantAssertionsEncrypted"] is False
    assert security["wantNameIdEncrypted"] is False


# --- the form -----------------------------------------------------------------------


def test_the_form_offers_the_token_security_settings(admin_client):
    response = admin_client.get("/admin/connections/new?protocol=oidc")
    for field in (
        "request_refresh_token",
        "store_rotated_refresh_token",
        "use_dpop",
        "accept_encrypted_id_token",
    ):
        assert f'name="{field}"' in response.text


def test_the_saml_form_offers_encryption(admin_client):
    response = admin_client.get("/admin/connections/new?protocol=saml")
    assert 'name="want_assertions_encrypted"' in response.text
    assert 'name="want_nameid_encrypted"' in response.text


def test_saving_the_settings_generates_keys_and_shows_the_jwks_url(admin_client, db):
    admin_client.post(
        "/admin/connections",
        data={
            "protocol": "oidc",
            "name": "Secure",
            "slug": "secure",
            "issuer": "https://idp.example/",
            "client_id": "cid",
            "default_role": "user",
            "use_dpop": "on",
            "accept_encrypted_id_token": "on",
            "request_refresh_token": "on",
        },
        follow_redirects=False,
    )
    created = conn.get_by_slug(db, "secure")
    settings_obj = conn.load_settings(created)

    assert settings_obj.use_dpop is True
    assert settings_obj.dpop_private_key
    assert settings_obj.jwe_private_key
    assert settings_obj.request_refresh_token is True

    page = admin_client.get(f"/admin/connections/{created.id}").text
    assert "/auth/oidc/secure/jwks.json" in page
