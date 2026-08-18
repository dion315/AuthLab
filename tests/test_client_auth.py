"""How this app authenticates itself to an OIDC token endpoint.

private_key_jwt is the certificate-based option, and the assertion it builds has
to be exactly right — a provider that rejects it answers `invalid_client` and
says nothing about which part was wrong, so these assertions stand in for the
error message the provider will not give you.
"""

from __future__ import annotations

import base64
import time

import jwt as pyjwt
import pytest

from app.auth import certs, oidc
from app.auth.schemas import OidcSettings

TOKEN_ENDPOINT = "https://login.example.com/oauth2/v2.0/token"
CLIENT_ID = "11111111-2222-3333-4444-555555555555"


@pytest.fixture(scope="module")
def credential() -> tuple[str, str]:
    return certs.generate_self_signed("AuthLab client credential", client_auth=True)


@pytest.fixture
def settings(credential) -> OidcSettings:
    return OidcSettings(
        issuer="https://login.example.com/v2.0",
        client_id=CLIENT_ID,
        client_auth_method="private_key_jwt",
        client_certificate=credential[0],
        client_private_key=credential[1],
    )


def _decode(assertion: str, credential: tuple[str, str]) -> dict:
    """Verify the assertion the way the provider would: against the public key."""
    return pyjwt.decode(
        assertion,
        certs.load_certificate(credential[0]).public_key(),
        algorithms=["RS256"],
        audience=TOKEN_ENDPOINT,
    )


def test_assertion_is_signed_by_the_registered_key(settings, credential):
    claims = _decode(oidc.build_client_assertion(settings, audience=TOKEN_ENDPOINT), credential)

    # RFC 7523: the client is both issuer and subject of its own assertion.
    assert claims["iss"] == CLIENT_ID
    assert claims["sub"] == CLIENT_ID
    assert claims["aud"] == TOKEN_ENDPOINT


def test_assertion_is_short_lived_and_single_use(settings, credential):
    assertion = oidc.build_client_assertion(settings, audience=TOKEN_ENDPOINT)
    claims = _decode(assertion, credential)

    assert 0 < claims["exp"] - time.time() <= 300
    # A replayed assertion is rejected by jti, so two must never match.
    second = _decode(oidc.build_client_assertion(settings, audience=TOKEN_ENDPOINT), credential)
    assert claims["jti"] != second["jti"]


def test_header_carries_both_certificate_thumbprints(settings, credential):
    """Entra documents x5t (SHA-1); everything modern prefers x5t#S256."""
    header = pyjwt.get_unverified_header(
        oidc.build_client_assertion(settings, audience=TOKEN_ENDPOINT)
    )
    certificate = certs.load_certificate(credential[0])

    assert header["alg"] == "RS256"
    assert header["x5t#S256"] == certs.x5t_s256(certificate)
    expected_sha1 = (
        base64.urlsafe_b64encode(bytes.fromhex(certs.thumbprint(certificate, "sha1")))
        .decode("ascii")
        .rstrip("=")
    )
    assert header["x5t"] == expected_sha1


def test_missing_private_key_is_reported_before_the_request(credential):
    settings = OidcSettings(
        client_id=CLIENT_ID, client_auth_method="private_key_jwt", client_certificate=credential[0]
    )

    with pytest.raises(oidc.OidcError) as exc:
        oidc.build_client_assertion(settings, audience=TOKEN_ENDPOINT)

    assert "no client private key" in str(exc.value)


def test_unreadable_private_key_names_the_field(settings):
    settings.client_private_key = "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"

    with pytest.raises(oidc.OidcError) as exc:
        oidc.build_client_assertion(settings, audience=TOKEN_ENDPOINT)

    assert "private key could not be read" in str(exc.value)


# --- the other three methods -------------------------------------------------


def test_private_key_jwt_puts_the_assertion_in_the_form(settings):
    form: dict[str, str] = {}

    headers = oidc.apply_client_authentication(
        settings, form, token_endpoint=TOKEN_ENDPOINT, issuer="https://login.example.com/v2.0"
    )

    assert headers == {}
    assert form["client_assertion_type"] == oidc.CLIENT_ASSERTION_TYPE
    assert form["client_assertion"]
    assert "client_secret" not in form


def test_client_secret_post_sends_the_secret_in_the_body():
    settings = OidcSettings(
        client_id=CLIENT_ID, client_secret="s3cret", client_auth_method="client_secret_post"
    )
    form: dict[str, str] = {}

    headers = oidc.apply_client_authentication(
        settings, form, token_endpoint=TOKEN_ENDPOINT, issuer=""
    )

    assert headers == {}
    assert form["client_secret"] == "s3cret"


def test_client_secret_basic_sends_an_authorization_header():
    settings = OidcSettings(
        client_id="client with spaces",
        client_secret="p@ss/word",
        client_auth_method="client_secret_basic",
    )
    form: dict[str, str] = {}

    headers = oidc.apply_client_authentication(
        settings, form, token_endpoint=TOKEN_ENDPOINT, issuer=""
    )

    encoded = headers["Authorization"].split(" ", 1)[1]
    # RFC 6749 §2.3.1: both halves are form-urlencoded before base64.
    assert base64.b64decode(encoded).decode() == "client%20with%20spaces:p%40ss%2Fword"
    assert "client_secret" not in form


def test_public_client_sends_no_credential_at_all():
    settings = OidcSettings(client_id=CLIENT_ID, client_secret="unused", client_auth_method="none")
    form: dict[str, str] = {}

    headers = oidc.apply_client_authentication(
        settings, form, token_endpoint=TOKEN_ENDPOINT, issuer=""
    )

    assert headers == {}
    assert form == {}


def test_a_secret_method_with_no_secret_is_refused():
    settings = OidcSettings(client_id=CLIENT_ID, client_auth_method="client_secret_post")

    with pytest.raises(oidc.OidcError) as exc:
        oidc.apply_client_authentication(settings, {}, token_endpoint=TOKEN_ENDPOINT, issuer="")

    assert "no client secret" in str(exc.value)


def test_assertion_audience_can_be_overridden(settings, credential):
    settings.assertion_audience = "https://login.example.com/v2.0"
    form: dict[str, str] = {}

    oidc.apply_client_authentication(
        settings, form, token_endpoint=TOKEN_ENDPOINT, issuer="https://login.example.com/v2.0"
    )

    claims = pyjwt.decode(
        form["client_assertion"],
        certs.load_certificate(credential[0]).public_key(),
        algorithms=["RS256"],
        audience="https://login.example.com/v2.0",
    )
    assert claims["aud"] == "https://login.example.com/v2.0"


def test_client_private_key_is_encrypted_at_rest(db, credential):
    from app.auth.connections import load_settings, store_settings
    from app.models import IdpConnection

    connection = IdpConnection(slug="pkjwt", name="Cert client", protocol="oidc", config={})
    store_settings(
        connection,
        {
            "issuer": "https://login.example.com/v2.0",
            "client_id": CLIENT_ID,
            "client_auth_method": "private_key_jwt",
            "client_certificate": credential[0],
            "client_private_key": credential[1],
        },
    )

    assert connection.config["client_private_key"].startswith("enc:v1:")
    assert "PRIVATE KEY" not in connection.config["client_private_key"]
    # And it round-trips, or nothing could ever be signed with it.
    assert load_settings(connection).client_private_key == credential[1]
