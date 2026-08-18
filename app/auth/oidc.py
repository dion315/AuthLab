"""OIDC / OAuth 2.0 Authorization Code flow with PKCE.

Written against the specification rather than against any one vendor: the
issuer's discovery document supplies every endpoint, so Entra ID, Okta, Auth0,
Ping, Keycloak, Google, and Duo are all just different issuer URLs.

The token exchange is written out explicitly instead of hidden behind a client
library, because seeing the actual parameters is most of the value for anyone
learning this flow. ID token signature and claim validation is the one part
delegated to a library (authlib) — that is the part you must never hand-roll.

Client authentication is configurable, including `private_key_jwt`: instead of
a shared secret, the app signs an assertion with a private key whose
certificate is registered at the provider. That is certificate-based
authentication for the *client*, and it is what an Entra app registration with
a certificate credential or an Okta service app expects.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any
from urllib.parse import quote, urlencode

import httpx
import jwt as pyjwt
from authlib.jose import JsonWebKey, jwt
from authlib.oidc.core import CodeIDToken
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.auth import certs
from app.auth.connections import load_settings, redirect_uri
from app.auth.schemas import OidcSettings
from app.models import IdpConnection

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"  # noqa: S105

# Discovery and JWKS documents change rarely; refetching them on every sign-in
# adds latency and a dependency on the IdP being reachable at that instant.
_CACHE_TTL_SECONDS = 3600
_discovery_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_jwks_cache: dict[str, tuple[float, Any]] = {}

REQUEST_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


class OidcError(Exception):
    """Something went wrong that the operator needs to read and act on.

    `code` and `description` come straight from the IdP where available — when
    you are testing an access policy those strings (AADSTS53003, access_denied,
    and so on) are the actual test result, so they are preserved verbatim.
    """

    def __init__(self, message: str, *, code: str = "", description: str = "", detail: dict | None = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.description = description
        self.detail = detail or {}


# --- discovery ---------------------------------------------------------------


async def fetch_discovery(settings: OidcSettings, *, force: bool = False) -> dict[str, Any]:
    issuer = settings.issuer.rstrip("/")
    if not issuer:
        raise OidcError("No issuer configured for this connection.")

    cached = _discovery_cache.get(issuer)
    if cached and not force and time.time() - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]

    url = f"{issuer}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.get(url)
            response.raise_for_status()
            document = response.json()
    except httpx.HTTPStatusError as exc:
        raise OidcError(
            f"Discovery failed: {url} returned HTTP {exc.response.status_code}.",
            detail={"discovery_url": url, "status": exc.response.status_code},
        ) from exc
    except httpx.HTTPError as exc:
        raise OidcError(
            f"Could not reach the discovery endpoint at {url}: {exc}",
            detail={"discovery_url": url},
        ) from exc

    if not settings.allow_insecure_http and not document.get("issuer", "").startswith("https://"):
        raise OidcError(
            "The discovery document advertises a non-HTTPS issuer. Enable "
            "'allow insecure http' on this connection only if you are pointing "
            "at a local test IdP.",
            detail={"issuer": document.get("issuer", "")},
        )

    _discovery_cache[issuer] = (time.time(), document)
    return document


async def fetch_jwks(discovery: dict[str, Any]) -> Any:
    jwks_uri = discovery.get("jwks_uri", "")
    if not jwks_uri:
        raise OidcError("Discovery document contains no jwks_uri; cannot verify tokens.")

    cached = _jwks_cache.get(jwks_uri)
    if cached and time.time() - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.get(jwks_uri)
        response.raise_for_status()
        key_set = JsonWebKey.import_key_set(response.json())

    _jwks_cache[jwks_uri] = (time.time(), key_set)
    return key_set


def invalidate_cache(issuer: str = "") -> None:
    """Drop cached discovery/JWKS — used after editing a connection."""
    if issuer:
        _discovery_cache.pop(issuer.rstrip("/"), None)
    else:
        _discovery_cache.clear()
        _jwks_cache.clear()


# --- authorization request ---------------------------------------------------


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    return verifier, challenge


async def build_authorization_request(
    connection: IdpConnection,
    *,
    extra_prompt: str = "",
    extra_acr: str = "",
    extra_claims: str = "",
    extra_max_age: str = "",
) -> tuple[str, dict[str, str]]:
    """Return (authorization_url, flow_state).

    flow_state is handed back to the caller to put in a signed, short-lived
    cookie; it is required again at the callback to complete PKCE and to check
    state and nonce.

    The `extra_*` arguments let the dashboard trigger a step-up or a forced
    re-authentication on demand without editing the saved connection — that is
    how you test "require MFA" or "require a certificate" interactively and
    still have the saved configuration to fall back to.
    """
    settings = load_settings(connection)
    assert isinstance(settings, OidcSettings)
    discovery = await fetch_discovery(settings)

    authorization_endpoint = discovery.get("authorization_endpoint", "")
    if not authorization_endpoint:
        raise OidcError("Discovery document contains no authorization_endpoint.")

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    flow_state = {"state": state, "nonce": nonce, "slug": connection.slug}

    params: dict[str, str] = {
        "response_type": "code",
        "client_id": settings.client_id,
        "redirect_uri": redirect_uri(connection.slug),
        "scope": settings.scopes,
        "state": state,
        "nonce": nonce,
    }

    if settings.use_pkce:
        verifier, challenge = _pkce_pair()
        flow_state["code_verifier"] = verifier
        params["code_challenge"] = challenge
        params["code_challenge_method"] = "S256"

    prompt = extra_prompt or settings.prompt
    if prompt:
        params["prompt"] = prompt

    acr = extra_acr or settings.acr_values
    if acr:
        params["acr_values"] = acr

    max_age = extra_max_age or (str(settings.max_age) if settings.max_age is not None else "")
    if max_age:
        params["max_age"] = max_age

    claims_request = extra_claims or settings.claims_request
    if claims_request:
        params["claims"] = claims_request

    return f"{authorization_endpoint}?{urlencode(params)}", flow_state


# --- client authentication ---------------------------------------------------
#
# How this app proves to the token endpoint that it is the registered client.
# A shared secret is the common case; private_key_jwt is the certificate-based
# alternative, where the provider holds only the public certificate and there
# is no shared secret in existence to leak.


def _assertion_algorithm(key: Any) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return "RS256"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return {"secp256r1": "ES256", "secp384r1": "ES384", "secp521r1": "ES512"}.get(
            key.curve.name, "ES256"
        )
    raise OidcError(
        "The client private key must be RSA or EC. Ed25519 keys are not accepted "
        "for client assertions by any provider this has been tested against."
    )


def build_client_assertion(settings: OidcSettings, *, audience: str) -> str:
    """A signed JWT proving possession of the client's private key (RFC 7523).

    The certificate is not sent — only a thumbprint of it in the header. The
    provider already holds the certificate from when it was registered, and
    matches on that thumbprint. Both `x5t` and `x5t#S256` are sent: Entra
    documents the SHA-1 form, everything modern prefers SHA-256, and sending
    both costs nothing.
    """
    if not settings.client_private_key:
        raise OidcError(
            "This connection uses private_key_jwt but has no client private key. "
            "Add one, or generate a keypair from the connection page."
        )
    if not settings.client_id:
        raise OidcError("A client ID is required to build a client assertion.")

    try:
        key = certs.load_private_key(settings.client_private_key)
    except certs.CertificateError as exc:
        raise OidcError(f"Client private key could not be read: {exc.message}") from exc

    headers: dict[str, Any] = {"typ": "JWT"}
    if settings.client_certificate:
        try:
            certificate = certs.load_certificate(settings.client_certificate)
        except certs.CertificateError as exc:
            raise OidcError(f"Client certificate could not be read: {exc.message}") from exc
        headers["x5t#S256"] = certs.x5t_s256(certificate)
        headers["x5t"] = (
            base64.urlsafe_b64encode(bytes.fromhex(certs.thumbprint(certificate, "sha1")))
            .decode("ascii")
            .rstrip("=")
        )

    now = int(time.time())
    payload = {
        "iss": settings.client_id,
        "sub": settings.client_id,
        "aud": audience,
        # Providers reject a replayed assertion by jti, so it must be unique.
        "jti": secrets.token_urlsafe(24),
        "iat": now,
        "nbf": now,
        # Short-lived on purpose: an assertion is used once, immediately.
        "exp": now + 300,
    }
    return pyjwt.encode(payload, key, algorithm=_assertion_algorithm(key), headers=headers)


def apply_client_authentication(
    settings: OidcSettings, form: dict[str, str], *, token_endpoint: str, issuer: str
) -> dict[str, str]:
    """Add client credentials to a token request. Returns extra HTTP headers.

    Mutates `form` because that is where three of the four methods put their
    credentials; only client_secret_basic uses a header.
    """
    method = settings.client_auth_method

    if method == "none":
        # A public client. Legitimate with PKCE, and the reason the secret is
        # never sent unless a method actually asks for it.
        return {}

    if method == "private_key_jwt":
        audience = settings.assertion_audience or token_endpoint or issuer
        form["client_assertion_type"] = CLIENT_ASSERTION_TYPE
        form["client_assertion"] = build_client_assertion(settings, audience=audience)
        return {}

    if not settings.client_secret:
        raise OidcError(
            f"This connection uses {method} but has no client secret stored. "
            "Enter one, or switch the client authentication method."
        )

    if method == "client_secret_basic":
        # RFC 6749 §2.3.1: both halves are form-urlencoded before base64.
        credentials = f"{quote(settings.client_id, safe='')}:{quote(settings.client_secret, safe='')}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {encoded}"}

    form["client_secret"] = settings.client_secret
    return {}


# --- callback ----------------------------------------------------------------


async def exchange_code(
    connection: IdpConnection, *, code: str, code_verifier: str | None
) -> dict[str, Any]:
    settings = load_settings(connection)
    assert isinstance(settings, OidcSettings)
    discovery = await fetch_discovery(settings)

    token_endpoint = discovery.get("token_endpoint", "")
    if not token_endpoint:
        raise OidcError("Discovery document contains no token_endpoint.")

    form: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri(connection.slug),
        "client_id": settings.client_id,
    }
    if code_verifier:
        form["code_verifier"] = code_verifier

    headers = {"Accept": "application/json"}
    headers.update(
        apply_client_authentication(
            settings,
            form,
            token_endpoint=token_endpoint,
            issuer=discovery.get("issuer", settings.issuer),
        )
    )

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.post(token_endpoint, data=form, headers=headers)

    try:
        payload = response.json()
    except ValueError:
        raise OidcError(
            f"Token endpoint returned HTTP {response.status_code} with a non-JSON body.",
            detail={"status": response.status_code, "body": response.text[:1000]},
        ) from None

    if response.status_code >= 400 or "error" in payload:
        # Surfaced rather than swallowed: this is where policy denials and
        # consent failures show up with their real error codes.
        raise OidcError(
            "The IdP rejected the token request.",
            code=str(payload.get("error", f"http_{response.status_code}")),
            description=str(payload.get("error_description", "")),
            detail={"status": response.status_code, "response": payload},
        )

    return payload


async def validate_id_token(
    connection: IdpConnection, *, id_token: str, nonce: str
) -> dict[str, Any]:
    settings = load_settings(connection)
    assert isinstance(settings, OidcSettings)
    discovery = await fetch_discovery(settings)
    key_set = await fetch_jwks(discovery)

    try:
        claims = jwt.decode(
            id_token,
            key_set,
            claims_cls=CodeIDToken,
            claims_options={
                "iss": {"essential": True, "values": [discovery.get("issuer", settings.issuer)]},
                "aud": {"essential": True, "values": [settings.client_id]},
            },
            claims_params={"nonce": nonce, "client_id": settings.client_id},
        )
        # 60s leeway absorbs ordinary clock skew between us and the IdP.
        claims.validate(leeway=60)
    except Exception as exc:
        raise OidcError(
            f"ID token validation failed: {exc}",
            detail={"reason": str(exc)},
        ) from exc

    return dict(claims)


async def fetch_userinfo(connection: IdpConnection, access_token: str) -> dict[str, Any]:
    """Best-effort userinfo call.

    Some IdPs put group membership only in userinfo, not in the ID token, so
    this is worth having — but a failure here must not fail the sign-in.
    """
    settings = load_settings(connection)
    assert isinstance(settings, OidcSettings)
    try:
        discovery = await fetch_discovery(settings)
        endpoint = discovery.get("userinfo_endpoint", "")
        if not endpoint:
            return {}
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.get(
                endpoint, headers={"Authorization": f"Bearer {access_token}"}
            )
            if response.status_code >= 400:
                return {}
            return response.json()
    except (httpx.HTTPError, OidcError, ValueError):
        return {}


async def end_session_url(connection: IdpConnection, *, id_token_hint: str = "") -> str:
    """Federated sign-out URL, or "" if the IdP does not advertise one.

    Without this, signing out only clears the local session and the next
    sign-in completes silently against the still-live IdP session — which makes
    it impossible to retest a policy without clearing browser state by hand.
    """
    settings = load_settings(connection)
    assert isinstance(settings, OidcSettings)
    if not settings.federated_logout:
        return ""
    try:
        discovery = await fetch_discovery(settings)
    except OidcError:
        return ""

    endpoint = discovery.get("end_session_endpoint", "")
    if not endpoint:
        return ""

    from app.config import get_settings

    params = {"post_logout_redirect_uri": get_settings().base_url.rstrip("/") + "/"}
    if id_token_hint:
        params["id_token_hint"] = id_token_hint
    return f"{endpoint}?{urlencode(params)}"
