"""OIDC / OAuth 2.0 Authorization Code flow with PKCE.

Written against the specification rather than against any one vendor: the
issuer's discovery document supplies every endpoint, so Entra ID, Okta, Auth0,
Ping, Keycloak, Google, and Duo are all just different issuer URLs.

The token exchange is written out explicitly instead of hidden behind a client
library, because seeing the actual parameters is most of the value for anyone
learning this flow. ID token signature and claim validation is the one part
delegated to a library (authlib) — that is the part you must never hand-roll.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx
from authlib.jose import JsonWebKey, jwt
from authlib.oidc.core import CodeIDToken

from app.auth import dpop, tokencrypto
from app.auth.connections import load_settings, redirect_uri
from app.auth.schemas import OidcSettings
from app.models import IdpConnection

# Discovery and JWKS documents change rarely; refetching them on every sign-in
# adds latency and a dependency on the IdP being reachable at that instant.
_CACHE_TTL_SECONDS = 3600
_discovery_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_jwks_cache: dict[str, tuple[float, Any]] = {}

REQUEST_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


class OidcError(Exception):
    """Something went wrong that the operator needs to read and act on.

    `code` and `description` come straight from the IdP where available — for
    Conditional Access work those strings (AADSTS53003, access_denied, and so
    on) are the actual test result, so they are preserved verbatim.
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


def requested_scopes(settings: OidcSettings) -> str:
    """The scope string actually sent.

    `offline_access` is appended rather than left to the operator because it is
    the scope that makes a provider issue a refresh token, and "I ticked the
    box and got no refresh token" is otherwise a puzzling place to end up.
    Duplicates are avoided in case somebody has already listed it.
    """
    scopes = [s for s in (settings.scopes or "").split() if s]
    if settings.request_refresh_token and "offline_access" not in scopes:
        scopes.append("offline_access")
    return " ".join(scopes)


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
    extra_max_age: int | None = None,
) -> tuple[str, dict[str, str]]:
    """Return (authorization_url, flow_state).

    flow_state is handed back to the caller to put in a signed, short-lived
    cookie; it is required again at the callback to complete PKCE and to check
    state and nonce.

    The `extra_*` arguments let the dashboard and the step-up page trigger a
    stronger authentication request on demand without editing the saved
    connection — that is how you test "require MFA" interactively.
    `extra_claims` carries a claims challenge, which is the mechanism an Entra
    ID authentication context uses to demand step-up for a specific action.
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
        "scope": requested_scopes(settings),
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

    max_age = settings.max_age if extra_max_age is None else extra_max_age
    if max_age is not None:
        params["max_age"] = str(max_age)

    claims_request = extra_claims or settings.claims_request
    if claims_request:
        params["claims"] = claims_request

    return f"{authorization_endpoint}?{urlencode(params)}", flow_state


# --- callback ----------------------------------------------------------------


async def _post_token_request(
    settings: OidcSettings, token_endpoint: str, form: dict[str, str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """POST to the token endpoint, carrying a DPoP proof when configured.

    Returns (payload, dpop_report). The report is for display: what we signed
    with, whether a nonce round trip was needed, and the proof itself decoded.

    The nonce retry is the part worth understanding. A server may refuse a first
    proof with `use_dpop_nonce` and hand back a `DPoP-Nonce` header, expecting
    the same request again with that nonce inside the proof. That is ordinary
    protocol traffic rather than an error, so it is retried once, silently to
    the caller but visibly in the report.
    """
    headers = {"Accept": "application/json"}
    report: dict[str, Any] = {"used": False}

    if settings.use_dpop:
        report["used"] = True
        report["thumbprint"] = dpop.thumbprint(settings.dpop_private_key)

    async def send(nonce: str = "") -> tuple[httpx.Response, str]:
        request_headers = dict(headers)
        proof = ""
        if settings.use_dpop:
            proof = dpop.create_proof(
                settings.dpop_private_key,
                method="POST",
                url=token_endpoint,
                nonce=nonce,
            )
            request_headers["DPoP"] = proof
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            return await client.post(token_endpoint, data=form, headers=request_headers), proof

    response, proof = await send()

    if settings.use_dpop and response.status_code >= 400:
        nonce = response.headers.get("DPoP-Nonce", "")
        body = {}
        try:
            body = response.json()
        except ValueError:
            body = {}
        if nonce and body.get("error") == "use_dpop_nonce":
            report["nonce_required"] = True
            report["nonce"] = nonce
            response, proof = await send(nonce)

    if proof:
        report["proof"] = dpop.describe_proof(proof)

    try:
        payload = response.json()
    except ValueError:
        raise OidcError(
            f"Token endpoint returned HTTP {response.status_code} with a non-JSON body.",
            detail={"status": response.status_code, "body": response.text[:1000]},
        ) from None

    if response.status_code >= 400 or "error" in payload:
        # Surfaced rather than swallowed: this is where Conditional Access
        # denials and consent failures show up with their real error codes.
        raise OidcError(
            "The IdP rejected the token request.",
            code=str(payload.get("error", f"http_{response.status_code}")),
            description=str(payload.get("error_description", "")),
            detail={"status": response.status_code, "response": payload, "dpop": report},
        )

    # A DPoP-bound token is issued as token_type "DPoP" rather than "Bearer".
    report["token_type"] = str(payload.get("token_type", ""))
    return payload, report


async def exchange_code(
    connection: IdpConnection, *, code: str, code_verifier: str | None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Trade the authorization code for tokens. Returns (payload, dpop_report)."""
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
    # A public client (no secret, PKCE only) is a legitimate configuration, so
    # the secret is sent only when one is actually configured.
    if settings.client_secret:
        form["client_secret"] = settings.client_secret

    return await _post_token_request(settings, token_endpoint, form)


async def refresh_tokens(
    connection: IdpConnection, *, refresh_token: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Exchange a refresh token for a fresh set. Returns (payload, dpop_report).

    What makes this interesting to run deliberately: a refresh is the one way
    access is extended *without* a new authentication, so it is where you find
    out whether your provider re-evaluates policy at refresh time or only at
    sign-in, and whether it rotates the refresh token on use.
    """
    settings = load_settings(connection)
    assert isinstance(settings, OidcSettings)

    # Checked before discovery: there is no point reaching out to the provider
    # to discover an endpoint we have nothing to send to, and a network error
    # would bury the actual problem.
    if not refresh_token:
        raise OidcError(
            "This session has no refresh token. Enable 'Request a refresh token' "
            "on the connection and sign in again — the token is only issued when "
            "offline_access is requested at authentication time."
        )

    discovery = await fetch_discovery(settings)
    token_endpoint = discovery.get("token_endpoint", "")
    if not token_endpoint:
        raise OidcError("Discovery document contains no token_endpoint.")

    form: dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": settings.client_id,
    }
    if settings.client_secret:
        form["client_secret"] = settings.client_secret
    # Narrowing is allowed but not required; sending the same scopes keeps the
    # comparison between the old and new token honest.
    scopes = requested_scopes(settings)
    if scopes:
        form["scope"] = scopes

    return await _post_token_request(settings, token_endpoint, form)


async def validate_id_token(
    connection: IdpConnection, *, id_token: str, nonce: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate an ID token, decrypting it first if it arrived as a JWE.

    Returns (claims, encryption_report). Decryption proves only who the token
    was *for*; the signature check below is what establishes who issued it, and
    it still runs either way.
    """
    settings = load_settings(connection)
    assert isinstance(settings, OidcSettings)

    try:
        id_token, encryption = tokencrypto.unwrap(id_token, settings)
    except tokencrypto.TokenCryptoError as exc:
        raise OidcError(str(exc), detail={"stage": "decrypt"}) from exc

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
            detail={"reason": str(exc), "encryption": encryption},
        ) from exc

    return dict(claims), encryption


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
