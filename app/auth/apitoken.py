"""Validating access tokens — the resource-server half of OAuth 2.0.

Everything else in this app is the *client* half: a browser turns up, gets
redirected, and comes back with an authorization code. But a large share of
"can this thing reach that thing" in an enterprise never involves a browser at
all. A service principal gets a token via client credentials, presents it to an
API, and the API decides. Testing that requires being the API, which is what
this module is for.

The validation is deliberately explicit rather than delegated, because the
questions people actually have are about *which check failed*:

  * Is the signature good against the issuer's published keys?
  * Is `iss` the issuer we expect?
  * Is `aud` us, or did someone hand us a token minted for something else?
  * Has it expired, and by how much?
  * What is in `scp` / `roles` / `appid`?

So every check is reported separately and a failure names itself.

One provider-specific trap worth knowing, because it costs people a day: an
Entra ID access token issued for **Microsoft Graph** cannot be validated by
anyone but Graph — the signature covers a nonce only Microsoft holds, so the
check will fail no matter what you do. Tokens issued for *your own* app
registration's exposed API validate normally. Point this at an audience you
own.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError

from app.auth.connections import load_settings
from app.auth.oidc import REQUEST_TIMEOUT, OidcError, fetch_discovery, fetch_jwks
from app.auth.schemas import OidcSettings
from app.models import IdpConnection

# Every algorithm here is asymmetric on purpose. Accepting an HMAC algorithm
# alongside RSA is the classic JWT confusion attack: an attacker signs a token
# with the *public* key as an HMAC secret and a permissive verifier accepts it.
ALLOWED_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"]

# Claims worth pulling out by name in the result, because they are the ones
# that decide API authorisation.
AUTHORISATION_CLAIMS = ("scp", "scope", "roles", "appid", "azp", "sub", "oid", "idtyp", "tid")


class TokenInspection(dict):
    """Result of inspecting a token. A dict so templates and JSON share it."""


def _unverified_header(token: str) -> dict[str, Any]:
    import base64
    import json

    try:
        header_segment = token.split(".")[0]
        padding = "=" * (-len(header_segment) % 4)
        return json.loads(base64.urlsafe_b64decode(header_segment + padding))
    except Exception:  # noqa: BLE001 — a malformed header is a result, not a crash
        return {}


async def inspect_access_token(
    connection: IdpConnection,
    token: str,
    *,
    expected_audience: str = "",
) -> TokenInspection:
    """Validate an access token against a connection's issuer.

    Never raises for a *token* problem — an invalid token is the answer, not an
    error. Raises OidcError only when the issuer itself cannot be reached, which
    is a configuration problem the operator has to fix before any answer means
    anything.
    """
    token = (token or "").strip()
    result = TokenInspection(
        valid=False,
        checks=[],
        claims={},
        header=_unverified_header(token),
        authorisation={},
    )

    if not token:
        result["error"] = "No token supplied."
        return result
    if token.count(".") != 2:
        result["error"] = (
            "This is not a JWT. Some providers issue opaque access tokens that "
            "only their own introspection endpoint can read; those cannot be "
            "validated here."
        )
        return result

    settings = load_settings(connection)
    assert isinstance(settings, OidcSettings)

    discovery = await fetch_discovery(settings)
    key_set = await fetch_jwks(discovery)

    def record(name: str, passed: bool, detail: str = "") -> None:
        result["checks"].append({"name": name, "passed": passed, "detail": detail})

    try:
        claims = JsonWebToken(ALLOWED_ALGORITHMS).decode(token, key_set)
        record("signature", True, f"Verified against {discovery.get('jwks_uri', '')}")
    except ValueError as exc:
        # authlib raises a bare ValueError when the token's `kid` is not in the
        # published key set — which is not an exotic case: it is what a rotated
        # signing key, or a token from a different tenant, looks like. Catching
        # only JoseError here turned that into a 500.
        kid = result["header"].get("kid", "")
        record("signature", False, f"No key with kid '{kid}' in the issuer's JWKS")
        result["error"] = (
            f"The issuer does not publish a signing key with kid '{kid}'. That "
            "usually means the token came from a different tenant or issuer than "
            "this connection points at, or the key has been rotated and the "
            "cached JWKS is stale."
            if "Key not found" in str(exc)
            else f"Signature validation failed: {exc}"
        )
        return result
    except JoseError as exc:
        record("signature", False, str(exc))
        result["error"] = f"Signature validation failed: {exc}"
        return result

    result["claims"] = dict(claims)

    expected_issuer = discovery.get("issuer", settings.issuer)
    actual_issuer = str(claims.get("iss", ""))
    # Entra issues v1 tokens with an /sts.windows.net/ issuer and v2 with
    # /login.microsoftonline.com/v2.0 — the same directory, two spellings.
    issuer_ok = actual_issuer.rstrip("/") == expected_issuer.rstrip("/")
    record(
        "issuer",
        issuer_ok,
        f"expected {expected_issuer}, got {actual_issuer}" if not issuer_ok else actual_issuer,
    )

    audience = claims.get("aud", "")
    audiences = audience if isinstance(audience, list) else [audience]
    audiences = [str(a) for a in audiences if a]
    wanted_audience = expected_audience.strip() or settings.client_id
    if wanted_audience:
        audience_ok = wanted_audience in audiences
        record(
            "audience",
            audience_ok,
            f"expected {wanted_audience}, got {', '.join(audiences) or '(none)'}",
        )
    else:
        audience_ok = True
        record("audience", True, "not checked — no expected audience configured")

    now = int(time.time())
    expiry = claims.get("exp")
    if expiry is None:
        expired_ok = False
        record("expiry", False, "token carries no exp claim")
    else:
        expired_ok = int(expiry) > now
        delta = abs(int(expiry) - now)
        record(
            "expiry",
            expired_ok,
            f"expires in {delta}s" if expired_ok else f"expired {delta}s ago",
        )

    not_before = claims.get("nbf")
    if not_before is not None and int(not_before) > now + 60:
        record("not_before", False, f"not valid for another {int(not_before) - now}s")
        nbf_ok = False
    else:
        nbf_ok = True

    result["authorisation"] = {
        name: claims[name] for name in AUTHORISATION_CLAIMS if name in claims
    }
    result["valid"] = issuer_ok and audience_ok and expired_ok and nbf_ok
    return result


async def client_credentials_token(
    connection: IdpConnection, *, scope: str = ""
) -> dict[str, Any]:
    """Run a client_credentials grant against the connection's token endpoint.

    This is how you get a token to inspect without standing up a separate
    client: the same app registration that backs the interactive flow can
    usually mint one for itself. Requires a client secret — a public client
    cannot use this grant, which is itself a useful thing to demonstrate.
    """
    settings = load_settings(connection)
    assert isinstance(settings, OidcSettings)

    if not settings.client_secret:
        raise OidcError(
            "client_credentials requires a client secret. This connection is "
            "configured as a public client (PKCE only), which cannot use this "
            "grant.",
        )

    discovery = await fetch_discovery(settings)
    token_endpoint = discovery.get("token_endpoint", "")
    if not token_endpoint:
        raise OidcError("Discovery document contains no token_endpoint.")

    form = {
        "grant_type": "client_credentials",
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
    }
    if scope.strip():
        form["scope"] = scope.strip()

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.post(
            token_endpoint, data=form, headers={"Accept": "application/json"}
        )

    try:
        payload = response.json()
    except ValueError:
        raise OidcError(
            f"Token endpoint returned HTTP {response.status_code} with a non-JSON body.",
            detail={"status": response.status_code, "body": response.text[:1000]},
        ) from None

    if response.status_code >= 400 or "error" in payload:
        raise OidcError(
            "The IdP rejected the client_credentials request.",
            code=str(payload.get("error", f"http_{response.status_code}")),
            description=str(payload.get("error_description", "")),
            detail={"status": response.status_code, "response": payload},
        )

    return payload
