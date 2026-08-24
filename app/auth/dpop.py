"""DPoP — demonstrating proof of possession at the application layer (RFC 9449).

A bearer token is a bearer token: whoever holds it can use it. DPoP fixes that
by binding the token to a key. The client signs a small JWT proving it holds a
private key, sends it in a `DPoP` header alongside every token-endpoint call,
and the authorization server stamps the key's thumbprint into the access token
as `cnf.jkt`. A resource server then rejects the token unless the caller can
produce a fresh proof signed by the same key — so a stolen token, on its own, is
worthless.

Two things make this worth having in a test harness rather than only in a
library:

  * **You can see it.** The proof is displayed, the thumbprint we signed with is
    displayed, and the `cnf.jkt` the provider put in the token is displayed
    beside it. Token binding either happened or it did not, and there is no
    interpretation involved.
  * **The nonce dance is the part people get wrong.** A server may reject a
    first attempt with `use_dpop_nonce` and a `DPoP-Nonce` header, expecting the
    proof to be replayed with that nonce included. That is a normal part of the
    protocol, not a failure, and it is handled here — visibly, so you can watch
    it happen.

The key is per connection and generated on demand. That keeps `cnf.jkt` stable
across sign-ins, which is what makes it legible: the same thumbprint should come
back every time, and a change means something was re-provisioned.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from authlib.jose import JsonWebKey, jwt

# ES256 over P-256. RFC 9449 permits any asymmetric algorithm the server
# supports, but every implementation supports this one, and it keeps the proof
# small enough to sit comfortably in a header.
CURVE = "P-256"
ALGORITHM = "ES256"


class DpopError(Exception):
    """Something about the proof or the key is wrong, and it is ours to fix."""


def generate_key() -> str:
    """A new private key, serialised as a JWK JSON string for storage."""
    key = JsonWebKey.generate_key("EC", CURVE, is_private=True)
    return json.dumps(key.as_dict(is_private=True))


def load_key(serialised: str) -> Any:
    if not serialised:
        raise DpopError("No DPoP key is configured for this connection.")
    try:
        return JsonWebKey.import_key(json.loads(serialised))
    except (ValueError, TypeError, KeyError) as exc:
        raise DpopError(f"The stored DPoP key could not be read: {exc}") from exc


def thumbprint(serialised: str) -> str:
    """The JWK SHA-256 thumbprint — what should appear as `cnf.jkt`."""
    return load_key(serialised).thumbprint()


def public_jwk(serialised: str) -> dict[str, Any]:
    return dict(load_key(serialised).as_dict(is_private=False))


def _htu(url: str) -> str:
    """The `htu` claim: the request URI without query or fragment.

    RFC 9449 is specific about this. Leaving a query string on it is a common
    cause of a server rejecting an otherwise correct proof, and the resulting
    error rarely says which part it disliked.
    """
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def create_proof(
    serialised_key: str,
    *,
    method: str,
    url: str,
    nonce: str = "",
    access_token: str = "",
) -> str:
    """Build a DPoP proof JWT for one request.

    `access_token` is only supplied when presenting a token to a resource
    server: the proof then carries `ath`, the hash of that token, which stops a
    proof captured from one call being replayed against another.
    """
    key = load_key(serialised_key)

    header = {
        "typ": "dpop+jwt",
        "alg": ALGORITHM,
        # The public key travels in the header — that is how the server learns
        # which key to check the signature against and to bind the token to.
        "jwk": key.as_dict(is_private=False),
    }
    payload: dict[str, Any] = {
        "jti": secrets.token_urlsafe(16),
        "htm": method.upper(),
        "htu": _htu(url),
        "iat": int(time.time()),
    }
    if nonce:
        payload["nonce"] = nonce
    if access_token:
        import base64
        import hashlib

        digest = hashlib.sha256(access_token.encode("ascii")).digest()
        payload["ath"] = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    try:
        return jwt.encode(header, payload, key).decode("ascii")
    except Exception as exc:  # noqa: BLE001 — surfaced to the operator, not raised on
        raise DpopError(f"Could not sign the DPoP proof: {exc}") from exc


def describe_proof(proof: str) -> dict[str, Any]:
    """Decode a proof for display. Never used to make a decision."""
    import base64

    def segment(index: int) -> dict[str, Any]:
        part = proof.split(".")[index]
        padding = "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part + padding))

    try:
        return {"header": segment(0), "payload": segment(1)}
    except Exception:  # noqa: BLE001
        return {}


def binding_of(claims: dict[str, Any]) -> str:
    """The `cnf.jkt` a provider put in a token, or "" if it bound nothing."""
    confirmation = claims.get("cnf")
    if isinstance(confirmation, dict):
        return str(confirmation.get("jkt", "") or "")
    return ""


def check_binding(claims: dict[str, Any], serialised_key: str) -> dict[str, Any]:
    """Did the provider actually bind the token to our key?

    Three outcomes worth telling apart, because they mean different things:
    the provider bound the token to us (DPoP worked), bound it to something
    else (a real problem), or bound nothing at all (it ignored the proof, which
    usually means DPoP is not enabled for the client).
    """
    expected = thumbprint(serialised_key) if serialised_key else ""
    actual = binding_of(claims)

    if not actual:
        return {
            "bound": False,
            "expected": expected,
            "actual": "",
            "detail": (
                "The token carries no cnf.jkt, so the provider issued an ordinary "
                "bearer token and ignored the proof. DPoP usually has to be "
                "enabled on the client at the provider as well as requested here."
            ),
        }
    if actual != expected:
        return {
            "bound": False,
            "expected": expected,
            "actual": actual,
            "detail": "The token is bound to a different key than the one we signed with.",
        }
    return {
        "bound": True,
        "expected": expected,
        "actual": actual,
        "detail": "The token is bound to this connection's key and cannot be replayed without it.",
    }
