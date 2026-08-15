"""Short-lived signed cookies carrying in-flight login state.

PKCE verifier, state, nonce, and the SAML AuthnRequest ID all have to survive
the round trip to the IdP and come back intact. They are genuinely signed with
itsdangerous and carry a hard expiry, so a tampered or stale value is rejected
rather than trusted.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config import get_settings

MAX_AGE_SECONDS = 600  # a login round trip that takes >10 minutes has failed
_SALT = "authlab.login-flow.v1"


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_settings().app_secret_key, salt=_SALT)


def cookie_name(kind: str, slug: str) -> str:
    return f"authlab_flow_{kind}_{slug}"


def set_flow(response: Response, kind: str, slug: str, data: dict[str, Any]) -> None:
    settings = get_settings()
    response.set_cookie(
        cookie_name(kind, slug),
        _serializer().dumps(data),
        httponly=True,
        secure=settings.cookies_secure,
        samesite="lax",
        max_age=MAX_AGE_SECONDS,
        path="/",
    )


def read_flow(request: Request, kind: str, slug: str) -> dict[str, Any] | None:
    raw = request.cookies.get(cookie_name(kind, slug))
    if not raw:
        return None
    try:
        return _serializer().loads(raw, max_age=MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None


def clear_flow(response: Response, kind: str, slug: str) -> None:
    response.delete_cookie(cookie_name(kind, slug), path="/")
