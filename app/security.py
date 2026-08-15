"""Passwords, bearer tokens, sessions, and client-IP resolution."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Request, Response
from itsdangerous import BadSignature, URLSafeSerializer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import UserSession

_hasher = PasswordHasher()


# --- passwords ---------------------------------------------------------------


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except (InvalidHashError, ValueError):
        return False


# --- bearer tokens (SCIM) ----------------------------------------------------


def generate_token() -> str:
    """A provisioning token. 256 bits — these get pasted into IdP consoles."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Keyed hash of a bearer token.

    A fast HMAC rather than Argon2 on purpose: these tokens are 256 bits of
    machine-generated entropy, not user-chosen passwords, so there is nothing
    to brute force and a provisioning run should not pay a KDF per request.
    """
    settings = get_settings()
    return hmac.new(
        settings.app_secret_key.encode("utf-8"), token.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_token(presented: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_token(presented), stored_hash)


# --- request metadata --------------------------------------------------------


def client_ip(request: Request) -> str:
    """Resolve the caller's IP.

    Behind a cloud load balancer the socket peer is the balancer, and the real
    client only appears in X-Forwarded-For. Source IP is a Conditional Access
    condition, so this needs to be right or the app misreports where sign-ins
    came from. Only trusted when TRUST_PROXY_HEADERS is on, because the header
    is caller-supplied and trivially spoofed when nothing strips it.
    """
    settings = get_settings()
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            # Left-most entry is the original client; the rest are hops.
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip", "")
        if real_ip:
            return real_ip.strip()
    return request.client.host if request.client else ""


def user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")[:400]


# --- sessions ----------------------------------------------------------------

_COOKIE_SALT = "authlab.session-cookie.v1"


def _serializer() -> URLSafeSerializer:
    return URLSafeSerializer(get_settings().app_secret_key, salt=_COOKIE_SALT)


def create_session(
    db: Session,
    response: Response,
    *,
    subject: str,
    email: str,
    display_name: str,
    role: str,
    source: str,
    protocol: str,
    raw_claims: dict,
    request: Request | None = None,
    id_token: str = "",
    name_id: str = "",
    session_index: str = "",
) -> UserSession:
    settings = get_settings()
    now = datetime.now(UTC)

    record = UserSession(
        subject=subject,
        email=email,
        display_name=display_name,
        role=role,
        source=source,
        protocol=protocol,
        raw_claims=raw_claims,
        id_token=id_token,
        name_id=name_id,
        session_index=session_index,
        created_at=now,
        expires_at=now + timedelta(minutes=settings.session_ttl_minutes),
        client_ip=client_ip(request) if request else "",
        user_agent=user_agent(request) if request else "",
    )
    db.add(record)
    db.commit()

    response.set_cookie(
        settings.session_cookie_name,
        _serializer().dumps(record.id),
        httponly=True,
        secure=settings.cookies_secure,
        # "lax" rather than "strict": the SAML and OIDC callbacks are
        # cross-site requests from the IdP, and "strict" would withhold the
        # cookie on the redirect that lands the user back here.
        samesite="lax",
        max_age=settings.session_ttl_minutes * 60,
        path="/",
    )
    return record


def read_session(db: Session, request: Request) -> UserSession | None:
    settings = get_settings()
    raw = request.cookies.get(settings.session_cookie_name)
    if not raw:
        return None
    try:
        session_id = _serializer().loads(raw)
    except BadSignature:
        return None

    record = db.execute(
        select(UserSession).where(UserSession.id == session_id)
    ).scalar_one_or_none()
    if record is None or record.revoked_at is not None:
        return None

    # SQLite hands back naive datetimes; normalise before comparing.
    expires = record.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if expires < datetime.now(UTC):
        return None

    return record


def revoke_session(db: Session, session_id: str) -> None:
    record = db.get(UserSession, session_id)
    if record and record.revoked_at is None:
        record.revoked_at = datetime.now(UTC)
        db.commit()


def revoke_sessions_for_subject(db: Session, subject: str) -> int:
    """Kill every live session for a subject.

    Called when SCIM deactivates a user, so deprovisioning takes effect at once
    instead of whenever the session happens to expire. Demonstrating that
    difference is a big part of why anyone tests SCIM.
    """
    now = datetime.now(UTC)
    rows = (
        db.execute(
            select(UserSession).where(
                UserSession.subject == subject, UserSession.revoked_at.is_(None)
            )
        )
        .scalars()
        .all()
    )
    for row in rows:
        row.revoked_at = now
    if rows:
        db.commit()
    return len(rows)


def clear_session_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(settings.session_cookie_name, path="/")
