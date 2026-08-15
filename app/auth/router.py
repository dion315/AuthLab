"""Sign-in, sign-out, and IdP callback routes.

Three ways in, all landing on the same session:

  * local password  — always available, never blocked by an IdP or a policy
  * OIDC            — /auth/oidc/{slug}/login
  * SAML            — /auth/saml/{slug}/login  (and IdP-initiated POST to /acs)

Failures render a page that shows what the IdP actually said. That is not
politeness — when you are testing Conditional Access, the denial *is* the
result, and burying it in a stack trace throws away the answer.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import events
from app.auth import connections as conn
from app.auth import flowstate, oidc, saml
from app.auth.rolemap import resolve_role
from app.config import get_settings
from app.db import get_db
from app.deps import current_session
from app.models import LocalUser, UserSession
from app.ratelimit import check as ratelimit_check
from app.ratelimit import record_failure, reset
from app.security import (
    clear_session_cookie,
    client_ip,
    create_session,
    hash_password,
    needs_rehash,
    revoke_session,
    verify_password,
)
from app.templating import templates

router = APIRouter()


def _login_error(
    request: Request,
    *,
    title: str,
    message: str,
    detail: dict[str, Any] | None = None,
    status_code: int = status.HTTP_400_BAD_REQUEST,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "auth_error.html",
        {"title": title, "message": message, "detail": detail or {}},
        status_code=status_code,
    )


# --- sign-in page ------------------------------------------------------------


@router.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession | None = Depends(current_session),
) -> Response:
    if session is not None:
        return RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    has_local = db.execute(select(LocalUser).limit(1)).scalar_one_or_none() is not None
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "connections": conn.list_enabled(db),
            "has_local": has_local,
            "error": request.query_params.get("error", ""),
        },
    )


# --- local account -----------------------------------------------------------


@router.post("/auth/local/login")
def local_login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
) -> Response:
    email = email.strip().lower()
    throttle_key = f"{client_ip(request)}|{email}"

    allowed, retry_in = ratelimit_check(throttle_key)
    if not allowed:
        events.record(
            db,
            kind="login_failure",
            outcome="denied",
            summary="Local sign-in throttled",
            request=request,
            subject=email,
            protocol="local",
            detail={"retry_in_seconds": retry_in},
        )
        return _login_error(
            request,
            title="Too many attempts",
            message=f"Too many failed sign-in attempts. Try again in {retry_in} seconds.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    user = db.execute(select(LocalUser).where(LocalUser.email == email)).scalar_one_or_none()

    # Verify even when the account is missing, so a wrong username and a wrong
    # password take the same amount of time and cannot be told apart.
    stored_hash = user.password_hash if user else hash_password("no-such-user")
    password_ok = verify_password(password, stored_hash)

    if user is None or not password_ok or not user.is_active:
        record_failure(throttle_key)
        events.record(
            db,
            kind="login_failure",
            outcome="denied",
            summary="Local sign-in failed",
            request=request,
            subject=email,
            protocol="local",
            detail={"reason": "invalid credentials or inactive account"},
        )
        return _login_error(
            request,
            title="Sign-in failed",
            message="That email and password combination was not accepted.",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    reset(throttle_key)

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    user.last_login_at = datetime.now(UTC)
    db.commit()

    response = RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    create_session(
        db,
        response,
        subject=user.email,
        email=user.email,
        display_name=user.display_name or user.email,
        role=user.role,
        source="local",
        protocol="local",
        raw_claims={
            "note": "Local account. No identity provider was involved in this sign-in.",
            "email": user.email,
            "role": user.role,
        },
        request=request,
    )
    events.record(
        db,
        kind="login_success",
        outcome="ok",
        summary="Local sign-in",
        request=request,
        subject=user.email,
        protocol="local",
    )
    return response


# --- OIDC --------------------------------------------------------------------


@router.get("/auth/oidc/{slug}/login")
async def oidc_login(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    connection = conn.get_by_slug(db, slug)
    if connection is None or connection.protocol != "oidc" or not connection.enabled:
        return _login_error(
            request,
            title="Unknown connection",
            message=f"No enabled OIDC connection named '{slug}'.",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # Optional per-attempt overrides, used by the "test step-up" buttons on the
    # dashboard: /auth/oidc/{slug}/login?prompt=login&acr_values=mfa
    extra_prompt = request.query_params.get("prompt", "")
    extra_acr = request.query_params.get("acr_values", "")

    try:
        url, flow = await oidc.build_authorization_request(
            connection, extra_prompt=extra_prompt, extra_acr=extra_acr
        )
    except oidc.OidcError as exc:
        # Caught, not raised: a bad issuer is a configuration mistake to be
        # reported, not a reason to take the process down.
        events.record(
            db,
            kind="login_failure",
            outcome="error",
            summary=exc.message,
            request=request,
            connection_slug=slug,
            protocol="oidc",
            detail=exc.detail,
        )
        return _login_error(
            request,
            title="Could not start sign-in",
            message=exc.message,
            detail=exc.detail,
            status_code=status.HTTP_502_BAD_GATEWAY,
        )

    events.record(
        db,
        kind="login_start",
        summary="Redirecting to OIDC provider",
        request=request,
        connection_slug=slug,
        protocol="oidc",
        detail={"prompt": extra_prompt, "acr_values": extra_acr},
    )

    response = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
    flowstate.set_flow(response, "oidc", slug, flow)
    return response


@router.get("/auth/oidc/{slug}/callback")
async def oidc_callback(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    connection = conn.get_by_slug(db, slug)
    if connection is None or connection.protocol != "oidc":
        return _login_error(
            request,
            title="Unknown connection",
            message=f"No OIDC connection named '{slug}'.",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    params = dict(request.query_params)

    # The IdP reports a denial here, by redirecting back with an error rather
    # than a code. Conditional Access blocks land in this branch.
    if "error" in params:
        detail = {
            "error": params.get("error", ""),
            "error_description": params.get("error_description", ""),
            "error_uri": params.get("error_uri", ""),
        }
        events.record(
            db,
            kind="login_failure",
            outcome="denied",
            summary=f"IdP returned error: {params.get('error', '')}",
            request=request,
            connection_slug=slug,
            protocol="oidc",
            detail=detail,
        )
        return _login_error(
            request,
            title="The identity provider denied this sign-in",
            message=(
                params.get("error_description")
                or "The provider returned an error instead of an authorization code."
            ),
            detail=detail,
            status_code=status.HTTP_403_FORBIDDEN,
        )

    flow = flowstate.read_flow(request, "oidc", slug)
    if not flow:
        return _login_error(
            request,
            title="Login session expired",
            message=(
                "The state cookie for this sign-in is missing or expired. "
                "Start again from the sign-in page."
            ),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    returned_state = params.get("state", "")
    if not returned_state or returned_state != flow.get("state"):
        events.record(
            db,
            kind="login_failure",
            outcome="error",
            summary="OIDC state mismatch",
            request=request,
            connection_slug=slug,
            protocol="oidc",
        )
        return _login_error(
            request,
            title="State mismatch",
            message=(
                "The state value returned by the provider does not match the one "
                "we issued. This request was rejected."
            ),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    code = params.get("code", "")
    if not code:
        return _login_error(
            request,
            title="No authorization code",
            message="The provider redirected back without an authorization code.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    try:
        tokens = await oidc.exchange_code(
            connection, code=code, code_verifier=flow.get("code_verifier")
        )
        id_token = tokens.get("id_token", "")
        if not id_token:
            raise oidc.OidcError(
                "The token response contained no id_token. Check that 'openid' "
                "is included in the configured scopes.",
                detail={"token_response_keys": sorted(tokens.keys())},
            )
        claims = await oidc.validate_id_token(
            connection, id_token=id_token, nonce=flow.get("nonce", "")
        )
        if tokens.get("access_token"):
            # Merge userinfo under any claim the ID token did not already
            # carry — some providers only expose groups there.
            for key, value in (await oidc.fetch_userinfo(connection, tokens["access_token"])).items():
                claims.setdefault(key, value)
    except oidc.OidcError as exc:
        events.record(
            db,
            kind="login_failure",
            outcome="denied" if exc.code else "error",
            summary=exc.message,
            request=request,
            connection_slug=slug,
            protocol="oidc",
            detail={"code": exc.code, "description": exc.description, **exc.detail},
        )
        return _login_error(
            request,
            title="Sign-in could not be completed",
            message=exc.description or exc.message,
            detail={"error": exc.code, **exc.detail} if exc.code else exc.detail,
            status_code=status.HTTP_403_FORBIDDEN if exc.code else status.HTTP_502_BAD_GATEWAY,
        )

    role, trace = resolve_role(connection, claims)
    subject = str(claims.get(connection.subject_claim) or claims.get("sub") or "")
    email = str(claims.get(connection.email_claim) or claims.get("preferred_username") or "")
    display = str(claims.get(connection.name_claim) or email or subject)

    response = RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    flowstate.clear_flow(response, "oidc", slug)
    create_session(
        db,
        response,
        subject=subject,
        email=email,
        display_name=display,
        role=role,
        source=slug,
        protocol="oidc",
        raw_claims=claims,
        request=request,
        id_token=id_token,
    )
    events.record(
        db,
        kind="login_success",
        outcome="ok",
        summary=f"OIDC sign-in via {connection.name}",
        request=request,
        connection_slug=slug,
        protocol="oidc",
        subject=subject or email,
        detail={"role": role, "role_trace": trace},
    )
    return response


# --- SAML --------------------------------------------------------------------
#
# These handlers are sync `def` on purpose: python3-saml is synchronous and
# CPU-bound, so Starlette runs them in a worker thread instead of blocking the
# event loop.


def _saml_request_data(request: Request, form: dict[str, str] | None = None) -> dict[str, Any]:
    return saml.build_request_dict(
        url=str(request.url),
        query_params=dict(request.query_params),
        form_data=form or {},
    )


@router.get("/auth/saml/{slug}/login")
def saml_login(slug: str, request: Request, db: Session = Depends(get_db)) -> Response:
    connection = conn.get_by_slug(db, slug)
    if connection is None or connection.protocol != "saml" or not connection.enabled:
        return _login_error(
            request,
            title="Unknown connection",
            message=f"No enabled SAML connection named '{slug}'.",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    force = request.query_params.get("force_authn", "").lower() in ("1", "true", "yes")

    try:
        url, request_id = saml.build_login_url(
            connection, _saml_request_data(request), force_authn=force or None
        )
    except saml.SamlError as exc:
        events.record(
            db,
            kind="login_failure",
            outcome="error",
            summary=exc.message,
            request=request,
            connection_slug=slug,
            protocol="saml",
            detail=exc.detail,
        )
        return _login_error(
            request,
            title="Could not start SAML sign-in",
            message=exc.message,
            detail=exc.detail,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    events.record(
        db,
        kind="login_start",
        summary="Redirecting to SAML IdP",
        request=request,
        connection_slug=slug,
        protocol="saml",
        detail={"request_id": request_id, "force_authn": force},
    )

    response = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
    # Carried so InResponseTo can be checked when the assertion comes back.
    flowstate.set_flow(response, "saml", slug, {"request_id": request_id})
    return response


@router.post("/auth/saml/{slug}/acs")
async def saml_acs(slug: str, request: Request, db: Session = Depends(get_db)) -> Response:
    """Assertion Consumer Service — the IdP POSTs the SAML Response here.

    The body is application/x-www-form-urlencoded, which is why this reads
    `await request.form()` rather than a JSON body.
    """
    connection = conn.get_by_slug(db, slug)
    if connection is None or connection.protocol != "saml":
        return _login_error(
            request,
            title="Unknown connection",
            message=f"No SAML connection named '{slug}'.",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    form = {key: str(value) for key, value in (await request.form()).items()}
    if "SAMLResponse" not in form:
        return _login_error(
            request,
            title="Not a SAML response",
            message="This endpoint expects a form POST containing a SAMLResponse field.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    flow = flowstate.read_flow(request, "saml", slug)
    request_id = (flow or {}).get("request_id")

    from starlette.concurrency import run_in_threadpool

    try:
        claims = await run_in_threadpool(
            saml.process_response,
            connection,
            _saml_request_data(request, form),
            request_id=request_id,
        )
    except saml.SamlError as exc:
        events.record(
            db,
            kind="login_failure",
            outcome="denied",
            summary=exc.message,
            request=request,
            connection_slug=slug,
            protocol="saml",
            detail=exc.detail,
        )
        return _login_error(
            request,
            title="SAML assertion rejected",
            message=exc.message,
            detail=exc.detail,
            status_code=status.HTTP_403_FORBIDDEN,
        )

    role, trace = resolve_role(connection, claims)
    subject = str(claims.get(connection.subject_claim) or claims.get("nameId") or "")
    email = str(claims.get(connection.email_claim) or subject)
    display = str(claims.get(connection.name_claim) or email or subject)

    response = RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    flowstate.clear_flow(response, "saml", slug)
    create_session(
        db,
        response,
        subject=subject,
        email=email,
        display_name=display,
        role=role,
        source=slug,
        protocol="saml",
        raw_claims=claims,
        request=request,
        name_id=str(claims.get("nameId", "")),
        session_index=str(claims.get("sessionIndex", "")),
    )
    events.record(
        db,
        kind="login_success",
        outcome="ok",
        summary=f"SAML sign-in via {connection.name}",
        request=request,
        connection_slug=slug,
        protocol="saml",
        subject=subject or email,
        detail={"role": role, "role_trace": trace},
    )
    return response


@router.get("/auth/saml/{slug}/metadata")
def saml_metadata(slug: str, request: Request, db: Session = Depends(get_db)) -> Response:
    """SP metadata XML for import into the IdP.

    Most consoles accept this file and fill in entity ID, ACS URL, and NameID
    format themselves, which removes the fiddliest part of SAML setup.
    """
    connection = conn.get_by_slug(db, slug)
    if connection is None or connection.protocol != "saml":
        return _login_error(
            request,
            title="Unknown connection",
            message=f"No SAML connection named '{slug}'.",
            status_code=status.HTTP_404_NOT_FOUND,
        )
    try:
        xml = saml.build_metadata(connection)
    except saml.SamlError as exc:
        return _login_error(
            request,
            title="Could not generate metadata",
            message=exc.message,
            detail=exc.detail,
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return Response(content=xml, media_type="application/samlmetadata+xml")


# --- sign-out ----------------------------------------------------------------


@router.post("/logout")
async def logout(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession | None = Depends(current_session),
    federated: str = Form(default=""),
) -> Response:
    if session is None:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)

    target = "/login"

    # Federated sign-out ends the session at the IdP too. Without it the next
    # sign-in completes silently and you cannot retest a policy change.
    if federated and session.protocol == "oidc":
        connection = conn.get_by_slug(db, session.source)
        if connection is not None:
            url = await oidc.end_session_url(connection, id_token_hint=session.id_token)
            if url:
                target = url
    elif federated and session.protocol == "saml":
        connection = conn.get_by_slug(db, session.source)
        if connection is not None:
            try:
                url = saml.build_logout_url(
                    connection,
                    _saml_request_data(request),
                    name_id=session.name_id,
                    session_index=session.session_index,
                )
                if url:
                    target = url
            except saml.SamlError:
                # A missing SLO endpoint should not prevent local sign-out.
                pass

    events.record(
        db,
        kind="logout",
        outcome="ok",
        summary="Federated sign-out" if target != "/login" else "Local sign-out",
        request=request,
        connection_slug=session.source,
        protocol=session.protocol,
        subject=session.subject,
    )
    revoke_session(db, session.id)

    response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    clear_session_cookie(response)
    return response


# --- helper used by the admin UI --------------------------------------------


def bootstrap_local_admin(db: Session) -> tuple[str, str] | None:
    """Create the first local account if none exists.

    Returns (email, generated_password) when a password was generated, so the
    caller can print it once at startup. Returns None if an account already
    existed or the password came from configuration.
    """
    import secrets as _secrets

    existing = db.execute(select(LocalUser).limit(1)).scalar_one_or_none()
    if existing is not None:
        return None

    settings = get_settings()
    generated = ""
    password = settings.bootstrap_admin_password
    if not password:
        generated = _secrets.token_urlsafe(18)
        password = generated

    user = LocalUser(
        email=settings.bootstrap_admin_email.strip().lower(),
        display_name="Local administrator",
        password_hash=hash_password(password),
        role="admin",
        is_active=True,
        must_change_password=bool(generated),
    )
    db.add(user)
    db.commit()

    return (user.email, generated) if generated else None
