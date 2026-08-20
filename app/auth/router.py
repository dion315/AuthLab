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

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import events
from app.auth import connections as conn
from app.auth import expectations, flowstate, oidc, saml, scimlink
from app.auth.rolemap import resolve_role
from app.config import get_settings
from app.db import get_db
from app.deps import current_session
from app.models import (
    PASSWORD_SOURCE_ENV,
    PASSWORD_SOURCE_GENERATED,
    PASSWORD_SOURCE_USER,
    PASSWORD_SOURCES,
    LocalUser,
    UserSession,
)
from app.ratelimit import check as ratelimit_check
from app.ratelimit import record_failure, reset
from app.redirects import safe_path
from app.security import (
    clear_session_cookie,
    client_ip,
    create_session,
    hash_password,
    needs_rehash,
    revoke_session,
    revoke_sessions_for_user,
    verify_password,
)
from app.templating import templates

router = APIRouter()


def _post_login_role(
    db: Session, connection: Any, claims: dict[str, Any]
) -> tuple[str, list[dict[str, Any]], list[str]]:
    """Resolve the role for a fresh sign-in, including SCIM group membership.

    The SCIM lookup happens here rather than inside `resolve_role` so that the
    rule engine stays a pure function of its inputs. Identifiers come from the
    claims because there is no session yet to read them from.
    """
    scim_groups: list[str] = []
    if (connection.role_source or "claims") != "claims":
        identifiers = [
            str(claims.get(connection.subject_claim) or ""),
            str(claims.get(connection.email_claim) or ""),
            str(claims.get("preferred_username") or ""),
            str(claims.get("upn") or ""),
        ]
        scim_groups = scimlink.group_names(scimlink.find_scim_user(db, *identifiers))

    role, trace = resolve_role(connection, claims, scim_groups)
    return role, trace, scim_groups


def _record_expectations(
    connection: Any, claims: dict[str, Any], role: str
) -> tuple[dict[str, Any], str]:
    """Evaluate a connection's expectations and produce a log-friendly summary."""
    result = expectations.evaluate(connection, claims, role)
    return result, expectations.summarise(result)


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
    extra_claims = request.query_params.get("claims", "")
    raw_max_age = request.query_params.get("max_age", "")
    extra_max_age = int(raw_max_age) if raw_max_age.isdigit() else None

    # Where to land after the round trip. Validated as a local path before it
    # goes anywhere near a cookie, because this is a sign-in endpoint and an
    # open redirect here is worth more to an attacker than almost anywhere else.
    return_to = safe_path(request.query_params.get("return_to"))

    try:
        url, flow = await oidc.build_authorization_request(
            connection,
            extra_prompt=extra_prompt,
            extra_acr=extra_acr,
            extra_claims=extra_claims,
            extra_max_age=extra_max_age,
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
        detail={
            "prompt": extra_prompt,
            "acr_values": extra_acr,
            "claims_challenge": bool(extra_claims),
            "max_age": extra_max_age,
        },
    )

    flow["return_to"] = return_to
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

    role, trace, scim_groups = _post_login_role(db, connection, claims)
    subject = str(claims.get(connection.subject_claim) or claims.get("sub") or "")
    email = str(claims.get(connection.email_claim) or claims.get("preferred_username") or "")
    display = str(claims.get(connection.name_claim) or email or subject)
    checks, checks_summary = _record_expectations(connection, claims, role)

    target = safe_path(flow.get("return_to"))
    response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
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
        # A sign-in that completed but failed its expectations is not a success
        # worth glossing over — the activity log should show it in red.
        outcome="ok" if checks.get("passed") is not False else "denied",
        summary=" · ".join(
            part
            for part in (f"OIDC sign-in via {connection.name}", checks_summary)
            if part
        ),
        request=request,
        connection_slug=slug,
        protocol="oidc",
        subject=subject or email,
        detail={
            "role": role,
            "role_trace": trace,
            "scim_groups": scim_groups,
            "expectations": checks,
        },
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
    return_to = safe_path(request.query_params.get("return_to"))

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
    flowstate.set_flow(
        response, "saml", slug, {"request_id": request_id, "return_to": return_to}
    )
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

    role, trace, scim_groups = _post_login_role(db, connection, claims)
    subject = str(claims.get(connection.subject_claim) or claims.get("nameId") or "")
    email = str(claims.get(connection.email_claim) or subject)
    display = str(claims.get(connection.name_claim) or email or subject)
    checks, checks_summary = _record_expectations(connection, claims, role)

    target = safe_path((flow or {}).get("return_to"))
    response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
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
        outcome="ok" if checks.get("passed") is not False else "denied",
        summary=" · ".join(
            part
            for part in (f"SAML sign-in via {connection.name}", checks_summary)
            if part
        ),
        request=request,
        connection_slug=slug,
        protocol="saml",
        subject=subject or email,
        detail={
            "role": role,
            "role_trace": trace,
            "scim_groups": scim_groups,
            "expectations": checks,
        },
    )
    return response


@router.api_route("/auth/saml/{slug}/sls", methods=["GET", "POST"])
async def saml_sls(slug: str, request: Request, db: Session = Depends(get_db)) -> Response:
    """Single Logout Service — the other half of SAML sign-out.

    The SP metadata has always advertised this endpoint, and until now nothing
    was listening on it. Two different messages arrive here:

      * a **LogoutResponse**, answering a LogoutRequest we sent. Without an
        endpoint to receive it, SP-initiated SLO ended at the IdP and the user
        landed on a 404 — the logout worked, but looked broken and gave no
        confirmation that the provider had actually ended its session.
      * a **LogoutRequest**, when the user signed out at the IdP or at another
        application and the provider is propagating that to us. Handling this
        is what makes single logout single: it lets an IdP-side sign-out
        actually terminate access here.

    Accepts both bindings. The redirect binding puts the message in the query
    string; some providers use POST instead.
    """
    connection = conn.get_by_slug(db, slug)
    if connection is None or connection.protocol != "saml":
        return _login_error(
            request,
            title="Unknown connection",
            message=f"No SAML connection named '{slug}'.",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    form: dict[str, str] = {}
    if request.method == "POST":
        form = {key: str(value) for key, value in (await request.form()).items()}

    # python3-saml reads both message types out of get_data, so a POST binding
    # message has to be presented there too.
    request_data = _saml_request_data(request, form)
    if form:
        merged = dict(request_data["get_data"])
        merged.update(form)
        request_data["get_data"] = merged

    if not (request_data["get_data"].get("SAMLRequest") or request_data["get_data"].get("SAMLResponse")):
        return _login_error(
            request,
            title="Not a SAML logout message",
            message=(
                "This endpoint expects a SAMLRequest or SAMLResponse parameter. "
                "It is the Single Logout Service listed in this connection's SP "
                "metadata."
            ),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    session = current_session(request, db)
    flow = flowstate.read_flow(request, "saml-slo", slug)
    request_id = (flow or {}).get("request_id")

    from starlette.concurrency import run_in_threadpool

    try:
        redirect_url, name_id = await run_in_threadpool(
            saml.process_logout, connection, request_data, request_id=request_id
        )
    except saml.SamlError as exc:
        events.record(
            db,
            kind="logout",
            outcome="error",
            summary=exc.message,
            request=request,
            connection_slug=slug,
            protocol="saml",
            detail=exc.detail,
        )
        return _login_error(
            request,
            title="SAML logout message rejected",
            message=exc.message,
            detail=exc.detail,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    revoked = 0
    if session is not None:
        revoke_session(db, session.id)
        revoked = 1
    if name_id:
        # IdP-initiated: the browser carrying the LogoutRequest may not be the
        # one holding our cookie, so revoke by identity as well.
        revoked += revoke_sessions_for_user(db, name_id)

    events.record(
        db,
        kind="logout",
        outcome="ok",
        summary=(
            f"IdP-initiated single logout; revoked {revoked} session(s)"
            if name_id
            else "Single logout completed at the provider"
        ),
        request=request,
        connection_slug=slug,
        protocol="saml",
        subject=name_id or (session.subject if session else ""),
        detail={"sessions_revoked": revoked, "idp_initiated": bool(name_id)},
    )

    # For a LogoutRequest, redirect_url carries our signed LogoutResponse back
    # to the IdP. For a LogoutResponse there is nothing left to send.
    target = redirect_url or "/login?message=Signed+out+everywhere"
    response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    flowstate.clear_flow(response, "saml-slo", slug)
    clear_session_cookie(response)
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
    slo_request_id = ""
    slo_slug = session.source

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
                url, slo_request_id = saml.build_logout_url(
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
    if slo_request_id:
        # Held so the LogoutResponse arriving at /sls can be matched to the
        # LogoutRequest we just sent, exactly as InResponseTo is validated for
        # sign-in.
        flowstate.set_flow(
            response, "saml-slo", slo_slug, {"request_id": slo_request_id}
        )
    clear_session_cookie(response)
    return response


# --- helper used by the admin UI --------------------------------------------


@dataclass(frozen=True)
class AdminPasswordState:
    """What startup did with the local administrator password.

    `password` is populated only when the app knows the plaintext — which is
    exactly when it just set it. A stored password is an Argon2 hash and cannot
    be recovered, so an account whose password somebody chose can never be
    reported here, only described.
    """

    email: str
    source: str
    password: str = ""
    created: bool = False
    changed: bool = False


def _effective_source(user: LocalUser) -> str:
    """The password source, inferring it for rows written before the column.

    A database upgraded from an earlier version has no value here. Rather than
    guess, infer from the flag that used to carry the same meaning:
    `must_change_password` was set only for an app-generated password.
    """
    if user.password_source in PASSWORD_SOURCES:
        return user.password_source
    return PASSWORD_SOURCE_GENERATED if user.must_change_password else PASSWORD_SOURCE_USER


def sync_local_admin(db: Session) -> AdminPasswordState:
    """Reconcile the local administrator account with the environment.

    Runs on every start, not just the first, because the environment is meant
    to be declarative: if `BOOTSTRAP_ADMIN_PASSWORD` says what the password is,
    then that is what it is, and editing `.env` and restarting is a supported
    way to get back in.

    Three outcomes, one per password source:

      * **A password is configured.** It is applied — created on first run, and
        reapplied later if the stored hash no longer matches, which is how an
        edited `.env` takes effect. The value is never logged: it is already in
        a file the operator controls, and putting it in the log would only
        widen where it exists.

      * **No password is configured.** The app issues one and the caller prints
        it. It is reissued on *every* start, so missing the banner in a wall of
        container output costs a restart rather than the account.

      * **Somebody chose the password.** Startup leaves it alone. Overwriting a
        deliberately chosen password because a service restarted would be a
        genuinely bad surprise, and there is no way to display it anyway.
    """
    import secrets as _secrets

    settings = get_settings()
    email = settings.bootstrap_admin_email.strip().lower()
    configured = settings.bootstrap_admin_password

    user = db.execute(
        select(LocalUser).where(func.lower(LocalUser.email) == email)
    ).scalar_one_or_none()

    # An existing deployment may have its administrator under a different
    # address; only fall back to "any admin" when the configured one is absent,
    # so the two never end up fighting over the same account.
    if user is None:
        user = db.execute(
            select(LocalUser).where(LocalUser.role == "admin").limit(1)
        ).scalar_one_or_none()

    if user is None:
        password = configured or _secrets.token_urlsafe(18)
        source = PASSWORD_SOURCE_ENV if configured else PASSWORD_SOURCE_GENERATED
        user = LocalUser(
            email=email,
            display_name="Local administrator",
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
            # Never forced: a configured password is the operator's decision,
            # and a generated one is reprinted every start, so demanding a
            # change would be undone by the next restart.
            must_change_password=False,
            password_source=source,
        )
        db.add(user)
        db.commit()
        return AdminPasswordState(
            email=user.email,
            source=source,
            password="" if configured else password,
            created=True,
        )

    source = _effective_source(user)

    if configured:
        if verify_password(configured, user.password_hash):
            # Already matches; nothing to write.
            if user.password_source != PASSWORD_SOURCE_ENV:
                user.password_source = PASSWORD_SOURCE_ENV
                db.commit()
            return AdminPasswordState(email=user.email, source=PASSWORD_SOURCE_ENV)

        user.password_hash = hash_password(configured)
        user.password_source = PASSWORD_SOURCE_ENV
        user.must_change_password = False
        # A configured password is no use if the account it belongs to is
        # disabled, and the whole point of this account is being able to get in.
        user.is_active = True
        db.commit()
        return AdminPasswordState(
            email=user.email, source=PASSWORD_SOURCE_ENV, changed=True
        )

    if source == PASSWORD_SOURCE_USER:
        return AdminPasswordState(email=user.email, source=PASSWORD_SOURCE_USER)

    # No password configured and the current one is app-managed: issue a fresh
    # one so the banner below is always the password that actually works.
    password = _secrets.token_urlsafe(18)
    user.password_hash = hash_password(password)
    user.password_source = PASSWORD_SOURCE_GENERATED
    user.must_change_password = False
    user.is_active = True
    db.commit()
    return AdminPasswordState(
        email=user.email,
        source=PASSWORD_SOURCE_GENERATED,
        password=password,
        changed=True,
    )
