"""Admin console — runtime configuration of IdPs, SCIM, and local accounts.

This is the reason the local account exists. Everything an operator needs to
stand up an OIDC or SAML connection, mint a provisioning token, and watch what
arrives is here, editable without a redeploy. Being able to change an issuer or
a role rule and immediately retry a sign-in is the difference between a useful
harness and a sample app.

Cross-site request forgery is handled by the session cookie's SameSite=Lax
attribute: a cross-origin POST does not carry the cookie, so it cannot reach
any of these routes authenticated.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import events
from app.auth import apitoken, oidc, saml
from app.auth import connections as conn
from app.auth import expectations as expectation_engine
from app.auth.schemas import SETTINGS_MODELS
from app.config import get_settings
from app.db import get_db
from app.deps import require_role
from app.models import (
    API_SCOPES,
    ROLE_SOURCES,
    ROLES,
    ApiToken,
    IdpConnection,
    LocalUser,
    ScimClient,
    ScimGroup,
    ScimUser,
    UserSession,
)
from app.security import generate_token, hash_password, hash_token, revoke_session
from app.templating import templates

router = APIRouter()

admin_only = require_role("admin")
admin_or_power = require_role("admin", "power")

_SLUG_RE = re.compile(r"[^a-z0-9-]+")


def _slugify(value: str) -> str:
    slug = _SLUG_RE.sub("-", value.strip().lower()).strip("-")
    return slug or "connection"


def _redirect(path: str, message: str = "", error: str = "") -> RedirectResponse:
    # Percent-encode the values: these strings contain slugs, quotes, and
    # provider error text, any of which would otherwise produce a malformed
    # Location header that some clients refuse to follow.
    params = {key: value for key, value in (("message", message), ("error", error)) if value}
    suffix = ("?" + urlencode(params)) if params else ""
    return RedirectResponse(path + suffix, status_code=status.HTTP_303_SEE_OTHER)


def _form_bool(form: Any, key: str) -> bool:
    return form.get(key) in ("on", "true", "1", "yes")


def _parse_role_rules(form: Any) -> list[dict[str, str]]:
    operators = form.getlist("rule_operator")
    values = form.getlist("rule_value")
    roles = form.getlist("rule_role")
    rules: list[dict[str, str]] = []
    for operator, value, role in zip(operators, values, roles, strict=False):
        if not value.strip():
            continue
        rules.append(
            {"operator": operator, "value": value.strip(), "role": role}
        )
    return rules


def _parse_expectations(form: Any) -> list[dict[str, str]]:
    """Read the expectation rows off the connection form.

    An expectation with no claim name asserts nothing, so blank rows are
    dropped rather than stored — the form always renders one empty row for
    adding the next one.
    """
    claims = form.getlist("expect_claim")
    operators = form.getlist("expect_operator")
    values = form.getlist("expect_value")
    descriptions = form.getlist("expect_description")

    parsed: list[dict[str, str]] = []
    for claim, operator, value, description in zip(
        claims, operators, values, descriptions, strict=False
    ):
        if not claim.strip():
            continue
        parsed.append(
            {
                "claim": claim.strip(),
                "operator": operator,
                "value": value.strip(),
                "description": description.strip(),
            }
        )
    return parsed


def _apply_assertion_fields(connection: IdpConnection, form: Any) -> None:
    """Expectation and step-up settings, shared by create and update."""
    role_source = str(form.get("role_source", "claims"))
    connection.role_source = role_source if role_source in ROLE_SOURCES else "claims"

    expected_role = str(form.get("expected_role", "")).strip()
    connection.expected_role = expected_role if expected_role in ROLES else ""
    connection.expectations = _parse_expectations(form)

    connection.stepup_claim = str(form.get("stepup_claim", "amr")).strip() or "amr"
    stepup_operator = str(form.get("stepup_operator", "contains")).strip()
    connection.stepup_operator = (
        stepup_operator if stepup_operator in expectation_engine.OPERATORS else "contains"
    )
    connection.stepup_value = str(form.get("stepup_value", "")).strip()
    connection.stepup_acr_values = str(form.get("stepup_acr_values", "")).strip()
    connection.stepup_claims_challenge = str(form.get("stepup_claims_challenge", "")).strip()


# --- overview ----------------------------------------------------------------


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
def overview(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_or_power),
) -> Response:
    return templates.TemplateResponse(
        request,
        "admin/overview.html",
        {
            "session": session,
            "read_only": session.role != "admin",
            "connections": conn.list_all(db),
            "scim_clients": list(db.execute(select(ScimClient)).scalars().all()),
            "user_count": db.execute(select(func.count()).select_from(ScimUser)).scalar_one(),
            "group_count": db.execute(select(func.count()).select_from(ScimGroup)).scalar_one(),
            "scim_base_url": conn.scim_base_url(),
            "recent_events": events.recent(db, limit=10),
        },
    )


# --- IdP connections ---------------------------------------------------------


@router.get("/connections/new", response_class=HTMLResponse)
def new_connection_form(
    request: Request,
    protocol: str = "oidc",
    session: UserSession = Depends(admin_only),
) -> Response:
    if protocol not in SETTINGS_MODELS:
        protocol = "oidc"
    model = SETTINGS_MODELS[protocol]
    return templates.TemplateResponse(
        request,
        "admin/connection_form.html",
        {
            "session": session,
            "connection": None,
            "protocol": protocol,
            "config": model().model_dump(),
            "role_rules": [],
            "roles": ROLES,
            "role_sources": ROLE_SOURCES,
            "expectation_operators": expectation_engine.OPERATORS,
            "urls": {},
            "errors": [],
        },
    )


@router.post("/connections")
async def create_connection(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    form = await request.form()
    protocol = str(form.get("protocol", "oidc"))
    if protocol not in SETTINGS_MODELS:
        return _redirect("/admin/connections/new", error="Unknown protocol")

    name = str(form.get("name", "")).strip() or "New connection"
    slug = _slugify(str(form.get("slug", "")) or name)

    if conn.get_by_slug(db, slug) is not None:
        return _redirect(
            "/admin/connections/new",
            error=f"A connection with the slug '{slug}' already exists",
        )

    connection = IdpConnection(
        slug=slug,
        name=name,
        protocol=protocol,
        enabled=_form_bool(form, "enabled"),
        role_claim=str(form.get("role_claim", "roles")).strip() or "roles",
        default_role=str(form.get("default_role", "user")),
        subject_claim=str(form.get("subject_claim", "sub")).strip() or "sub",
        email_claim=str(form.get("email_claim", "email")).strip() or "email",
        name_claim=str(form.get("name_claim", "name")).strip() or "name",
        role_rules=_parse_role_rules(form),
        config={},
    )

    config_data = _extract_config(form, protocol)
    errors = conn.validate_config(protocol, config_data)
    if errors:
        return _redirect("/admin/connections/new", error="; ".join(errors))

    _apply_assertion_fields(connection, form)
    conn.store_settings(connection, config_data)
    db.add(connection)
    db.commit()

    events.record(
        db,
        kind="config_change",
        outcome="ok",
        summary=f"Created {protocol.upper()} connection '{name}'",
        request=request,
        subject=session.email,
        connection_slug=slug,
    )
    return _redirect(f"/admin/connections/{connection.id}", message="Connection created")


@router.get("/connections/{connection_id}", response_class=HTMLResponse)
def edit_connection_form(
    connection_id: str,
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    connection = db.get(IdpConnection, connection_id)
    if connection is None:
        return _redirect("/admin", error="Connection not found")

    urls = {
        "redirect_uri": conn.redirect_uri(connection.slug),
        "acs_url": conn.acs_url(connection.slug),
        "sls_url": conn.sls_url(connection.slug),
        "export_url": f"/admin/connections/{connection.id}/export",
        "metadata_url": conn.metadata_url(connection.slug),
        "login_url": f"/auth/{connection.protocol}/{connection.slug}/login",
    }

    return templates.TemplateResponse(
        request,
        "admin/connection_form.html",
        {
            "session": session,
            "connection": connection,
            "protocol": connection.protocol,
            "config": conn.redacted_config(connection),
            "role_rules": connection.role_rules or [],
            "roles": ROLES,
            "role_sources": ROLE_SOURCES,
            "expectation_operators": expectation_engine.OPERATORS,
            "urls": urls,
            "errors": [],
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
        },
    )


@router.post("/connections/{connection_id}")
async def update_connection(
    connection_id: str,
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    connection = db.get(IdpConnection, connection_id)
    if connection is None:
        return _redirect("/admin", error="Connection not found")

    form = await request.form()
    connection.name = str(form.get("name", connection.name)).strip() or connection.name
    connection.enabled = _form_bool(form, "enabled")
    connection.role_claim = str(form.get("role_claim", connection.role_claim)).strip()
    connection.default_role = str(form.get("default_role", connection.default_role))
    connection.subject_claim = str(form.get("subject_claim", connection.subject_claim)).strip()
    connection.email_claim = str(form.get("email_claim", connection.email_claim)).strip()
    connection.name_claim = str(form.get("name_claim", connection.name_claim)).strip()
    connection.role_rules = _parse_role_rules(form)
    _apply_assertion_fields(connection, form)

    config_data = _extract_config(form, connection.protocol)
    errors = conn.validate_config(connection.protocol, config_data)
    if errors:
        return _redirect(f"/admin/connections/{connection_id}", error="; ".join(errors))

    conn.store_settings(connection, config_data)
    db.commit()

    # Discovery documents are cached; a changed issuer must not keep using the
    # old one.
    oidc.invalidate_cache()

    events.record(
        db,
        kind="config_change",
        outcome="ok",
        summary=f"Updated connection '{connection.name}'",
        request=request,
        subject=session.email,
        connection_slug=connection.slug,
    )
    return _redirect(f"/admin/connections/{connection_id}", message="Saved")


@router.post("/connections/{connection_id}/delete")
def delete_connection(
    connection_id: str,
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    connection = db.get(IdpConnection, connection_id)
    if connection is None:
        return _redirect("/admin", error="Connection not found")
    name = connection.name
    slug = connection.slug
    db.delete(connection)
    db.commit()
    oidc.invalidate_cache()
    events.record(
        db,
        kind="config_change",
        outcome="ok",
        summary=f"Deleted connection '{name}'",
        request=request,
        subject=session.email,
        connection_slug=slug,
    )
    return _redirect("/admin", message="Connection deleted")


@router.post("/connections/{connection_id}/test", response_class=HTMLResponse)
async def test_connection(
    connection_id: str,
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    """Check a connection without performing a sign-in.

    For OIDC this fetches the discovery document and reports which endpoints
    the provider advertises; for SAML it renders the SP metadata and validates
    it. Catching a typo here rather than three redirects into a browser flow
    saves a lot of time.
    """
    connection = db.get(IdpConnection, connection_id)
    if connection is None:
        return _redirect("/admin", error="Connection not found")

    result: dict[str, Any] = {"ok": False, "protocol": connection.protocol}

    if connection.protocol == "oidc":
        try:
            settings_obj = conn.load_settings(connection)
            document = await oidc.fetch_discovery(settings_obj, force=True)  # type: ignore[arg-type]
            result.update(
                ok=True,
                issuer=document.get("issuer", ""),
                authorization_endpoint=document.get("authorization_endpoint", ""),
                token_endpoint=document.get("token_endpoint", ""),
                userinfo_endpoint=document.get("userinfo_endpoint", ""),
                jwks_uri=document.get("jwks_uri", ""),
                end_session_endpoint=document.get("end_session_endpoint", ""),
                scopes_supported=document.get("scopes_supported", []),
                redirect_uri_to_register=conn.redirect_uri(connection.slug),
            )
        except oidc.OidcError as exc:
            result.update(ok=False, error=exc.message, detail=exc.detail)
    else:
        try:
            xml = saml.build_metadata(connection)
            result.update(
                ok=True,
                metadata_length=len(xml),
                acs_url=conn.acs_url(connection.slug),
                metadata_url=conn.metadata_url(connection.slug),
                entity_id=conn.load_settings(connection).sp_entity_id  # type: ignore[union-attr]
                or conn.metadata_url(connection.slug),
            )
        except saml.SamlError as exc:
            result.update(ok=False, error=exc.message, detail=exc.detail)

    return templates.TemplateResponse(
        request,
        "admin/connection_test.html",
        {"session": session, "connection": connection, "result": result},
    )


def _extract_config(form: Any, protocol: str) -> dict[str, Any]:
    """Pull protocol settings out of the submitted form.

    Field names match the Pydantic model, so adding a setting means adding it
    to the model and the template — never here.
    """
    model = SETTINGS_MODELS[protocol]
    data: dict[str, Any] = {}
    for field_name, field in model.model_fields.items():
        raw = form.get(field_name)
        if field.annotation is bool:
            data[field_name] = _form_bool(form, field_name)
        elif field_name == "max_age":
            text = str(raw or "").strip()
            data[field_name] = int(text) if text.isdigit() else None
        else:
            data[field_name] = str(raw or "").strip()
    return data


# --- SCIM --------------------------------------------------------------------


def _render_scim_console(
    request: Request, db: Session, session: UserSession, *, new_token: str = ""
) -> Response:
    return templates.TemplateResponse(
        request,
        "admin/scim.html",
        {
            "session": session,
            "read_only": session.role != "admin",
            "clients": list(db.execute(select(ScimClient).order_by(ScimClient.name)).scalars()),
            "users": list(db.execute(select(ScimUser).order_by(ScimUser.user_name)).scalars()),
            "groups": list(db.execute(select(ScimGroup).order_by(ScimGroup.display_name)).scalars()),
            "scim_base_url": conn.scim_base_url(),
            "new_token": new_token,
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
            "scim_events": events.recent(db, limit=25, kind="scim_request"),
        },
    )


@router.get("/scim", response_class=HTMLResponse)
def scim_console(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_or_power),
) -> Response:
    return _render_scim_console(request, db, session)


@router.post("/scim/clients", response_class=HTMLResponse)
async def create_scim_client(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    form = await request.form()
    name = str(form.get("name", "")).strip() or "Provisioning client"

    token = generate_token()
    client = ScimClient(
        name=name,
        token_hash=hash_token(token),
        # Enough to recognise which token this is later, not enough to use.
        token_hint=token[:6],
        enabled=True,
    )
    db.add(client)
    db.commit()

    events.record(
        db,
        kind="config_change",
        outcome="ok",
        summary=f"Created SCIM client '{name}'",
        request=request,
        subject=session.email,
    )

    # Rendered directly rather than redirected with the token in a query
    # string: URLs end up in access logs, browser history, and referrer
    # headers, and this is a credential. Shown once — only its hash is stored.
    return _render_scim_console(request, db, session, new_token=token)


@router.post("/scim/clients/{client_id}/delete")
def delete_scim_client(
    client_id: str,
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    client = db.get(ScimClient, client_id)
    if client is None:
        return _redirect("/admin/scim", error="Client not found")
    name = client.name
    db.delete(client)
    db.commit()
    events.record(
        db,
        kind="config_change",
        outcome="ok",
        summary=f"Deleted SCIM client '{name}'",
        request=request,
        subject=session.email,
    )
    return _redirect("/admin/scim", message="Client deleted")


@router.get("/scim/users/{user_id}", response_class=HTMLResponse)
def scim_user_detail(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_or_power),
) -> Response:
    user = db.get(ScimUser, user_id)
    if user is None:
        return _redirect("/admin/scim", error="User not found")
    return templates.TemplateResponse(
        request, "admin/scim_user.html", {"session": session, "scim_user": user}
    )


# --- local accounts ----------------------------------------------------------


@router.get("/users", response_class=HTMLResponse)
def local_users(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    return templates.TemplateResponse(
        request,
        "admin/local_users.html",
        {
            "session": session,
            "users": list(db.execute(select(LocalUser).order_by(LocalUser.email)).scalars()),
            "roles": ROLES,
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
        },
    )


@router.post("/users")
async def create_local_user(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    form = await request.form()
    email = str(form.get("email", "")).strip().lower()
    password = str(form.get("password", ""))
    role = str(form.get("role", "user"))

    if not email or "@" not in email:
        return _redirect("/admin/users", error="A valid email address is required")
    if len(password) < 12:
        return _redirect("/admin/users", error="Password must be at least 12 characters")
    if role not in ROLES:
        return _redirect("/admin/users", error="Unknown role")
    if db.execute(select(LocalUser).where(LocalUser.email == email)).scalar_one_or_none():
        return _redirect("/admin/users", error="That account already exists")

    db.add(
        LocalUser(
            email=email,
            display_name=str(form.get("display_name", "")).strip() or email,
            password_hash=hash_password(password),
            role=role,
            is_active=True,
        )
    )
    db.commit()
    events.record(
        db,
        kind="config_change",
        outcome="ok",
        summary=f"Created local account {email} ({role})",
        request=request,
        subject=session.email,
    )
    return _redirect("/admin/users", message="Account created")


@router.post("/users/{user_id}/password")
async def change_local_password(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    user = db.get(LocalUser, user_id)
    if user is None:
        return _redirect("/admin/users", error="Account not found")

    form = await request.form()
    password = str(form.get("password", ""))
    if len(password) < 12:
        return _redirect("/admin/users", error="Password must be at least 12 characters")

    user.password_hash = hash_password(password)
    user.must_change_password = False
    db.commit()
    events.record(
        db,
        kind="config_change",
        outcome="ok",
        summary=f"Changed password for {user.email}",
        request=request,
        subject=session.email,
    )
    return _redirect("/admin/users", message="Password updated")


@router.post("/users/{user_id}/toggle")
def toggle_local_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    user = db.get(LocalUser, user_id)
    if user is None:
        return _redirect("/admin/users", error="Account not found")

    if user.email == session.email:
        # Disabling the account you are signed in with is the fastest way to
        # lock yourself out of your own test harness.
        return _redirect("/admin/users", error="You cannot disable the account you are using")

    active_admins = [
        u
        for u in db.execute(select(LocalUser).where(LocalUser.role == "admin")).scalars()
        if u.is_active and u.id != user.id
    ]
    if user.is_active and user.role == "admin" and not active_admins:
        return _redirect("/admin/users", error="At least one active local admin must remain")

    user.is_active = not user.is_active
    db.commit()
    return _redirect("/admin/users", message="Account updated")


# --- activity ----------------------------------------------------------------


@router.get("/events", response_class=HTMLResponse)
def event_log(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_or_power),
) -> Response:
    kind = request.query_params.get("kind", "")
    return templates.TemplateResponse(
        request,
        "admin/events.html",
        {
            "session": session,
            "events": events.recent(db, limit=200, kind=kind or None),
            "kind": kind,
        },
    )


@router.get("/sessions", response_class=HTMLResponse)
def active_sessions(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    rows = list(
        db.execute(
            select(UserSession)
            .where(UserSession.revoked_at.is_(None))
            .order_by(UserSession.created_at.desc())
            .limit(100)
        ).scalars()
    )
    return templates.TemplateResponse(
        request,
        "admin/sessions.html",
        {"session": session, "sessions": rows, "message": request.query_params.get("message", "")},
    )


@router.post("/sessions/{session_id}/revoke")
def revoke(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    revoke_session(db, session_id)
    events.record(
        db,
        kind="config_change",
        outcome="ok",
        summary="Revoked a session",
        request=request,
        subject=session.email,
        detail={"session_id": session_id},
    )
    return _redirect("/admin/sessions", message="Session revoked")


# --- connection export -------------------------------------------------------


@router.get("/connections/{connection_id}/export")
def export_connection(
    connection_id: str,
    db: Session = Depends(get_db),
    _session: UserSession = Depends(admin_only),
) -> Response:
    """Download one connection as JSON, ready to import elsewhere.

    Secrets are omitted, so the file is safe to attach to a ticket or commit to
    a repository of known-good configurations. The destination prompts for the
    client secret on import.
    """
    connection = db.get(IdpConnection, connection_id)
    if connection is None:
        return _redirect("/admin", error="Connection not found")

    payload = {"connections": [conn.export_connection(connection)]}
    return Response(
        content=json.dumps(payload, indent=2, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="authlab-connection-{connection.slug}.json"'
            )
        },
    )


@router.post("/connections/import")
async def import_connection_form(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    """Paste an exported definition into the console."""
    form = await request.form()
    raw = str(form.get("definition", "")).strip()
    if not raw:
        return _redirect("/admin/automation", error="Paste a connection definition first")

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        return _redirect("/admin/automation", error=f"That is not valid JSON: {exc}")

    definitions = payload.get("connections") if isinstance(payload, dict) else None
    if definitions is None:
        definitions = [payload]

    imported: list[str] = []
    for definition in definitions:
        if not isinstance(definition, dict):
            return _redirect("/admin/automation", error="Each definition must be an object")
        try:
            connection, created = conn.import_connection(db, definition)
        except ValueError as exc:
            return _redirect("/admin/automation", error=str(exc))
        imported.append(f"{connection.name} ({'created' if created else 'updated'})")
        events.record(
            db,
            kind="config_change",
            outcome="ok",
            summary=f"Imported connection '{connection.name}'",
            request=request,
            connection_slug=connection.slug,
            subject=session.email,
        )

    oidc.invalidate_cache()
    return _redirect(
        "/admin/automation",
        message=f"Imported {len(imported)}: {', '.join(imported)}. Re-enter any client secret.",
    )


# --- automation tokens -------------------------------------------------------


def _render_automation(
    request: Request, db: Session, session: UserSession, *, new_token: str = ""
) -> Response:
    return templates.TemplateResponse(
        request,
        "admin/automation.html",
        {
            "session": session,
            "tokens": list(db.execute(select(ApiToken).order_by(ApiToken.name)).scalars()),
            "scopes": API_SCOPES,
            "connections": conn.list_all(db),
            "new_token": new_token,
            "api_base_url": get_settings().base_url.rstrip("/"),
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
        },
    )


@router.get("/automation", response_class=HTMLResponse)
def automation_console(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    return _render_automation(request, db, session)


@router.post("/automation/tokens", response_class=HTMLResponse)
async def create_api_token(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    form = await request.form()
    name = str(form.get("name", "")).strip() or "Automation token"
    scopes = [scope for scope in form.getlist("scopes") if scope in API_SCOPES]

    if not scopes:
        return _redirect("/admin/automation", error="Select at least one scope")

    token = generate_token()
    db.add(
        ApiToken(
            name=name,
            token_hash=hash_token(token),
            token_hint=token[:6],
            scopes=scopes,
            enabled=True,
        )
    )
    db.commit()

    events.record(
        db,
        kind="config_change",
        outcome="ok",
        summary=f"Created API token '{name}' with scopes {', '.join(scopes)}",
        request=request,
        subject=session.email,
    )

    # Rendered rather than redirected, for the same reason the SCIM token is:
    # a credential in a query string ends up in logs, history, and referrers.
    return _render_automation(request, db, session, new_token=token)


@router.post("/automation/tokens/{token_id}/delete")
def delete_api_token(
    token_id: str,
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    token = db.get(ApiToken, token_id)
    if token is None:
        return _redirect("/admin/automation", error="Token not found")
    name = token.name
    db.delete(token)
    db.commit()
    events.record(
        db,
        kind="config_change",
        outcome="ok",
        summary=f"Deleted API token '{name}'",
        request=request,
        subject=session.email,
    )
    return _redirect("/admin/automation", message="Token deleted")


# --- service and API access ---------------------------------------------------


def _oidc_connections(db: Session) -> list[IdpConnection]:
    return [c for c in conn.list_all(db) if c.protocol == "oidc"]


@router.get("/service-access", response_class=HTMLResponse)
def service_access(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    return templates.TemplateResponse(
        request,
        "admin/service_access.html",
        {
            "session": session,
            "connections": _oidc_connections(db),
            "result": None,
            "token_response": None,
            "selected": request.query_params.get("connection", ""),
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
        },
    )


@router.post("/service-access/inspect", response_class=HTMLResponse)
async def inspect_token(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    """Validate a pasted access token the way a resource server would.

    This is the half of OAuth the rest of the app does not exercise: not "can
    this person sign in" but "would an API accept this token, and what would it
    decide the caller may do".
    """
    form = await request.form()
    slug = str(form.get("connection", "")).strip()
    token = str(form.get("token", "")).strip()
    audience = str(form.get("audience", "")).strip()

    connection = conn.get_by_slug(db, slug)
    if connection is None or connection.protocol != "oidc":
        return _redirect("/admin/service-access", error="Choose an OIDC connection")

    result: dict[str, Any] | None = None
    error = ""
    try:
        result = await apitoken.inspect_access_token(
            connection, token, expected_audience=audience
        )
    except oidc.OidcError as exc:
        error = exc.message

    events.record(
        db,
        kind="config_change",
        outcome="ok" if result and result.get("valid") else "denied",
        summary=(
            f"Inspected an access token against '{connection.name}': "
            f"{'valid' if result and result.get('valid') else 'rejected'}"
        ),
        request=request,
        connection_slug=connection.slug,
        subject=session.email,
        # The token itself is never recorded — only the verdict and the checks.
        detail={"checks": (result or {}).get("checks", []), "error": error},
    )

    return templates.TemplateResponse(
        request,
        "admin/service_access.html",
        {
            "session": session,
            "connections": _oidc_connections(db),
            "result": result,
            "token_response": None,
            "selected": slug,
            "message": "",
            "error": error,
        },
    )


@router.post("/service-access/client-credentials", response_class=HTMLResponse)
async def run_client_credentials(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    """Mint a token as the application itself, with no user involved.

    Service principals are how most application-to-application access actually
    works, and none of the browser flow tells you anything about them.
    """
    form = await request.form()
    slug = str(form.get("connection", "")).strip()
    scope = str(form.get("scope", "")).strip()

    connection = conn.get_by_slug(db, slug)
    if connection is None or connection.protocol != "oidc":
        return _redirect("/admin/service-access", error="Choose an OIDC connection")

    token_response: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    error = ""
    try:
        token_response = await apitoken.client_credentials_token(connection, scope=scope)
        access_token = str(token_response.get("access_token", ""))
        if access_token:
            result = await apitoken.inspect_access_token(connection, access_token)
    except oidc.OidcError as exc:
        error = exc.description or exc.message

    events.record(
        db,
        kind="config_change",
        outcome="ok" if token_response else "denied",
        summary=(
            f"client_credentials against '{connection.name}': "
            f"{'issued' if token_response else 'refused'}"
        ),
        request=request,
        connection_slug=connection.slug,
        subject=session.email,
        detail={"scope": scope, "error": error},
    )

    return templates.TemplateResponse(
        request,
        "admin/service_access.html",
        {
            "session": session,
            "connections": _oidc_connections(db),
            "result": result,
            "token_response": token_response,
            "selected": slug,
            "message": "",
            "error": error,
        },
    )


# --- session comparison -------------------------------------------------------


def diff_claims(left: dict[str, Any], right: dict[str, Any]) -> list[dict[str, Any]]:
    """Compare two claim sets, key by key.

    The question this answers is "what changed between the attempt that worked
    and the one that did not" — usually amr, acr, ipaddr, or a group that
    appeared. Reading two JSON dumps side by side to find it is exactly the
    manual work worth removing.
    """
    rows: list[dict[str, Any]] = []
    for key in sorted(set(left) | set(right)):
        in_left = key in left
        in_right = key in right
        left_value = left.get(key)
        right_value = right.get(key)

        if in_left and not in_right:
            state = "removed"
        elif in_right and not in_left:
            state = "added"
        elif left_value == right_value:
            state = "same"
        else:
            state = "changed"

        rows.append(
            {"claim": key, "state": state, "left": left_value, "right": right_value}
        )
    return rows


@router.get("/sessions/compare", response_class=HTMLResponse)
def compare_sessions(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    """Side-by-side claim diff between two sessions.

    Two sign-ins, one that satisfied a policy and one that did not, and the
    difference between them is usually two or three claims. This finds them.
    """
    left_id = request.query_params.get("a", "")
    right_id = request.query_params.get("b", "")

    left = db.get(UserSession, left_id) if left_id else None
    right = db.get(UserSession, right_id) if right_id else None

    rows: list[dict[str, Any]] = []
    if left is not None and right is not None:
        rows = diff_claims(left.raw_claims or {}, right.raw_claims or {})

    changed_only = request.query_params.get("changed_only", "") == "1"
    return templates.TemplateResponse(
        request,
        "admin/session_diff.html",
        {
            "session": session,
            "left": left,
            "right": right,
            "rows": [r for r in rows if r["state"] != "same"] if changed_only else rows,
            "changed_only": changed_only,
            "difference_count": sum(1 for r in rows if r["state"] != "same"),
            "sessions": list(
                db.execute(
                    select(UserSession).order_by(UserSession.created_at.desc()).limit(50)
                ).scalars()
            ),
        },
    )
