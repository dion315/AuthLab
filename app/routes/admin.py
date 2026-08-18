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

import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import events
from app.auth import certs, mtls, oidc, saml
from app.auth import connections as conn
from app.auth.schemas import (
    CLIENT_AUTH_METHODS,
    IDENTITY_SOURCES,
    PROTOCOL_LABELS,
    SETTINGS_MODELS,
    MtlsSettings,
)
from app.config import get_settings
from app.db import get_db
from app.deps import require_role
from app.models import (
    ROLES,
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

# Where each protocol reads identity from by default. Certificate connections
# take theirs from the certificate itself, so the names are certificate fields
# rather than claim names.
CLAIM_DEFAULTS: dict[str, dict[str, str]] = {
    "oidc": {
        "subject_claim": "sub",
        "email_claim": "email",
        "name_claim": "name",
        "role_claim": "roles",
    },
    "saml": {
        "subject_claim": "nameId",
        "email_claim": "email",
        "name_claim": "name",
        "role_claim": "groups",
    },
    "mtls": {
        "subject_claim": "identity",
        "email_claim": "san_email",
        "name_claim": "subject_cn",
        "role_claim": "issuer_cn",
    },
}


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
            "protocol_label": PROTOCOL_LABELS[protocol],
            "config": model().model_dump(),
            "defaults": CLAIM_DEFAULTS[protocol],
            "identity_sources": IDENTITY_SOURCES,
            "client_auth_methods": CLIENT_AUTH_METHODS,
            "certificates": {},
            "role_rules": [],
            "roles": ROLES,
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

    fallback = CLAIM_DEFAULTS[protocol]
    connection = IdpConnection(
        slug=slug,
        name=name,
        protocol=protocol,
        enabled=_form_bool(form, "enabled"),
        role_claim=str(form.get("role_claim", "")).strip() or fallback["role_claim"],
        default_role=str(form.get("default_role", "user")),
        subject_claim=str(form.get("subject_claim", "")).strip() or fallback["subject_claim"],
        email_claim=str(form.get("email_claim", "")).strip() or fallback["email_claim"],
        name_claim=str(form.get("name_claim", "")).strip() or fallback["name_claim"],
        role_rules=_parse_role_rules(form),
        config={},
    )

    config_data = _extract_config(form, protocol)
    errors = conn.validate_config(protocol, config_data)
    if errors:
        return _redirect("/admin/connections/new", error="; ".join(errors))

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
        "metadata_url": conn.metadata_url(connection.slug),
        "inspect_url": conn.mtls_inspect_url(connection.slug),
        "login_url": f"/auth/{connection.protocol}/{connection.slug}/login",
    }

    return templates.TemplateResponse(
        request,
        "admin/connection_form.html",
        {
            "session": session,
            "connection": connection,
            "protocol": connection.protocol,
            "protocol_label": PROTOCOL_LABELS[connection.protocol],
            "config": conn.redacted_config(connection),
            "defaults": CLAIM_DEFAULTS[connection.protocol],
            "identity_sources": IDENTITY_SOURCES,
            "client_auth_methods": CLIENT_AUTH_METHODS,
            "certificates": _certificate_diagnostics(connection),
            "role_rules": connection.role_rules or [],
            "roles": ROLES,
            "urls": urls,
            "errors": [],
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
        },
    )


def _certificate_diagnostics(connection: IdpConnection) -> dict[str, Any]:
    """Describe every certificate on a connection, for display beside its field.

    An expired signing certificate or a trust anchor that is not actually a CA
    are both invisible in a textarea full of base64, and both produce failures
    at sign-in time that name neither.
    """
    settings_obj = conn.load_settings(connection)
    described: dict[str, Any] = {}

    if connection.protocol == "saml":
        return saml.certificate_diagnostics(connection)

    if connection.protocol == "oidc" and getattr(settings_obj, "client_certificate", ""):
        described["client_certificate"] = certs.describe_pem(settings_obj.client_certificate)

    if connection.protocol == "mtls":
        assert isinstance(settings_obj, MtlsSettings)
        if settings_obj.trusted_ca_pem:
            try:
                described["trust_anchors"] = [
                    certs.describe(certificate)
                    for certificate in certs.load_certificates(settings_obj.trusted_ca_pem)
                ]
            except certs.CertificateError as exc:
                described["trust_anchors_error"] = exc.message
        if settings_obj.crl_pem:
            try:
                described["crl_count"] = sum(
                    len(list(crl)) for crl in certs.load_crls(settings_obj.crl_pem)
                )
            except certs.CertificateError as exc:
                described["crl_error"] = exc.message
        described["has_ca_key"] = bool(settings_obj.ca_private_key)

    return described


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
                token_endpoint_auth_methods=document.get(
                    "token_endpoint_auth_methods_supported", []
                ),
                client_auth_method=settings_obj.client_auth_method,  # type: ignore[union-attr]
                redirect_uri_to_register=conn.redirect_uri(connection.slug),
            )
            # A client assertion that cannot be built is a configuration error
            # worth finding here rather than at the token endpoint, where it
            # comes back as a generic invalid_client.
            if settings_obj.client_auth_method == "private_key_jwt":  # type: ignore[union-attr]
                try:
                    oidc.build_client_assertion(
                        settings_obj,  # type: ignore[arg-type]
                        audience=document.get("token_endpoint", ""),
                    )
                    result["client_assertion"] = "built and signed successfully"
                except oidc.OidcError as exc:
                    result.update(ok=False, error=exc.message)
        except oidc.OidcError as exc:
            result.update(ok=False, error=exc.message, detail=exc.detail)
    elif connection.protocol == "mtls":
        settings_obj = conn.load_settings(connection)
        assert isinstance(settings_obj, MtlsSettings)
        try:
            anchors = certs.load_certificates(settings_obj.trusted_ca_pem)
            problems = [
                f"'{certs.describe(anchor)['subject']}' is not a CA certificate "
                "(no basicConstraints CA:TRUE), so nothing can chain to it"
                for anchor in anchors
                if not certs.is_certificate_authority(anchor)
            ]
            result.update(
                ok=bool(anchors) or not settings_obj.require_chain,
                anchors=[certs.describe(anchor) for anchor in anchors],
                problems=problems,
                header_name=settings_obj.header_name,
                header_format=settings_obj.header_format,
                identity_sources=settings_obj.identity_sources,
                login_url=conn.mtls_login_url(connection.slug),
                inspect_url=conn.mtls_inspect_url(connection.slug),
            )
            if not anchors and settings_obj.require_chain:
                result["error"] = (
                    "This connection requires a chain to a trusted CA but has no CA "
                    "certificates. Paste one, or generate a test CA below."
                )
        except certs.CertificateError as exc:
            result.update(ok=False, error=exc.message)
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


# --- certificate tooling -----------------------------------------------------
#
# Certificate-based authentication is the one area where "just configure it"
# runs into a wall: you cannot test it without a certificate, and getting one
# usually means a PKI you do not have. So the app issues its own test material,
# clearly labelled as such, and every private key it generates for itself is
# encrypted before it is stored.


def _save_config_values(connection: IdpConnection, values: dict[str, Any]) -> None:
    """Merge a few settings into a connection without touching the rest.

    Reads back the redacted config so stored secrets stay put — the placeholder
    means "unchanged" to store_settings, which is exactly what is wanted here.
    """
    data = conn.redacted_config(connection)
    data.update(values)
    conn.store_settings(connection, data)


@router.post("/connections/{connection_id}/certificates/ca")
def generate_test_ca(
    connection_id: str,
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    connection = db.get(IdpConnection, connection_id)
    if connection is None or connection.protocol != "mtls":
        return _redirect("/admin", error="Client-certificate connection not found")

    certificate_pem, key_pem = certs.generate_ca(f"AuthLab Test CA ({connection.name})")
    _save_config_values(
        connection, {"trusted_ca_pem": certificate_pem, "ca_private_key": key_pem}
    )
    db.commit()

    events.record(
        db,
        kind="config_change",
        outcome="ok",
        summary=f"Generated a test CA for '{connection.name}'",
        request=request,
        subject=session.email,
        connection_slug=connection.slug,
    )
    return _redirect(
        f"/admin/connections/{connection_id}",
        message="Test CA generated. Issue a client certificate below, and point your proxy at this CA.",
    )


@router.post("/connections/{connection_id}/certificates/issue", response_class=HTMLResponse)
async def issue_test_certificate(
    connection_id: str,
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    """Issue a client certificate from this connection's test CA.

    Nothing is stored: the certificate and key are rendered once, and the
    PKCS#12 bundle is built on demand from what the page posts back. A test
    harness has no business keeping a copy of a user credential it minted.
    """
    connection = db.get(IdpConnection, connection_id)
    if connection is None or connection.protocol != "mtls":
        return _redirect("/admin", error="Client-certificate connection not found")

    settings_obj = conn.load_settings(connection)
    assert isinstance(settings_obj, MtlsSettings)
    if not settings_obj.ca_private_key:
        return _redirect(
            f"/admin/connections/{connection_id}",
            error="This connection has no test CA private key. Generate a test CA first.",
        )

    form = await request.form()
    common_name = str(form.get("common_name", "")).strip() or "Test User"
    upn = str(form.get("upn", "")).strip()
    email = str(form.get("email", "")).strip()
    validity = str(form.get("validity", "valid"))

    now = datetime.now(UTC)
    windows = {
        # Issuing something already dead, or not yet alive, is how you check
        # that the validity check is actually running.
        "expired": (now - timedelta(days=400), now - timedelta(days=35)),
        "future": (now + timedelta(days=30), now + timedelta(days=395)),
    }
    not_before, not_after = windows.get(validity, (None, None))

    try:
        certificate_pem, key_pem = certs.issue_client_certificate(
            ca_cert_pem=settings_obj.trusted_ca_pem,
            ca_key_pem=settings_obj.ca_private_key,
            common_name=common_name,
            upn=upn,
            email=email,
            not_before=not_before,
            not_after=not_after,
        )
    except certs.CertificateError as exc:
        return _redirect(f"/admin/connections/{connection_id}", error=exc.message)

    events.record(
        db,
        kind="config_change",
        outcome="ok",
        summary=f"Issued a test client certificate for '{common_name}'",
        request=request,
        subject=session.email,
        connection_slug=connection.slug,
        detail={"common_name": common_name, "upn": upn, "validity": validity},
    )

    return templates.TemplateResponse(
        request,
        "admin/issued_certificate.html",
        {
            "session": session,
            "connection": connection,
            "certificate_pem": certificate_pem,
            "key_pem": key_pem,
            "ca_pem": settings_obj.trusted_ca_pem,
            "described": certs.describe_pem(certificate_pem),
            # Shown on screen rather than chosen silently: the operator needs it
            # to complete the import, and a password nobody can see is useless.
            "suggested_password": generate_token()[:16],
        },
    )


@router.post("/certificates/pkcs12")
async def download_pkcs12(
    request: Request,
    session: UserSession = Depends(admin_only),
) -> Response:
    """Bundle a certificate and key into a .p12 for browser or OS import.

    The values are posted back from the page that generated them rather than
    stored, so this endpoint holds nothing and remembers nothing.
    """
    form = await request.form()
    password = str(form.get("password", "")).strip()
    if len(password) < 6:
        return _redirect("/admin", error="A PKCS#12 password of at least 6 characters is required")

    try:
        payload = certs.to_pkcs12(
            cert_pem=str(form.get("certificate_pem", "")),
            key_pem=str(form.get("key_pem", "")),
            ca_pem=str(form.get("ca_pem", "")),
            friendly_name=str(form.get("friendly_name", "authlab-test-user")),
            password=password,
        )
    except certs.CertificateError as exc:
        return _redirect("/admin", error=exc.message)

    filename = _SLUG_RE.sub("-", str(form.get("friendly_name", "authlab")).lower()).strip("-")
    return Response(
        content=payload,
        media_type="application/x-pkcs12",
        headers={"Content-Disposition": f'attachment; filename="{filename or "authlab"}.p12"'},
    )


@router.post("/connections/{connection_id}/certificates/keypair")
def generate_connection_keypair(
    connection_id: str,
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    """Generate the SP keypair (SAML) or client credential keypair (OIDC).

    Both are self-signed by design: the provider is given the public
    certificate directly and trusts it on that basis, so there is no chain for
    a CA to add anything to.
    """
    connection = db.get(IdpConnection, connection_id)
    if connection is None:
        return _redirect("/admin", error="Connection not found")

    base = get_settings().base_url.replace("https://", "").replace("http://", "").split("/")[0]

    if connection.protocol == "saml":
        certificate_pem, key_pem = certs.generate_self_signed(f"AuthLab SP {base}")
        _save_config_values(
            connection, {"sp_x509_cert": certificate_pem, "sp_private_key": key_pem}
        )
        note = (
            "SP keypair generated. Re-import the SP metadata at your IdP so it picks up "
            "the new certificate."
        )
    elif connection.protocol == "oidc":
        certificate_pem, key_pem = certs.generate_self_signed(
            f"AuthLab client {connection.slug}", client_auth=True
        )
        _save_config_values(
            connection, {"client_certificate": certificate_pem, "client_private_key": key_pem}
        )
        note = (
            "Client credential keypair generated. Upload the certificate shown on this "
            "page to your app registration, then set client authentication to private_key_jwt."
        )
    else:
        return _redirect(
            f"/admin/connections/{connection_id}",
            error="Keypair generation applies to OIDC and SAML connections",
        )

    db.commit()
    events.record(
        db,
        kind="config_change",
        outcome="ok",
        summary=f"Generated a keypair for '{connection.name}'",
        request=request,
        subject=session.email,
        connection_slug=connection.slug,
    )
    return _redirect(f"/admin/connections/{connection_id}", message=note)


@router.post("/connections/{connection_id}/certificates/simulate", response_class=HTMLResponse)
async def simulate_certificate(
    connection_id: str,
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(admin_only),
) -> Response:
    """Run a pasted certificate through the full validation pipeline.

    This is what makes certificate authentication testable before a proxy is
    in front of the app: same code path as a real sign-in, same checks, same
    identity binding — it simply does not create a session.
    """
    connection = db.get(IdpConnection, connection_id)
    if connection is None or connection.protocol != "mtls":
        return _redirect("/admin", error="Client-certificate connection not found")

    settings_obj = conn.load_settings(connection)
    assert isinstance(settings_obj, MtlsSettings)
    if not settings_obj.allow_pasted_certificate:
        return _redirect(
            f"/admin/connections/{connection_id}",
            error="Pasted-certificate testing is turned off for this connection",
        )

    form = await request.form()
    pasted = str(form.get("certificate_pem", "")).strip()
    try:
        result = mtls.evaluate(connection, mtls.decode_header_value(pasted, "auto"))
    except mtls.MtlsError as exc:
        return _redirect(f"/admin/connections/{connection_id}", error=exc.message)

    return templates.TemplateResponse(
        request,
        "mtls_result.html",
        {
            "session": session,
            "connection": connection,
            "result": result,
            "simulated": True,
            "signed_in": True,
            "header_used": "(pasted into the admin console)",
            "headers_present": {},
        },
    )


def _extract_config(form: Any, protocol: str) -> dict[str, Any]:
    """Pull protocol settings out of the submitted form.

    Field names match the Pydantic model, so adding a setting means adding it
    to the model and the template — never here. Optional integers are read from
    the annotation rather than by field name, so a second one does not silently
    arrive as a string.
    """
    model = SETTINGS_MODELS[protocol]
    data: dict[str, Any] = {}
    for field_name, field in model.model_fields.items():
        raw = form.get(field_name)
        if field.annotation is bool:
            data[field_name] = _form_bool(form, field_name)
        elif field.annotation in (int, int | None):
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
