"""The automation API — everything the admin console does, without a browser.

The console is the right interface for the first hour with a new provider and
the wrong one for everything after. Three things need to happen without a human
clicking:

**Evidence has to leave the app.** The activity log is the actual product of a
Conditional Access test, and until now it existed only as HTML in a browser
tab. A change record wants the events; a comparison between last week's run and
today's wants both, diffable. So: JSON and CSV, filterable by kind, outcome and
time.

**A working connection has to be reproducible.** Exported as JSON, imported
somewhere else — a colleague's instance, a fresh deployment, a pipeline that
stands up a known state before it asserts anything. Secrets never travel; they
are re-entered at the destination, and an import leaves an existing one alone.

**Configuration has to be checkable before a browser is involved.** Running the
discovery test from CI catches a rotated issuer or a withdrawn endpoint at the
point the pipeline runs, not the next time somebody tries to sign in.

Authentication accepts either an API token or an admin session cookie, so the
same endpoints serve `curl` and the console's own download buttons.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import events
from app.auth import connections as conn
from app.auth import oidc, saml
from app.db import get_db
from app.models import ApiToken, AuthEvent, UserSession
from app.security import read_session, verify_token

router = APIRouter()


# --- authentication -----------------------------------------------------------


class Caller:
    """Who is making the request, and what they may do."""

    def __init__(self, *, kind: str, name: str, scopes: tuple[str, ...]):
        self.kind = kind  # "token" | "session"
        self.name = name
        self.scopes = scopes


def require_scope(scope: str):
    """Dependency factory: require `scope` from a token, or an admin session.

    An admin session is granted every scope because an administrator can
    already do all of this through the console — refusing them here would be
    theatre, and it is what lets the console's own export buttons work with no
    separate credential.
    """

    def dependency(
        request: Request,
        db: Session = Depends(get_db),
        authorization: str = Header(default=""),
    ) -> Caller:
        presented = ""
        if authorization.lower().startswith("bearer "):
            presented = authorization[7:].strip()

        if presented:
            for token in db.execute(
                select(ApiToken).where(ApiToken.enabled.is_(True))
            ).scalars():
                if verify_token(presented, token.token_hash):
                    if scope not in (token.scopes or []):
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=(
                                f"This token does not carry the '{scope}' scope. "
                                f"It has: {', '.join(token.scopes or []) or '(none)'}."
                            ),
                        )
                    token.last_used_at = datetime.now(UTC)
                    db.commit()
                    return Caller(
                        kind="token", name=token.name, scopes=tuple(token.scopes or [])
                    )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or disabled API token.",
            )

        session = read_session(db, request)
        if session is not None and session.role == "admin":
            return Caller(kind="session", name=session.email, scopes=("*",))

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Provide an API token as a bearer token, or sign in as an "
                "administrator. Tokens are minted under Admin → Automation."
            ),
        )

    return dependency


# Module-level singletons, matching the admin console's `admin_only` pattern —
# a dependency built once at import rather than per call in an argument default.
events_read = require_scope("events:read")
sessions_read = require_scope("sessions:read")
connections_read = require_scope("connections:read")
connections_write = require_scope("connections:write")


# --- events -------------------------------------------------------------------


def _event_rows(
    db: Session,
    *,
    kind: str,
    outcome: str,
    since_minutes: int | None,
    limit: int,
) -> list[AuthEvent]:
    statement = select(AuthEvent).order_by(AuthEvent.at.desc()).limit(limit)
    if kind:
        statement = statement.where(AuthEvent.kind == kind)
    if outcome:
        statement = statement.where(AuthEvent.outcome == outcome)
    if since_minutes:
        cutoff = datetime.now(UTC) - timedelta(minutes=since_minutes)
        statement = statement.where(AuthEvent.at >= cutoff)
    return list(db.execute(statement).scalars().all())


def _event_to_dict(event: AuthEvent) -> dict[str, Any]:
    at = event.at
    if at is not None and at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    return {
        "id": event.id,
        "at": at.isoformat() if at else "",
        "kind": event.kind,
        "outcome": event.outcome,
        "connection": event.connection_slug,
        "protocol": event.protocol,
        "subject": event.subject,
        "client_ip": event.client_ip,
        "user_agent": event.user_agent,
        "summary": event.summary,
        "detail": event.detail or {},
    }


@router.get("/api/admin/events")
def export_events(
    db: Session = Depends(get_db),
    _caller: Caller = Depends(events_read),
    kind: str = Query("", description="login_success, login_failure, scim_request, ..."),
    outcome: str = Query("", description="ok, denied, error, info"),
    since_minutes: int | None = Query(None, ge=1, le=525600),
    limit: int = Query(500, ge=1, le=5000),
    format: str = Query("json", pattern="^(json|csv)$"),
) -> Response:
    """The activity log, as evidence you can keep.

    CSV flattens `detail` to a JSON string in one column rather than dropping
    it: the error code an IdP returned lives in there, and it is the single
    most useful field on a denied sign-in.
    """
    rows = _event_rows(
        db, kind=kind, outcome=outcome, since_minutes=since_minutes, limit=limit
    )
    payload = [_event_to_dict(event) for event in rows]

    if format == "csv":
        buffer = io.StringIO()
        columns = [
            "id", "at", "kind", "outcome", "connection", "protocol",
            "subject", "client_ip", "summary", "detail",
        ]
        writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for item in payload:
            writer.writerow({**item, "detail": json.dumps(item["detail"], default=str)})
        return Response(
            content=buffer.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": 'attachment; filename="authlab-events.csv"'
            },
        )

    return JSONResponse(
        content={
            "generated_at": datetime.now(UTC).isoformat(),
            "count": len(payload),
            "filters": {
                "kind": kind,
                "outcome": outcome,
                "since_minutes": since_minutes,
                "limit": limit,
            },
            "events": payload,
        }
    )


# --- sessions -----------------------------------------------------------------


@router.get("/api/admin/sessions")
def list_sessions(
    db: Session = Depends(get_db),
    _caller: Caller = Depends(sessions_read),
    include_revoked: bool = Query(False),
) -> dict[str, Any]:
    statement = select(UserSession).order_by(UserSession.created_at.desc()).limit(500)
    if not include_revoked:
        statement = statement.where(UserSession.revoked_at.is_(None))

    rows = list(db.execute(statement).scalars().all())
    return {
        "count": len(rows),
        "sessions": [
            {
                "id": row.id,
                "subject": row.subject,
                "email": row.email,
                "role": row.role,
                "source": row.source,
                "protocol": row.protocol,
                "client_ip": row.client_ip,
                "created_at": row.created_at.isoformat() if row.created_at else "",
                "expires_at": row.expires_at.isoformat() if row.expires_at else "",
                "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
                "claims": row.raw_claims or {},
            }
            for row in rows
        ],
    }


# --- connections --------------------------------------------------------------


@router.get("/api/admin/connections")
def export_connections(
    db: Session = Depends(get_db),
    _caller: Caller = Depends(connections_read),
    slug: str = Query("", description="Export one connection instead of all"),
) -> dict[str, Any]:
    """Connection definitions as portable JSON. Secrets are never included."""
    if slug:
        connection = conn.get_by_slug(db, slug)
        if connection is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"No connection '{slug}'.")
        found = [connection]
    else:
        found = conn.list_all(db)

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "connections": [conn.export_connection(item) for item in found],
    }


@router.post("/api/admin/connections")
def import_connections(
    request: Request,
    db: Session = Depends(get_db),
    caller: Caller = Depends(connections_write),
    payload: dict[str, Any] = Body(...),
) -> dict[str, Any]:
    """Create or update connections from exported definitions.

    Accepts either a single definition or `{"connections": [...]}`, so the
    output of the export endpoint can be piped straight back in.
    """
    definitions = payload.get("connections")
    if definitions is None:
        definitions = [payload]
    if not isinstance(definitions, list):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "'connections' must be a list of connection definitions.",
        )

    results: list[dict[str, Any]] = []
    for definition in definitions:
        if not isinstance(definition, dict):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Each definition must be an object.")
        try:
            connection, created = conn.import_connection(db, definition)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

        results.append(
            {
                "slug": connection.slug,
                "name": connection.name,
                "protocol": connection.protocol,
                "created": created,
                "secrets_required": sorted(
                    conn.EXPORT_EXCLUDED
                    & set(conn.load_settings(connection).model_dump().keys())
                ),
            }
        )
        events.record(
            db,
            kind="config_change",
            outcome="ok",
            summary=(
                f"{'Created' if created else 'Updated'} connection "
                f"'{connection.name}' via the automation API"
            ),
            request=request,
            connection_slug=connection.slug,
            subject=caller.name,
        )

    # A changed issuer must not keep resolving against the cached document.
    oidc.invalidate_cache()
    return {"imported": len(results), "results": results}


@router.post("/api/admin/connections/{slug}/test")
async def test_connection(
    slug: str,
    db: Session = Depends(get_db),
    _caller: Caller = Depends(connections_read),
) -> dict[str, Any]:
    """Run the configuration check without a browser flow.

    Returns 200 with `ok: false` rather than an error status when the *provider*
    is misconfigured: the check ran and produced a verdict, which is a
    successful request. A pipeline should branch on `ok`, not on the status
    code, and reserve non-2xx for "the check could not be performed".
    """
    connection = conn.get_by_slug(db, slug)
    if connection is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No connection '{slug}'.")

    result: dict[str, Any] = {"slug": slug, "protocol": connection.protocol, "ok": False}
    if connection.protocol == "oidc":
        # Included whether or not the check succeeds: when discovery fails, a
        # wrong redirect URI is the next thing anyone wants to look at.
        result["redirect_uri_to_register"] = conn.redirect_uri(slug)

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
            )
        except oidc.OidcError as exc:
            result.update(ok=False, error=exc.message, detail=exc.detail)
    else:
        try:
            xml = saml.build_metadata(connection)
            result.update(
                ok=True,
                metadata_length=len(xml),
                acs_url=conn.acs_url(slug),
                sls_url=conn.sls_url(slug),
                metadata_url=conn.metadata_url(slug),
            )
        except saml.SamlError as exc:
            result.update(ok=False, error=exc.message, detail=exc.detail)

    return result
