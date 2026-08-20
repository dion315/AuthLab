"""Pages that belong to the signed-in user rather than to an administrator.

Two things live here:

**Changing your own password.** Previously only an administrator could set
anyone's password, including their own, and the `must_change_password` flag
raised at first run was decorative — it rendered a badge and nothing enforced
it. A harness that prints a generated administrator password into a startup log
needs a way for that password to stop being the one that works.

**Step-up authentication.** A page that requires a stronger authentication
context than the session currently carries, and issues a challenge when it does
not have one. This is the shape of a Conditional Access authentication context
(Entra) or a step-up ACR request (most other providers): the user is already
signed in, but *this particular action* demands more, so the app sends them
back to the IdP asking for it and re-evaluates on return.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import events
from app.auth import connections as conn
from app.auth.rolemap import extract_claim, matches
from app.db import get_db
from app.deps import current_session, require_login
from app.models import PASSWORD_SOURCE_USER, LocalUser, UserSession
from app.security import hash_password, verify_password
from app.templating import templates

router = APIRouter()

MIN_PASSWORD_LENGTH = 12


# --- self-service password change --------------------------------------------


@router.get("/account/password", response_class=HTMLResponse)
def password_form(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession | None = Depends(current_session),
) -> Response:
    if session is None:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)

    if session.protocol != "local":
        return templates.TemplateResponse(
            request,
            "auth_error.html",
            {
                "title": "No password to change",
                "message": (
                    "You signed in through an identity provider, so your password "
                    "is managed there rather than here."
                ),
                "detail": {"connection": session.source},
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    user = _local_user(db, session)
    return templates.TemplateResponse(
        request,
        "account/password.html",
        {
            "session": session,
            "required": bool(user and user.must_change_password),
            "min_length": MIN_PASSWORD_LENGTH,
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
        },
    )


@router.post("/account/password")
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
    session: UserSession | None = Depends(current_session),
) -> Response:
    if session is None or session.protocol != "local":
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)

    user = _local_user(db, session)
    if user is None:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)

    def back(error: str) -> Response:
        # Percent-encoded rather than interpolated: these strings contain
        # spaces and punctuation that would otherwise produce a malformed
        # Location header some clients refuse to follow.
        return RedirectResponse(
            "/account/password?" + urlencode({"error": error}),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    # The current password is required even though the session already proves
    # identity: it is what stops a borrowed, unlocked browser becoming a
    # permanent account takeover.
    if not verify_password(current_password, user.password_hash):
        events.record(
            db,
            kind="config_change",
            outcome="denied",
            summary=f"Failed password change for {user.email}",
            request=request,
            subject=user.email,
        )
        return back("Your current password was not accepted")

    if new_password != confirm_password:
        return back("The new passwords did not match")
    if len(new_password) < MIN_PASSWORD_LENGTH:
        return back(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if new_password == current_password:
        return back("The new password must be different from the current one")

    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    # Now owned by a person, so startup stops reissuing it.
    user.password_source = PASSWORD_SOURCE_USER
    db.commit()

    events.record(
        db,
        kind="config_change",
        outcome="ok",
        summary=f"{user.email} changed their own password",
        request=request,
        subject=user.email,
    )
    return RedirectResponse(
        "/dashboard?message=Password+updated", status_code=status.HTTP_303_SEE_OTHER
    )


def _local_user(db: Session, session: UserSession) -> LocalUser | None:
    if not session.email:
        return None
    return db.execute(
        select(LocalUser).where(func.lower(LocalUser.email) == session.email.lower())
    ).scalar_one_or_none()


# --- step-up authentication ---------------------------------------------------


def evaluate_stepup(connection: Any, claims: dict[str, Any]) -> dict[str, Any]:
    """Does this session already satisfy the connection's step-up condition?

    Kept as a plain function of (connection, claims) so the outcome is testable
    without a browser, and so the page can explain exactly what it looked at.
    """
    required_value = (connection.stepup_value or "").strip()
    claim_name = (connection.stepup_claim or "amr").strip()
    operator = (connection.stepup_operator or "contains").strip()

    if not required_value:
        return {
            "configured": False,
            "satisfied": False,
            "claim": claim_name,
            # Not "values": Jinja would resolve that to the dict method.
            "found_values": [],
        }

    values = extract_claim(claims, claim_name)
    matched = next((v for v in values if matches(operator, required_value, v)), None)
    return {
        "configured": True,
        "satisfied": matched is not None,
        "claim": claim_name,
        "operator": operator,
        "required": required_value,
        "found_values": values,
        "matched_on": matched,
    }


@router.get("/step-up", response_class=HTMLResponse)
def step_up(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(require_login),
) -> Response:
    """A protected action that demands a stronger authentication context.

    The "sensitive action" is deliberately trivial — what matters is whether
    the provider challenges when asked to, and what the token looks like
    afterwards. If the condition is already met, the page says so and shows
    which claim value satisfied it, which is the evidence that the policy
    actually applied rather than the request quietly succeeding unchanged.
    """
    connection = conn.get_by_slug(db, session.source) if session.source != "local" else None
    claims = session.raw_claims or {}

    result: dict[str, Any] = {"configured": False, "satisfied": False}
    challenge_url = ""

    if connection is not None:
        result = evaluate_stepup(connection, claims)
        if result["configured"] and not result["satisfied"]:
            challenge_url = _challenge_url(connection)

    return templates.TemplateResponse(
        request,
        "stepup.html",
        {
            "session": session,
            "connection": connection,
            "result": result,
            "challenge_url": challenge_url,
        },
    )


def _challenge_url(connection: Any) -> str:
    """Build the authorization request that asks for the stronger context.

    `prompt=login` is always included: without it a provider with a live
    session will often return the existing authentication context unchanged,
    and the test silently passes without anything having been challenged.
    """
    from urllib.parse import urlencode

    params: dict[str, str] = {"prompt": "login", "return_to": "/step-up"}
    if connection.stepup_acr_values:
        params["acr_values"] = connection.stepup_acr_values
    if connection.stepup_claims_challenge:
        params["claims"] = connection.stepup_claims_challenge

    if connection.protocol == "saml":
        # SAML has no claims challenge; ForceAuthn plus the connection's
        # RequestedAuthnContext is the equivalent lever.
        return f"/auth/saml/{connection.slug}/login?force_authn=1&return_to=/step-up"

    return f"/auth/oidc/{connection.slug}/login?{urlencode(params)}"
