"""Shared FastAPI dependencies for authentication and authorisation."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import LocalUser, UserSession
from app.security import read_session

# Paths a user with an expired password may still reach. Without the first two
# entries the redirect below would loop; without the third they could not sign
# out of an account they cannot use.
_PASSWORD_CHANGE_EXEMPT = ("/account/password", "/logout", "/static", "/healthz", "/readyz")


def current_session(
    request: Request, db: Session = Depends(get_db)
) -> UserSession | None:
    """The signed-in session, or None. Never raises — for optional contexts."""
    return read_session(db, request)


def _password_change_required(db: Session, session: UserSession) -> bool:
    """True when this session belongs to a local account owing a new password.

    Only local accounts can be in this state: a federated password is the
    provider's business, not ours.
    """
    if session.protocol != "local" or not session.email:
        return False
    user = db.execute(
        select(LocalUser).where(func.lower(LocalUser.email) == session.email.lower())
    ).scalar_one_or_none()
    return user is not None and user.must_change_password


def require_login(
    request: Request, db: Session = Depends(get_db)
) -> UserSession:
    session = read_session(db, request)
    if session is None:
        # 303 forces the browser to follow with GET regardless of the original
        # method, which matters when an expired session hits a form POST.
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            detail="Not signed in",
            headers={"Location": "/login"},
        )

    # The first-run administrator password is generated and printed to a log,
    # which is fine for getting in once and not fine for leaving in place. The
    # flag has always been set; this is what makes it mean something.
    if not request.url.path.startswith(_PASSWORD_CHANGE_EXEMPT) and _password_change_required(
        db, session
    ):
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            detail="Password change required",
            headers={"Location": "/account/password"},
        )

    return session


def require_role(*allowed: str) -> Callable[..., UserSession]:
    """Gate a route on app role.

    Returns 403 with a real explanation rather than a bare status, because
    seeing *why* a role check failed is the point of the exercise here.
    """

    def dependency(session: UserSession = Depends(require_login)) -> UserSession:
        if session.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Your role is '{session.role}'. This page requires one of: "
                    f"{', '.join(allowed)}. Role is assigned by the mapping rules on "
                    f"connection '{session.source}'."
                ),
            )
        return session

    return dependency
