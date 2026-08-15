"""Shared FastAPI dependencies for authentication and authorisation."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import UserSession
from app.security import read_session


def current_session(
    request: Request, db: Session = Depends(get_db)
) -> UserSession | None:
    """The signed-in session, or None. Never raises — for optional contexts."""
    return read_session(db, request)


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
