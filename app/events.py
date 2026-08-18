"""Recording authentication and provisioning events.

Every sign-in attempt, every SCIM call, and every configuration change lands
here. When an access policy blocks someone, the interesting output
is not the error page they see — it is the error code the IdP returned, the IP
it saw, and how that differs from the attempt that worked five minutes ago.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuthEvent
from app.security import client_ip, user_agent


def record(
    db: Session,
    *,
    kind: str,
    outcome: str = "info",
    summary: str = "",
    request: Request | None = None,
    connection_slug: str = "",
    protocol: str = "",
    subject: str = "",
    detail: dict[str, Any] | None = None,
) -> AuthEvent:
    event = AuthEvent(
        kind=kind,
        outcome=outcome,
        summary=summary[:2000],
        connection_slug=connection_slug,
        protocol=protocol,
        subject=subject,
        client_ip=client_ip(request) if request else "",
        user_agent=user_agent(request) if request else "",
        detail=detail or {},
    )
    db.add(event)
    db.commit()
    return event


def recent(db: Session, limit: int = 50, kind: str | None = None) -> list[AuthEvent]:
    stmt = select(AuthEvent).order_by(AuthEvent.at.desc()).limit(limit)
    if kind:
        stmt = stmt.where(AuthEvent.kind == kind)
    return list(db.execute(stmt).scalars().all())
