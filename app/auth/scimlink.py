"""Linking a signed-in session to the SCIM user provisioned for it.

Before this existed the SCIM store was write-only with respect to access: a
provisioning connector could create users and groups all day and none of it
changed what anyone could do in the app. Roles came exclusively from token
claims. That made half of a provisioning test unobservable — you could watch
the payload arrive, but not watch it grant anything.

The join is by identifier rather than by a foreign key because there is no
moment at which the two systems agree on one. SCIM knows a user by `userName`
(a UPN or email) and `externalId` (the directory's own object id); a session
knows them by whatever `subject_claim` produced, plus an email. Any of those
may be the value that matches, so all of them are tried.
"""

from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models import ScimUser, UserSession


def find_scim_user(db: Session, *identifiers: str | None) -> ScimUser | None:
    """The provisioned user matching any of these identifiers, if there is one.

    Case-insensitive, because email addresses are and providers are not
    consistent about the casing they assert.
    """
    wanted = {value.strip().lower() for value in identifiers if value and value.strip()}
    if not wanted:
        return None

    return db.execute(
        select(ScimUser).where(
            or_(
                func.lower(ScimUser.user_name).in_(wanted),
                func.lower(ScimUser.email).in_(wanted),
                func.lower(ScimUser.external_id).in_(wanted),
            )
        )
    ).scalars().first()


def for_session(db: Session, session: UserSession) -> ScimUser | None:
    return find_scim_user(db, session.subject, session.email)


def group_names(user: ScimUser | None) -> list[str]:
    """Group display names for the rule engine to match against.

    Display names rather than ids: they are what a person types into a mapping
    rule, and what the provider shows in its own console. The group id is still
    available on the SCIM console page for anyone who needs to match on it.
    """
    if user is None:
        return []
    return [group.display_name for group in user.groups]


def describe(db: Session, session: UserSession) -> dict[str, object]:
    """What the dashboard needs to explain the link, or its absence.

    Reporting *why* no SCIM user was found is the useful part: "we looked for
    these identifiers" is immediately actionable, where an empty group list
    looks like a mapping bug.
    """
    user = for_session(db, session)
    identifiers = [value for value in (session.subject, session.email) if value]
    return {
        "searched_for": identifiers,
        "found": user is not None,
        "user": user,
        "groups": group_names(user),
        "active": user.active if user is not None else None,
    }
