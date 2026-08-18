"""Database models.

Design note: IdP configuration is a *row*, not an environment variable. That is
the central difference from a typical sample app and it is deliberate — the
point of this harness is to change an issuer, a role mapping, or a signing
certificate and immediately retry a sign-in, without a redeploy.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


# --- roles -------------------------------------------------------------------

ROLES = ("admin", "power", "user")
DEFAULT_ROLE = "user"


# --- local accounts ----------------------------------------------------------


class LocalUser(Base):
    """A username/password account that does not depend on any IdP.

    This exists so you can never lock yourself out. If an access policy at your
    provider blocks federated sign-in — which, when testing policies, is
    frequently the *intended* outcome — you still need a way back in to change
    the configuration that locked you out.
    """

    __tablename__ = "local_users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="admin")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# --- identity provider connections -------------------------------------------


class IdpConnection(Base):
    """One configured identity provider.

    Several may be enabled at once — the sign-in page renders a button per
    connection. That is intentional: comparing how two IdPs present the same
    user, or testing a policy change against a second tenant without tearing
    down the first, is the common case in this kind of work.

    Protocol-specific settings live in `config` and are validated by the
    Pydantic models in app/auth/schemas.py before they are written.
    """

    __tablename__ = "idp_connections"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False)  # "oidc" | "saml"
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Protocol settings. Secret-bearing fields inside are stored encrypted;
    # see app/auth/schemas.py for which ones and app/crypto.py for how.
    config: Mapped[dict] = mapped_column(MutableDict.as_mutable(JSON), nullable=False, default=dict)

    # --- claim -> app role mapping ---
    # Which claim/assertion attribute carries group or role information.
    role_claim: Mapped[str] = mapped_column(String(200), nullable=False, default="roles")
    # Ordered rules, first match wins:
    #   [{"operator": "equals"|"contains"|"regex", "value": "...", "role": "admin"}]
    role_rules: Mapped[list] = mapped_column(
        MutableList.as_mutable(JSON), nullable=False, default=list
    )
    default_role: Mapped[str] = mapped_column(String(20), nullable=False, default=DEFAULT_ROLE)

    # Where to read identity from. Defaults suit most IdPs; overridable because
    # "most" is not "all" — this is the field people actually need to change.
    subject_claim: Mapped[str] = mapped_column(String(200), nullable=False, default="sub")
    email_claim: Mapped[str] = mapped_column(String(200), nullable=False, default="email")
    name_claim: Mapped[str] = mapped_column(String(200), nullable=False, default="name")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


# --- SCIM provisioning -------------------------------------------------------


class ScimClient(Base):
    """A provisioning client — one bearer token per provisioning source.

    Separate tokens per IdP mean a provisioning log entry can be attributed to
    whichever system actually made the call, and one can be revoked without
    breaking the others.
    """

    __tablename__ = "scim_clients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # Stored as a salted hash, not encrypted: the app only ever needs to verify
    # a presented token, never to display it. Shown once at creation time.
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    token_hint: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


scim_user_groups = Table(
    "scim_user_groups",
    Base.metadata,
    Column("user_id", String(36), ForeignKey("scim_users.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", String(36), ForeignKey("scim_groups.id", ondelete="CASCADE"), primary_key=True),
)


class ScimUser(Base):
    __tablename__ = "scim_users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_name: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    external_id: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    given_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    family_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    email: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Kept verbatim so you can inspect exactly what your IdP sent. When a
    # provisioning mapping does something unexpected, this is the evidence.
    raw_payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    groups: Mapped[list[ScimGroup]] = relationship(
        secondary=scim_user_groups, back_populates="members", lazy="selectin"
    )


class ScimGroup(Base):
    __tablename__ = "scim_groups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    display_name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False, index=True)
    external_id: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    raw_payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    members: Mapped[list[ScimUser]] = relationship(
        secondary=scim_user_groups, back_populates="groups", lazy="selectin"
    )


# --- sessions ----------------------------------------------------------------


class UserSession(Base):
    """Server-side session. The cookie carries only a signed session id.

    Two reasons this is not a self-contained JWT cookie:

    1. Revocation. Deprovisioning a user through SCIM should be able to end
       their session immediately — demonstrating that is one of the things
       this harness exists to test, and a stateless token cannot do it.
    2. Size. The raw claim set from the IdP is the most useful artifact of a
       sign-in and it routinely exceeds the 4KB cookie limit. Kept here, it can
       be as large as it likes.

    We already run a database for SCIM state, so this costs nothing extra.
    """

    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    subject: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    email: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    display_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    role: Mapped[str] = mapped_column(String(20), nullable=False, default=DEFAULT_ROLE)

    # "local" for the built-in account, otherwise the IdpConnection slug.
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="local")
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="local")

    # Everything the IdP asserted, verbatim: ID token claims or SAML attributes.
    raw_claims: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # Kept only to pass back as id_token_hint on federated sign-out, and as
    # SAML NameID/SessionIndex for a LogoutRequest. Not used for authorisation.
    id_token: Mapped[str] = mapped_column(Text, nullable=False, default="")
    name_id: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    session_index: Mapped[str] = mapped_column(String(200), nullable=False, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    client_ip: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    user_agent: Mapped[str] = mapped_column(String(400), nullable=False, default="")


# --- observability -----------------------------------------------------------


class AuthEvent(Base):
    """Append-only record of every authentication and provisioning event.

    This is the actual product of an access policy test. A policy that
    blocks a sign-in produces an error at the IdP, a redirect back, and a
    specific error code — all of which are worth keeping and diffing against
    the next attempt. Without this the result of a test is a screenshot.
    """

    __tablename__ = "auth_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)

    # login_start | login_success | login_failure | logout |
    # scim_request | config_change
    kind: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False, default="info")  # ok|denied|error

    connection_slug: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="")
    subject: Mapped[str] = mapped_column(String(320), nullable=False, default="")

    client_ip: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    user_agent: Mapped[str] = mapped_column(String(400), nullable=False, default="")

    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Error codes, raw claims, SCIM request bodies — whatever the event carried.
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class AppSetting(Base):
    """Small key/value store for global runtime settings."""

    __tablename__ = "app_settings"
    __table_args__ = (UniqueConstraint("key"),)

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict] = mapped_column(MutableDict.as_mutable(JSON), nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
