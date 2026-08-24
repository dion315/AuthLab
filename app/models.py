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

# Where a connection reads group/role information from.
#   claims           — the token or assertion only (the original behaviour)
#   scim             — SCIM-provisioned group membership only
#   claims_then_scim — claims first; fall back to SCIM groups if nothing matched
ROLE_SOURCES = ("claims", "scim", "claims_then_scim")

# Where a local account's current password came from.
#   env       — BOOTSTRAP_ADMIN_PASSWORD. Reapplied on every start, so the
#               environment stays the source of truth.
#   generated — the app invented it because no password was configured. It is
#               reissued and printed on every start, so it is never lost.
#   user      — somebody chose it. Startup never touches these.
# noqa on each: these are the *names* of the sources, not passwords.
PASSWORD_SOURCE_ENV = "env"  # noqa: S105
PASSWORD_SOURCE_GENERATED = "generated"  # noqa: S105
PASSWORD_SOURCE_USER = "user"  # noqa: S105
PASSWORD_SOURCES = (PASSWORD_SOURCE_ENV, PASSWORD_SOURCE_GENERATED, PASSWORD_SOURCE_USER)

# Capabilities an automation token can be granted. Kept coarse on purpose:
# this is a test harness, and a token that can read everything and write
# connections is the realistic unit of delegation for a CI job.
API_SCOPES = ("events:read", "connections:read", "connections:write", "sessions:read")


# --- local accounts ----------------------------------------------------------


class LocalUser(Base):
    """A username/password account that does not depend on any IdP.

    This exists so you can never lock yourself out. If a Conditional Access
    policy blocks your federated sign-in — which, when testing CA policies, is
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

    # Who owns this password — see PASSWORD_SOURCES. It decides what startup is
    # allowed to do: a password the app issued may be reissued, a password a
    # person chose may not be silently overwritten by a restart.
    # "" means unknown, which is what an upgraded database has; it is inferred
    # from must_change_password rather than guessed at.
    password_source: Mapped[str] = mapped_column(String(20), nullable=False, default="user")
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

    # Which product is at the other end — see app/providers.py. Purely
    # advisory: it selects the terminology shown beside each field on the form
    # and the setup guide linked from it, and never changes protocol behaviour.
    # Empty means "not stated", which is a legitimate answer.
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="")

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

    # Which source the rules above are evaluated against — see ROLE_SOURCES.
    # "scim" and "claims_then_scim" let a provisioned group membership decide
    # the role, which is how a great many real applications actually behave and
    # was previously impossible to test here: SCIM data had no effect on access.
    role_source: Mapped[str] = mapped_column(String(20), nullable=False, default="claims")

    # Where to read identity from. Defaults suit most IdPs; overridable because
    # "most" is not "all" — this is the field people actually need to change.
    subject_claim: Mapped[str] = mapped_column(String(200), nullable=False, default="sub")
    email_claim: Mapped[str] = mapped_column(String(200), nullable=False, default="email")
    name_claim: Mapped[str] = mapped_column(String(200), nullable=False, default="name")

    # --- expected outcome, asserted after every sign-in ---
    # Turns "sign in and squint at the claims" into a pass/fail. Empty means no
    # expectation and nothing is asserted.
    expected_role: Mapped[str] = mapped_column(String(20), nullable=False, default="")
    #   [{"claim": "amr", "operator": "contains", "value": "mfa", "description": "..."}]
    expectations: Mapped[list] = mapped_column(
        MutableList.as_mutable(JSON), nullable=False, default=list
    )

    # --- step-up / claims challenge ---
    # The condition /step-up requires. Empty stepup_value disables the page for
    # this connection.
    stepup_claim: Mapped[str] = mapped_column(String(200), nullable=False, default="amr")
    stepup_operator: Mapped[str] = mapped_column(String(20), nullable=False, default="contains")
    stepup_value: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    # What to ask the IdP for when the condition is not met. acr_values suits
    # most providers; claims_challenge carries an Entra authentication-context
    # id (the `claims` request parameter) for CA-protected actions.
    stepup_acr_values: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    stepup_claims_challenge: Mapped[str] = mapped_column(Text, nullable=False, default="")

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


class ApiToken(Base):
    """A bearer token for the automation API.

    Separate from ScimClient because the two answer to different callers and
    carry different authority: a SCIM token is handed to an identity provider's
    provisioning connector, an API token is handed to a pipeline that exports
    evidence or pushes a connection definition. Conflating them would mean
    every provisioning connector could rewrite your IdP configuration.
    """

    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    token_hint: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    # Subset of API_SCOPES.
    scopes: Mapped[list] = mapped_column(
        MutableList.as_mutable(JSON), nullable=False, default=list
    )
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

    # Encrypted at rest with the same key that protects IdP client secrets: a
    # refresh token is a long-lived credential, and storing it in the clear
    # would be worse than not offering the feature. Only present when the
    # connection asked for offline_access.
    refresh_token: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # The DPoP key thumbprint the provider bound the tokens to, if any, so the
    # dashboard can show binding without re-reading the token.
    dpop_jkt: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    # How many times this session's tokens have been refreshed.
    refresh_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
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

    This is the actual product of a Conditional Access test. A policy that
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
