"""Loading and saving IdP connections, with secret encryption applied.

All reads and writes of IdpConnection.config go through here so that encryption
is never something a caller has to remember to do.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.schemas import (
    SECRET_FIELDS,
    SETTINGS_MODELS,
    MtlsSettings,
    OidcSettings,
    SamlSettings,
)
from app.config import get_settings
from app.crypto import decrypt, encrypt, is_encrypted
from app.models import IdpConnection

# Rendered in place of a stored secret so the real value never reaches the
# browser. Not a credential itself.
SECRET_PLACEHOLDER = "********"  # noqa: S105


def load_settings(connection: IdpConnection) -> OidcSettings | SamlSettings | MtlsSettings:
    """Parsed protocol settings with secrets decrypted, ready to use."""
    model = SETTINGS_MODELS[connection.protocol]
    raw = dict(connection.config or {})
    for field in SECRET_FIELDS.get(connection.protocol, set()):
        if field in raw:
            raw[field] = decrypt(raw[field]) or ""
    return model(**raw)


def store_settings(connection: IdpConnection, data: dict[str, Any]) -> None:
    """Validate and write protocol settings, encrypting secret fields.

    A secret submitted as the placeholder means "unchanged" — the admin UI
    never renders a stored secret back to the browser, so the form has nothing
    real to submit unless the operator typed a new value.
    """
    protocol = connection.protocol
    model = SETTINGS_MODELS[protocol]
    secrets_for_protocol = SECRET_FIELDS.get(protocol, set())
    existing = dict(connection.config or {})

    merged = dict(data)
    for field in secrets_for_protocol:
        submitted = merged.get(field, "")
        if submitted in ("", SECRET_PLACEHOLDER):
            # Keep what is already stored (still encrypted).
            merged[field] = decrypt(existing.get(field)) or ""

    validated = model(**merged).model_dump()

    for field in secrets_for_protocol:
        value = validated.get(field)
        if value and not is_encrypted(value):
            validated[field] = encrypt(value)

    connection.config = validated


def redacted_config(connection: IdpConnection) -> dict[str, Any]:
    """Config safe to render in a form — secrets replaced with a placeholder."""
    settings_obj = load_settings(connection)
    data = settings_obj.model_dump()
    for field in SECRET_FIELDS.get(connection.protocol, set()):
        data[field] = SECRET_PLACEHOLDER if data.get(field) else ""
    return data


def validate_config(protocol: str, data: dict[str, Any]) -> list[str]:
    """Return human-readable validation errors, or an empty list."""
    model = SETTINGS_MODELS.get(protocol)
    if model is None:
        return [f"Unknown protocol '{protocol}'"]
    try:
        model(**data)
    except ValidationError as exc:
        return [
            f"{'.'.join(str(p) for p in err['loc']) or 'config'}: {err['msg']}"
            for err in exc.errors()
        ]
    return []


# --- queries -----------------------------------------------------------------


def get_by_slug(db: Session, slug: str) -> IdpConnection | None:
    return db.execute(
        select(IdpConnection).where(IdpConnection.slug == slug)
    ).scalar_one_or_none()


def list_all(db: Session) -> list[IdpConnection]:
    return list(db.execute(select(IdpConnection).order_by(IdpConnection.name)).scalars().all())


def list_enabled(db: Session) -> list[IdpConnection]:
    return [c for c in list_all(db) if c.enabled]


# --- derived URLs ------------------------------------------------------------
#
# Computed from BASE_URL rather than stored, so they cannot drift out of sync
# with where the app is actually running. These are the values you paste into
# the IdP console, and the admin UI displays them for copying.


def redirect_uri(slug: str) -> str:
    return f"{get_settings().base_url.rstrip('/')}/auth/oidc/{slug}/callback"


def acs_url(slug: str) -> str:
    return f"{get_settings().base_url.rstrip('/')}/auth/saml/{slug}/acs"


def sls_url(slug: str) -> str:
    return f"{get_settings().base_url.rstrip('/')}/auth/saml/{slug}/sls"


def metadata_url(slug: str) -> str:
    return f"{get_settings().base_url.rstrip('/')}/auth/saml/{slug}/metadata"


def mtls_login_url(slug: str) -> str:
    return f"{get_settings().base_url.rstrip('/')}/auth/mtls/{slug}/login"


def mtls_inspect_url(slug: str) -> str:
    return f"{get_settings().base_url.rstrip('/')}/auth/mtls/{slug}/inspect"


def scim_base_url() -> str:
    return f"{get_settings().base_url.rstrip('/')}/scim/v2"
