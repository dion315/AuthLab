"""Loading and saving IdP connections, with secret encryption applied.

All reads and writes of IdpConnection.config go through here so that encryption
is never something a caller has to remember to do.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.schemas import SECRET_FIELDS, SETTINGS_MODELS, OidcSettings, SamlSettings
from app.config import get_settings
from app.crypto import decrypt, encrypt, is_encrypted
from app.models import IdpConnection

# Rendered in place of a stored secret so the real value never reaches the
# browser. Not a credential itself.
SECRET_PLACEHOLDER = "********"  # noqa: S105


def load_settings(connection: IdpConnection) -> OidcSettings | SamlSettings:
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


# --- portable definitions ----------------------------------------------------
#
# A connection is a dozen fields spread over four sections of a form, and half
# of them are provider-specific strings nobody remembers. Exporting the working
# one and importing it somewhere else is how a colleague gets the same setup
# without retyping it, and how a pipeline stands up a known state before a test.

# Never exported, whatever the protocol. These are the fields the admin UI also
# refuses to render back, for the same reason.
EXPORT_EXCLUDED: set[str] = {field for fields in SECRET_FIELDS.values() for field in fields}

# Columns carried in an exported definition. `slug` is the identity, so an
# import updates rather than duplicates when the slug already exists.
_PORTABLE_COLUMNS = (
    "slug",
    "name",
    "protocol",
    "enabled",
    "role_claim",
    "role_rules",
    "role_source",
    "default_role",
    "subject_claim",
    "email_claim",
    "name_claim",
    "expected_role",
    "expectations",
    "stepup_claim",
    "stepup_operator",
    "stepup_value",
    "stepup_acr_values",
    "stepup_claims_challenge",
)


def export_connection(connection: IdpConnection) -> dict[str, Any]:
    """A connection as portable JSON, with every secret removed.

    Secrets are omitted rather than blanked so an import cannot silently clear
    a client secret that is already correctly configured at the destination —
    `store_settings` treats a missing secret as "leave what is there".
    """
    settings_obj = load_settings(connection)
    config = settings_obj.model_dump()
    for field in EXPORT_EXCLUDED:
        config.pop(field, None)

    data: dict[str, Any] = {key: getattr(connection, key) for key in _PORTABLE_COLUMNS}
    data["config"] = config
    # Named so anyone reading the file knows what it will and will not carry.
    data["secrets_excluded"] = sorted(EXPORT_EXCLUDED & set(settings_obj.model_dump().keys()))
    return data


def import_connection(db: Session, data: dict[str, Any]) -> tuple[IdpConnection, bool]:
    """Create or update a connection from an exported definition.

    Returns (connection, created). Raises ValueError with a readable message
    for anything that cannot be applied, because the caller is usually a
    pipeline whose only feedback channel is the error string.
    """
    protocol = str(data.get("protocol", "")).strip()
    if protocol not in SETTINGS_MODELS:
        raise ValueError(f"Unknown protocol '{protocol}'. Expected one of {sorted(SETTINGS_MODELS)}.")

    slug = str(data.get("slug", "")).strip().lower()
    if not slug:
        raise ValueError("A 'slug' is required — it identifies the connection to create or update.")

    config = data.get("config") or {}
    if not isinstance(config, dict):
        raise ValueError("'config' must be an object.")

    errors = validate_config(protocol, {**config, **{f: "" for f in EXPORT_EXCLUDED}})
    if errors:
        raise ValueError("; ".join(errors))

    connection = get_by_slug(db, slug)
    created = connection is None
    if connection is None:
        connection = IdpConnection(slug=slug, protocol=protocol, config={})
        db.add(connection)
    elif connection.protocol != protocol:
        raise ValueError(
            f"Connection '{slug}' already exists with protocol "
            f"'{connection.protocol}'; refusing to change it to '{protocol}'."
        )

    for key in _PORTABLE_COLUMNS:
        if key in ("slug", "protocol") or key not in data:
            continue
        setattr(connection, key, data[key])

    # Secrets absent from the payload keep whatever is already stored.
    store_settings(connection, dict(config))
    db.commit()
    return connection, created


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


def scim_base_url() -> str:
    return f"{get_settings().base_url.rstrip('/')}/scim/v2"
