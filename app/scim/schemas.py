"""SCIM 2.0 resource shapes (RFC 7643) as Pydantic models.

Beyond documentation, these do real work: FastAPI validates incoming bodies
against them, so a malformed provisioning request produces a 400 describing the
offending field instead of an AttributeError halfway through a write.

Note on booleans — Pydantic coerces the string "False" to False automatically,
which matters because several provisioning connectors send `active` as a
JSON string rather than a JSON boolean. Getting that wrong means a
deprovisioned user stays enabled, so it is covered by a test.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
ENTERPRISE_USER_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SERVICE_PROVIDER_CONFIG_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
RESOURCE_TYPE_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"


class ScimModel(BaseModel):
    # Provisioning clients send extension attributes and vendor-specific keys
    # freely; rejecting unknown fields would break real connectors, so they are
    # accepted and preserved in raw_payload for inspection.
    model_config = ConfigDict(populate_by_name=True, extra="allow")


class Name(ScimModel):
    formatted: str | None = None
    givenName: str | None = None  # noqa: N815 — SCIM wire format is camelCase
    familyName: str | None = None  # noqa: N815


class Email(ScimModel):
    value: str | None = None
    type: str | None = None
    primary: bool | None = None


class GroupRef(ScimModel):
    value: str | None = None
    display: str | None = None
    ref: str | None = Field(default=None, alias="$ref")


class Member(ScimModel):
    value: str | None = None
    display: str | None = None
    type: str | None = None


class Meta(ScimModel):
    resourceType: str | None = None  # noqa: N815
    created: str | None = None
    lastModified: str | None = None  # noqa: N815
    location: str | None = None
    version: str | None = None


class UserResource(ScimModel):
    schemas: list[str] = Field(default_factory=lambda: [USER_SCHEMA])
    id: str | None = None
    externalId: str | None = None  # noqa: N815
    userName: str | None = None  # noqa: N815
    name: Name | None = None
    displayName: str | None = None  # noqa: N815
    emails: list[Email] = Field(default_factory=list)
    active: bool = True
    groups: list[GroupRef] = Field(default_factory=list)
    meta: Meta | None = None


class GroupResource(ScimModel):
    schemas: list[str] = Field(default_factory=lambda: [GROUP_SCHEMA])
    id: str | None = None
    externalId: str | None = None  # noqa: N815
    displayName: str | None = None  # noqa: N815
    members: list[Member] = Field(default_factory=list)
    meta: Meta | None = None


class PatchOperation(ScimModel):
    # Case varies between connectors: "replace", "Replace", and "REPLACE" all
    # appear. Normalised at use rather than validated strictly here.
    op: str
    path: str | None = None
    value: Any = None


class PatchOp(ScimModel):
    schemas: list[str] = Field(default_factory=lambda: [PATCH_OP_SCHEMA])
    Operations: list[PatchOperation] = Field(default_factory=list)  # noqa: N815


T = TypeVar("T")


class ListResponse(BaseModel, Generic[T]):
    schemas: list[str] = Field(default_factory=lambda: [LIST_RESPONSE_SCHEMA])
    totalResults: int  # noqa: N815
    itemsPerPage: int  # noqa: N815
    startIndex: int  # noqa: N815
    Resources: list[T] = Field(default_factory=list)  # noqa: N815


def scim_error(status_code: int, detail: str, scim_type: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schemas": [ERROR_SCHEMA],
        "detail": detail,
        # The specification says status is a string here, and some connectors
        # do parse it strictly.
        "status": str(status_code),
    }
    if scim_type:
        body["scimType"] = scim_type
    return body


def coerce_bool(value: Any, default: bool = False) -> bool:
    """Interpret a SCIM boolean that may not be a JSON boolean.

    Entra ID in particular sends {"path": "active", "value": "False"} — a
    string. Treating that as truthy silently keeps deprovisioned users enabled,
    which is the single most common bug in hand-rolled SCIM servers.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes", "on", "t"):
            return True
        if lowered in ("false", "0", "no", "off", "f", ""):
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, dict) and "active" in value:
        return coerce_bool(value["active"], default)
    return default
