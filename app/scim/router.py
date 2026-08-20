"""SCIM 2.0 provisioning endpoints.

Written to satisfy the specification rather than one vendor's connector, and
verified against the request shapes Entra ID, Okta, and OneLogin actually send.

Responses use the `application/scim+json` media type. Incoming bodies are
parsed regardless of whether the client sends `application/json` or
`application/scim+json` — FastAPI treats any `*+json` subtype as JSON, which
removes a whole category of "the connector says 400 and I cannot see why".
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import events
from app.auth.connections import scim_base_url
from app.db import get_db
from app.models import ScimClient, ScimGroup, ScimUser
from app.scim import schemas as s
from app.scim.filters import AttributeMap, ScimFilterError, build_filter
from app.security import revoke_sessions_for_user, verify_token

MAX_PAGE_SIZE = 200


class ScimResponse(JSONResponse):
    media_type = "application/scim+json"


router = APIRouter(default_response_class=ScimResponse)


# --- errors ------------------------------------------------------------------


class ScimHttpError(Exception):
    def __init__(self, status_code: int, detail: str, scim_type: str | None = None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.scim_type = scim_type


async def scim_exception_handler(_request: Request, exc: Exception) -> Response:
    assert isinstance(exc, ScimHttpError)
    return ScimResponse(
        status_code=exc.status_code,
        content=s.scim_error(exc.status_code, exc.detail, exc.scim_type),
    )


# --- authentication ----------------------------------------------------------


def require_scim_client(
    request: Request,
    db: Session = Depends(get_db),
    authorization: str = Header(default=""),
) -> ScimClient:
    """Authenticate a provisioning client by bearer token.

    Tokens are compared against a keyed hash in constant time, and each client
    has its own token so that a provisioning log entry can be attributed to a
    specific system and one token can be revoked without disturbing the others.
    """
    presented = ""
    if authorization.lower().startswith("bearer "):
        presented = authorization[7:].strip()

    if not presented:
        raise ScimHttpError(
            status.HTTP_401_UNAUTHORIZED,
            "Missing bearer token. Provide the token generated in the admin console.",
        )

    for client in db.execute(select(ScimClient).where(ScimClient.enabled.is_(True))).scalars():
        if verify_token(presented, client.token_hash):
            client.last_used_at = datetime.now(UTC)
            db.commit()
            request.state.scim_client = client
            return client

    events.record(
        db,
        kind="scim_request",
        outcome="denied",
        summary="SCIM request with an invalid bearer token",
        request=request,
        detail={"path": request.url.path},
    )
    raise ScimHttpError(status.HTTP_401_UNAUTHORIZED, "Invalid or disabled bearer token.")


# --- serialisation -----------------------------------------------------------


def _meta(resource_type: str, resource_id: str, created: datetime, modified: datetime) -> dict:
    return {
        "resourceType": resource_type,
        "created": created.isoformat(),
        "lastModified": modified.isoformat(),
        "location": f"{scim_base_url()}/{resource_type}s/{resource_id}",
    }


def user_to_resource(user: ScimUser) -> dict[str, Any]:
    return {
        "schemas": [s.USER_SCHEMA],
        "id": user.id,
        "externalId": user.external_id,
        "userName": user.user_name,
        "name": {
            "formatted": user.display_name,
            "givenName": user.given_name,
            "familyName": user.family_name,
        },
        "displayName": user.display_name,
        "emails": [{"value": user.email, "primary": True, "type": "work"}] if user.email else [],
        "active": user.active,
        "groups": [
            {"value": g.id, "display": g.display_name, "$ref": f"{scim_base_url()}/Groups/{g.id}"}
            for g in user.groups
        ],
        "meta": _meta("User", user.id, user.created_at, user.updated_at),
    }


def group_to_resource(group: ScimGroup) -> dict[str, Any]:
    return {
        "schemas": [s.GROUP_SCHEMA],
        "id": group.id,
        "externalId": group.external_id,
        "displayName": group.display_name,
        "members": [
            {"value": m.id, "display": m.user_name, "type": "User"} for m in group.members
        ],
        "meta": _meta("Group", group.id, group.created_at, group.updated_at),
    }


USER_ATTRIBUTES = AttributeMap(
    {
        "id": ScimUser.id,
        "username": ScimUser.user_name,
        "externalid": ScimUser.external_id,
        "displayname": ScimUser.display_name,
        "name.givenname": ScimUser.given_name,
        "name.familyname": ScimUser.family_name,
        "emails": ScimUser.email,
        "emails.value": ScimUser.email,
        "active": ScimUser.active,
    }
)

GROUP_ATTRIBUTES = AttributeMap(
    {
        "id": ScimGroup.id,
        "displayname": ScimGroup.display_name,
        "externalid": ScimGroup.external_id,
    }
)


def _paginate(request: Request) -> tuple[int, int]:
    """Read startIndex/count. SCIM startIndex is 1-based."""
    try:
        start_index = max(1, int(request.query_params.get("startIndex", 1)))
    except ValueError:
        start_index = 1
    try:
        count = int(request.query_params.get("count", MAX_PAGE_SIZE))
    except ValueError:
        count = MAX_PAGE_SIZE
    return start_index, max(0, min(count, MAX_PAGE_SIZE))


def _log(db: Session, request: Request, summary: str, detail: dict | None = None) -> None:
    client = getattr(request.state, "scim_client", None)
    events.record(
        db,
        kind="scim_request",
        outcome="ok",
        summary=summary,
        request=request,
        subject=getattr(client, "name", ""),
        detail=detail or {},
    )


# --- discovery ---------------------------------------------------------------
#
# These three are unauthenticated on purpose: they are static capability
# documents containing no tenant data, and some connectors fetch them before
# they have credentials configured.


@router.get("/ServiceProviderConfig")
def service_provider_config() -> dict[str, Any]:
    return {
        "schemas": [s.SERVICE_PROVIDER_CONFIG_SCHEMA],
        "documentationUri": "https://datatracker.ietf.org/doc/html/rfc7644",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": MAX_PAGE_SIZE},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Bearer token issued from the AuthLab admin console.",
                "primary": True,
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": f"{scim_base_url()}/ServiceProviderConfig",
        },
    }


@router.get("/ResourceTypes")
def resource_types() -> dict[str, Any]:
    entries = [
        {
            "schemas": [s.RESOURCE_TYPE_SCHEMA],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "schema": s.USER_SCHEMA,
            "schemaExtensions": [{"schema": s.ENTERPRISE_USER_SCHEMA, "required": False}],
            "meta": {"resourceType": "ResourceType"},
        },
        {
            "schemas": [s.RESOURCE_TYPE_SCHEMA],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "schema": s.GROUP_SCHEMA,
            "meta": {"resourceType": "ResourceType"},
        },
    ]
    return {
        "schemas": [s.LIST_RESPONSE_SCHEMA],
        "totalResults": len(entries),
        "itemsPerPage": len(entries),
        "startIndex": 1,
        "Resources": entries,
    }


@router.get("/Schemas")
def schemas_endpoint() -> dict[str, Any]:
    """Schema discovery.

    Some connectors skip this entirely; others (and most conformance test
    suites) will not proceed without it, so it is implemented rather than
    left out.
    """
    definitions = [
        {
            "id": s.USER_SCHEMA,
            "name": "User",
            "description": "SCIM core User",
            "attributes": [
                _attribute("userName", required=True, uniqueness="server"),
                _attribute("externalId"),
                _attribute("displayName"),
                _attribute("active", attr_type="boolean"),
                _complex_attribute("name", ["formatted", "givenName", "familyName"]),
                _complex_attribute("emails", ["value", "type", "primary"], multi=True),
            ],
            "meta": {"resourceType": "Schema"},
        },
        {
            "id": s.GROUP_SCHEMA,
            "name": "Group",
            "description": "SCIM core Group",
            "attributes": [
                _attribute("displayName", required=True),
                _attribute("externalId"),
                _complex_attribute("members", ["value", "display", "type"], multi=True),
            ],
            "meta": {"resourceType": "Schema"},
        },
    ]
    return {
        "schemas": [s.LIST_RESPONSE_SCHEMA],
        "totalResults": len(definitions),
        "itemsPerPage": len(definitions),
        "startIndex": 1,
        "Resources": definitions,
    }


def _attribute(
    name: str, *, attr_type: str = "string", required: bool = False, uniqueness: str = "none"
) -> dict[str, Any]:
    return {
        "name": name,
        "type": attr_type,
        "multiValued": False,
        "required": required,
        "caseExact": False,
        "mutability": "readWrite",
        "returned": "default",
        "uniqueness": uniqueness,
    }


def _complex_attribute(name: str, sub_names: list[str], *, multi: bool = False) -> dict[str, Any]:
    return {
        "name": name,
        "type": "complex",
        "multiValued": multi,
        "required": False,
        "mutability": "readWrite",
        "returned": "default",
        "subAttributes": [_attribute(sub) for sub in sub_names],
    }


# --- users -------------------------------------------------------------------


@router.get("/Users")
def list_users(
    request: Request,
    db: Session = Depends(get_db),
    _client: ScimClient = Depends(require_scim_client),
) -> dict[str, Any]:
    filter_expression = request.query_params.get("filter", "")
    start_index, count = _paginate(request)

    statement = select(ScimUser)
    count_statement = select(func.count()).select_from(ScimUser)

    if filter_expression:
        try:
            clause = build_filter(filter_expression, USER_ATTRIBUTES)
        except ScimFilterError as exc:
            raise ScimHttpError(
                status.HTTP_400_BAD_REQUEST, str(exc), scim_type="invalidFilter"
            ) from exc
        if clause is not None:
            statement = statement.where(clause)
            count_statement = count_statement.where(clause)

    total = db.execute(count_statement).scalar_one()
    rows = (
        db.execute(statement.order_by(ScimUser.user_name).offset(start_index - 1).limit(count))
        .scalars()
        .all()
    )

    _log(db, request, f"GET /Users ({total} matched)", {"filter": filter_expression})
    return {
        "schemas": [s.LIST_RESPONSE_SCHEMA],
        "totalResults": total,
        "itemsPerPage": len(rows),
        "startIndex": start_index,
        "Resources": [user_to_resource(u) for u in rows],
    }


@router.get("/Users/{user_id}")
def get_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _client: ScimClient = Depends(require_scim_client),
) -> dict[str, Any]:
    user = db.get(ScimUser, user_id)
    if user is None:
        raise ScimHttpError(status.HTTP_404_NOT_FOUND, f"User {user_id} not found.")
    _log(db, request, f"GET /Users/{user_id}")
    return user_to_resource(user)


@router.post("/Users", status_code=status.HTTP_201_CREATED)
def create_user(
    payload: s.UserResource,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    _client: ScimClient = Depends(require_scim_client),
) -> dict[str, Any]:
    if not payload.userName:
        raise ScimHttpError(
            status.HTTP_400_BAD_REQUEST, "userName is required.", scim_type="invalidValue"
        )

    existing = db.execute(
        select(ScimUser).where(func.lower(ScimUser.user_name) == payload.userName.lower())
    ).scalar_one_or_none()
    if existing is not None:
        # The specification calls for 409 on a duplicate. Connectors that see
        # this generally recover by querying and then PATCHing, which is the
        # behaviour we want to exercise rather than paper over.
        raise ScimHttpError(
            status.HTTP_409_CONFLICT,
            f"A user with userName '{payload.userName}' already exists.",
            scim_type="uniqueness",
        )

    user = ScimUser(
        user_name=payload.userName,
        external_id=payload.externalId,
        display_name=payload.displayName or (payload.name.formatted if payload.name else "") or "",
        given_name=(payload.name.givenName if payload.name else "") or "",
        family_name=(payload.name.familyName if payload.name else "") or "",
        email=_primary_email(payload) or payload.userName,
        active=payload.active,
        raw_payload=payload.model_dump(mode="json", by_alias=True),
    )
    db.add(user)
    db.commit()

    _log(db, request, f"Created user {user.user_name}", {"id": user.id})
    response.status_code = status.HTTP_201_CREATED
    response.headers["Location"] = f"{scim_base_url()}/Users/{user.id}"
    return user_to_resource(user)


@router.put("/Users/{user_id}")
def replace_user(
    user_id: str,
    payload: s.UserResource,
    request: Request,
    db: Session = Depends(get_db),
    _client: ScimClient = Depends(require_scim_client),
) -> dict[str, Any]:
    user = db.get(ScimUser, user_id)
    if user is None:
        raise ScimHttpError(status.HTTP_404_NOT_FOUND, f"User {user_id} not found.")

    was_active = user.active

    user.user_name = payload.userName or user.user_name
    user.external_id = payload.externalId if payload.externalId is not None else user.external_id
    user.display_name = payload.displayName or (payload.name.formatted if payload.name else "") or ""
    user.given_name = (payload.name.givenName if payload.name else "") or ""
    user.family_name = (payload.name.familyName if payload.name else "") or ""
    user.email = _primary_email(payload) or user.email
    user.active = payload.active
    user.raw_payload = payload.model_dump(mode="json", by_alias=True)
    db.commit()

    _handle_deactivation(db, user, was_active, request)
    _log(db, request, f"Replaced user {user.user_name}")
    return user_to_resource(user)


@router.patch("/Users/{user_id}")
def patch_user(
    user_id: str,
    payload: s.PatchOp,
    request: Request,
    db: Session = Depends(get_db),
    _client: ScimClient = Depends(require_scim_client),
) -> dict[str, Any]:
    user = db.get(ScimUser, user_id)
    if user is None:
        raise ScimHttpError(status.HTTP_404_NOT_FOUND, f"User {user_id} not found.")

    was_active = user.active
    applied: list[str] = []

    for operation in payload.Operations:
        applied.extend(_apply_user_operation(db, user, operation))

    user.updated_at = datetime.now(UTC)
    db.commit()

    _handle_deactivation(db, user, was_active, request)
    _log(db, request, f"Patched user {user.user_name}", {"applied": applied})
    return user_to_resource(user)


@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _client: ScimClient = Depends(require_scim_client),
) -> Response:
    user = db.get(ScimUser, user_id)
    if user is None:
        raise ScimHttpError(status.HTTP_404_NOT_FOUND, f"User {user_id} not found.")
    subject = user.user_name
    identifiers = (user.user_name, user.email, user.external_id)
    db.delete(user)
    db.commit()
    revoked = revoke_sessions_for_user(db, *identifiers)
    _log(db, request, f"Deleted user {subject}; revoked {revoked} session(s)")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- patch application -------------------------------------------------------

# Matches "emails[type eq \"work\"].value" and similar. The data model holds a
# single email per user, so the inner filter selects nothing meaningful and the
# path is treated as plain "emails.value".
_MULTIVALUE_PATH = re.compile(r"^(?P<attr>[A-Za-z]+)\[[^\]]*\](?:\.(?P<sub>[A-Za-z]+))?$")

_USER_FIELD_MAP: dict[str, str] = {
    "username": "user_name",
    "externalid": "external_id",
    "displayname": "display_name",
    "name.givenname": "given_name",
    "name.familyname": "family_name",
    "name.formatted": "display_name",
    "emails.value": "email",
    "emails": "email",
    "active": "active",
}


def _normalise_path(path: str) -> str:
    path = (path or "").strip()
    match = _MULTIVALUE_PATH.match(path)
    if match:
        attribute = match.group("attr")
        sub = match.group("sub")
        path = f"{attribute}.{sub}" if sub else attribute
    # Extension URN prefixes are stripped: we store the handful of enterprise
    # attributes we care about alongside the core ones.
    if ":" in path:
        path = path.rsplit(":", 1)[-1]
    return path.lower()


def _set_user_field(user: ScimUser, path: str, value: Any) -> str | None:
    field = _USER_FIELD_MAP.get(_normalise_path(path))
    if field is None:
        return None
    if field == "active":
        setattr(user, field, s.coerce_bool(value, default=user.active))
    else:
        if isinstance(value, list) and value:
            first = value[0]
            value = first.get("value") if isinstance(first, dict) else first
        if isinstance(value, dict):
            value = value.get("value", "")
        setattr(user, field, "" if value is None else str(value))
    return field


def _apply_user_operation(db: Session, user: ScimUser, operation: s.PatchOperation) -> list[str]:
    """Apply one PATCH operation.

    Handles both shapes seen in the wild: an explicit `path`, and a path-less
    replace whose `value` is an object of attributes.
    """
    op = (operation.op or "").lower()
    applied: list[str] = []

    if op == "remove":
        if operation.path:
            field = _USER_FIELD_MAP.get(_normalise_path(operation.path))
            if field == "active":
                user.active = False
                applied.append("active")
            elif field:
                setattr(user, field, "")
                applied.append(field)
        return applied

    if op not in ("add", "replace"):
        raise ScimHttpError(
            status.HTTP_400_BAD_REQUEST,
            f"Unsupported PATCH op '{operation.op}'.",
            scim_type="invalidSyntax",
        )

    if operation.path:
        field = _set_user_field(user, operation.path, operation.value)
        if field:
            applied.append(field)
        return applied

    # No path: value is an object whose keys are attribute paths.
    if isinstance(operation.value, dict):
        for key, value in operation.value.items():
            field = _set_user_field(user, key, value)
            if field:
                applied.append(field)
    return applied


def _handle_deactivation(
    db: Session, user: ScimUser, was_active: bool, request: Request
) -> None:
    """When provisioning deactivates a user, end their sessions immediately.

    This is the behaviour people actually want to see when they test SCIM
    deprovisioning: access should stop now, not whenever a token happens to
    expire. It is only possible because sessions are server-side.
    """
    if was_active and not user.active:
        # Every identifier the session could have been recorded under: the
        # subject claim may be a pairwise `sub`, an email, or the externalId
        # the provider also sends over SCIM.
        revoked = revoke_sessions_for_user(
            db, user.user_name, user.email, user.external_id
        )
        events.record(
            db,
            kind="scim_request",
            outcome="ok",
            summary=f"Deactivated {user.user_name}; revoked {revoked} session(s)",
            request=request,
            subject=user.user_name,
            detail={"sessions_revoked": revoked},
        )


def _primary_email(payload: s.UserResource) -> str:
    for email in payload.emails:
        if email.primary and email.value:
            return email.value
    for email in payload.emails:
        if email.value:
            return email.value
    return ""


# --- groups ------------------------------------------------------------------


@router.get("/Groups")
def list_groups(
    request: Request,
    db: Session = Depends(get_db),
    _client: ScimClient = Depends(require_scim_client),
) -> dict[str, Any]:
    filter_expression = request.query_params.get("filter", "")
    start_index, count = _paginate(request)

    statement = select(ScimGroup)
    count_statement = select(func.count()).select_from(ScimGroup)

    if filter_expression:
        try:
            clause = build_filter(filter_expression, GROUP_ATTRIBUTES)
        except ScimFilterError as exc:
            raise ScimHttpError(
                status.HTTP_400_BAD_REQUEST, str(exc), scim_type="invalidFilter"
            ) from exc
        if clause is not None:
            statement = statement.where(clause)
            count_statement = count_statement.where(clause)

    total = db.execute(count_statement).scalar_one()
    rows = (
        db.execute(statement.order_by(ScimGroup.display_name).offset(start_index - 1).limit(count))
        .scalars()
        .all()
    )

    _log(db, request, f"GET /Groups ({total} matched)", {"filter": filter_expression})
    return {
        "schemas": [s.LIST_RESPONSE_SCHEMA],
        "totalResults": total,
        "itemsPerPage": len(rows),
        "startIndex": start_index,
        "Resources": [group_to_resource(g) for g in rows],
    }


@router.get("/Groups/{group_id}")
def get_group(
    group_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _client: ScimClient = Depends(require_scim_client),
) -> dict[str, Any]:
    group = db.get(ScimGroup, group_id)
    if group is None:
        raise ScimHttpError(status.HTTP_404_NOT_FOUND, f"Group {group_id} not found.")
    _log(db, request, f"GET /Groups/{group_id}")
    return group_to_resource(group)


@router.post("/Groups", status_code=status.HTTP_201_CREATED)
def create_group(
    payload: s.GroupResource,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    _client: ScimClient = Depends(require_scim_client),
) -> dict[str, Any]:
    if not payload.displayName:
        raise ScimHttpError(
            status.HTTP_400_BAD_REQUEST, "displayName is required.", scim_type="invalidValue"
        )

    existing = db.execute(
        select(ScimGroup).where(func.lower(ScimGroup.display_name) == payload.displayName.lower())
    ).scalar_one_or_none()
    if existing is not None:
        raise ScimHttpError(
            status.HTTP_409_CONFLICT,
            f"A group named '{payload.displayName}' already exists.",
            scim_type="uniqueness",
        )

    group = ScimGroup(
        display_name=payload.displayName,
        external_id=payload.externalId,
        raw_payload=payload.model_dump(mode="json", by_alias=True),
    )
    group.members = _resolve_members(db, [m.value for m in payload.members if m.value])
    db.add(group)
    db.commit()

    _log(db, request, f"Created group {group.display_name}", {"id": group.id})
    response.headers["Location"] = f"{scim_base_url()}/Groups/{group.id}"
    return group_to_resource(group)


@router.put("/Groups/{group_id}")
def replace_group(
    group_id: str,
    payload: s.GroupResource,
    request: Request,
    db: Session = Depends(get_db),
    _client: ScimClient = Depends(require_scim_client),
) -> dict[str, Any]:
    group = db.get(ScimGroup, group_id)
    if group is None:
        raise ScimHttpError(status.HTTP_404_NOT_FOUND, f"Group {group_id} not found.")

    group.display_name = payload.displayName or group.display_name
    group.external_id = payload.externalId if payload.externalId is not None else group.external_id
    group.members = _resolve_members(db, [m.value for m in payload.members if m.value])
    group.raw_payload = payload.model_dump(mode="json", by_alias=True)
    db.commit()

    _log(db, request, f"Replaced group {group.display_name}")
    return group_to_resource(group)


@router.patch("/Groups/{group_id}")
def patch_group(
    group_id: str,
    payload: s.PatchOp,
    request: Request,
    db: Session = Depends(get_db),
    _client: ScimClient = Depends(require_scim_client),
) -> dict[str, Any]:
    group = db.get(ScimGroup, group_id)
    if group is None:
        raise ScimHttpError(status.HTTP_404_NOT_FOUND, f"Group {group_id} not found.")

    for operation in payload.Operations:
        op = (operation.op or "").lower()
        path = _normalise_path(operation.path or "")

        if path == "displayname" and op in ("add", "replace"):
            group.display_name = str(operation.value or group.display_name)
            continue

        if path != "members":
            if op in ("add", "replace") and isinstance(operation.value, dict):
                display = operation.value.get("displayName")
                if display:
                    group.display_name = str(display)
            continue

        member_ids = _member_ids(operation.value)

        if op == "add":
            current = {m.id for m in group.members}
            group.members = group.members + [
                u for u in _resolve_members(db, member_ids) if u.id not in current
            ]
        elif op == "replace":
            group.members = _resolve_members(db, member_ids)
        elif op == "remove":
            if not member_ids and operation.path and "[" in operation.path:
                # "members[value eq \"<id>\"]" — pull the id out of the filter.
                found = re.findall(r'"([^"]+)"', operation.path)
                member_ids = found
            removing = set(member_ids)
            group.members = [m for m in group.members if m.id not in removing]

    group.updated_at = datetime.now(UTC)
    db.commit()

    _log(db, request, f"Patched group {group.display_name}")
    return group_to_resource(group)


@router.delete("/Groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_group(
    group_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _client: ScimClient = Depends(require_scim_client),
) -> Response:
    group = db.get(ScimGroup, group_id)
    if group is None:
        raise ScimHttpError(status.HTTP_404_NOT_FOUND, f"Group {group_id} not found.")
    name = group.display_name
    db.delete(group)
    db.commit()
    _log(db, request, f"Deleted group {name}")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _member_ids(value: Any) -> list[str]:
    if isinstance(value, list):
        return [
            str(item.get("value")) if isinstance(item, dict) else str(item)
            for item in value
            if item
        ]
    if isinstance(value, dict) and value.get("value"):
        return [str(value["value"])]
    return []


def _resolve_members(db: Session, member_ids: list[str]) -> list[ScimUser]:
    if not member_ids:
        return []
    return list(
        db.execute(select(ScimUser).where(ScimUser.id.in_(member_ids))).scalars().all()
    )
