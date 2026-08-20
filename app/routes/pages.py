"""The user-facing app: landing page, dashboard, and the weather widget.

The weather itself is trivial — it exists so there is something real behind the
sign-in, rather than a page that says "you are logged in". Everything else on
the dashboard is there to answer the questions you actually have while testing:
what did the IdP assert, why did that produce this role, and what happens if I
ask for a stronger authentication context.
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app import events
from app.auth import connections as conn
from app.auth import expectations, lifetimes, scimlink
from app.auth.rolemap import describe_claim_lookup, resolve_role
from app.db import get_db
from app.deps import current_session, require_login
from app.models import UserSession
from app.routes.account import evaluate_stepup
from app.templating import templates

router = APIRouter()

# Claims worth calling out when evaluating a Conditional Access policy. The
# names are OIDC/Entra conventions; SAML equivalents are matched where they
# exist. Anything not in this list still shows in the full claim dump.
NOTABLE_CLAIMS: dict[str, str] = {
    "amr": "Authentication methods actually used (e.g. pwd, mfa, fido). The claim an MFA policy changes.",
    "acr": "Authentication context class. '1' typically means single-factor.",
    "acrs": "Authentication context classes the token satisfies (Entra: step-up support).",
    "authnContextClassRef": "SAML equivalent of acr — the authentication context the IdP asserted.",
    "auth_time": "When the user actually authenticated, as opposed to when this token was issued.",
    "ipaddr": "Source IP as the IdP saw it. Compare with the address recorded below.",
    "tid": "Tenant/directory the user signed in from.",
    "oid": "Immutable object id for the user in the directory.",
    "sub": "Subject identifier — unique per user per application.",
    "groups": "Group memberships, when the IdP is configured to emit them.",
    "roles": "Application roles assigned in the IdP.",
    "wids": "Directory role template ids (Entra).",
    "deviceid": "Device identifier — present when the device is registered/compliant.",
    "xms_cc": "Client capabilities, including whether the client can handle a claims challenge.",
    "sid": "Session identifier at the IdP, used for federated sign-out.",
}

OPEN_METEO_URL = "https://api.open-meteo.com/v1/forecast"

# WMO weather interpretation codes, condensed.
WEATHER_CODES: dict[int, str] = {
    0: "Clear sky",
    1: "Mainly clear",
    2: "Partly cloudy",
    3: "Overcast",
    45: "Fog",
    48: "Depositing rime fog",
    51: "Light drizzle",
    53: "Moderate drizzle",
    55: "Dense drizzle",
    61: "Slight rain",
    63: "Moderate rain",
    65: "Heavy rain",
    71: "Slight snow",
    73: "Moderate snow",
    75: "Heavy snow",
    77: "Snow grains",
    80: "Slight rain showers",
    81: "Moderate rain showers",
    82: "Violent rain showers",
    85: "Slight snow showers",
    86: "Heavy snow showers",
    95: "Thunderstorm",
    96: "Thunderstorm with slight hail",
    99: "Thunderstorm with heavy hail",
}


@router.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession | None = Depends(current_session),
) -> Response:
    if session is not None:
        return RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request, "index.html", {"connections": conn.list_enabled(db)}
    )


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(require_login),
) -> Response:
    connection = conn.get_by_slug(db, session.source) if session.source != "local" else None
    claims = session.raw_claims or {}

    # Recomputed live rather than read from the session, so that editing a role
    # rule and reloading this page shows the new outcome immediately — without
    # that, testing a mapping change means a full sign-out/sign-in cycle.
    role_trace: list[dict[str, Any]] = []
    claim_lookup: dict[str, Any] = {}
    scim_link: dict[str, Any] = {}
    checks: dict[str, Any] = {}
    stepup: dict[str, Any] = {"configured": False, "satisfied": False}
    current_role = session.role

    if connection is not None:
        scim_link = scimlink.describe(db, session)
        scim_groups = scim_link.get("groups", [])
        current_role, role_trace = resolve_role(connection, claims, scim_groups)
        claim_lookup = describe_claim_lookup(connection, claims, scim_groups)
        checks = expectations.evaluate(connection, claims, current_role)
        stepup = evaluate_stepup(connection, claims)

    notable = [
        {"name": name, "value": claims[name], "description": description}
        for name, description in NOTABLE_CLAIMS.items()
        if name in claims
    ]

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "session": session,
            "connection": connection,
            "claims": claims,
            "notable_claims": notable,
            "role_trace": role_trace,
            "claim_lookup": claim_lookup,
            "scim_link": scim_link,
            "checks": checks,
            "stepup": stepup,
            "lifetimes": lifetimes.describe(claims, session),
            "session_outlives_token": lifetimes.outlives_token(claims, session),
            "role_drifted": current_role != session.role,
            "current_role": current_role,
            "recent_events": events.recent(db, limit=15),
            "message": request.query_params.get("message", ""),
        },
    )


@router.get("/api/weather")
async def weather(
    latitude: float = Query(..., ge=-90, le=90),
    longitude: float = Query(..., ge=-180, le=180),
    units: str = Query("fahrenheit", pattern="^(fahrenheit|celsius)$"),
    _session: UserSession = Depends(require_login),
) -> dict[str, Any]:
    """Server-side proxy to Open-Meteo.

    The browser could call Open-Meteo directly, but then the page would need
    `connect-src https://api.open-meteo.com` in its Content Security Policy.
    Proxying keeps the policy at `default-src 'self'`, and as a side effect the
    weather API never sees the user's browser or address.
    """
    params = {
        "latitude": latitude,
        "longitude": longitude,
        "current": "temperature_2m,relative_humidity_2m,wind_speed_10m,weather_code",
        "temperature_unit": units,
        "wind_speed_unit": "mph" if units == "fahrenheit" else "kmh",
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=4.0)) as client:
            response = await client.get(OPEN_METEO_URL, params=params)
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPError as exc:
        # A weather outage must not look like an auth failure.
        return {"available": False, "error": f"Weather service unavailable: {exc}"}

    current = payload.get("current", {})
    code = int(current.get("weather_code", -1))
    return {
        "available": True,
        "temperature": current.get("temperature_2m"),
        "humidity": current.get("relative_humidity_2m"),
        "wind_speed": current.get("wind_speed_10m"),
        "description": WEATHER_CODES.get(code, "Unknown conditions"),
        "units": "°F" if units == "fahrenheit" else "°C",
        "wind_units": "mph" if units == "fahrenheit" else "km/h",
    }


@router.get("/healthz")
def healthz() -> dict[str, str]:
    """Liveness probe. Deliberately does not touch the database.

    A health check that fails when the database is briefly unavailable causes
    the platform to restart or drain a container that would have recovered on
    its own. Readiness is a separate question — see /readyz.
    """
    return {"status": "ok"}


@router.get("/readyz")
def readyz(db: Session = Depends(get_db)) -> Response:
    from sqlalchemy import text

    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 — any failure means not ready
        return Response(
            content=f'{{"status":"unavailable","error":"{exc.__class__.__name__}"}}',
            media_type="application/json",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return Response(content='{"status":"ready"}', media_type="application/json")
