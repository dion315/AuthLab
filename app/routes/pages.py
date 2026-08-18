"""The user-facing app: landing page, dashboard, and the weather widget.

The weather itself is trivial — it exists so there is something real behind the
sign-in, rather than a page that says "you are logged in". Everything else on
the dashboard is there to answer the questions you actually have while testing:
what did the provider assert, why did that produce this role, and what happens
if I ask for a stronger authentication context.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app import events
from app.auth import authn_methods
from app.auth import connections as conn
from app.auth.rolemap import describe_claim_lookup, resolve_role
from app.db import get_db
from app.deps import current_session, require_login
from app.models import UserSession
from app.templating import templates

router = APIRouter()

# Per-attempt authentication requests. None of these change the saved
# connection — each one starts a single sign-in with stronger requirements, so
# you can see whether the provider's policy actually challenges or quietly
# passes. The parameters are standard OIDC; whether a given provider honours
# them is exactly what you are testing.
OIDC_RETEST_PRESETS: list[dict[str, str]] = [
    {
        "label": "Force re-authentication",
        "query": "prompt=login",
        "help": "prompt=login — ignore any live session at the provider.",
    },
    {
        "label": "Require a fresh sign-in",
        "query": "max_age=0",
        "help": "max_age=0 — reject any prior authentication, however recent.",
    },
    {
        "label": "Request multi-factor",
        "query": "prompt=login&acr_values=mfa",
        "help": "acr_values=mfa — the portable way to ask for a second factor.",
    },
    {
        "label": "Request phishing-resistant",
        "query": "prompt=login&acr_values=phr",
        "help": "acr_values=phr — Okta and several others map this to FIDO2 or certificate.",
    },
    {
        "label": "Request a certificate context",
        "query": (
            "prompt=login&claims="
            + quote(
                '{"id_token":{"acr":{"essential":true,"values":'
                '["urn:oasis:names:tc:SAML:2.0:ac:classes:X509",'
                '"urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"]}}}',
                safe="",
            )
        ),
        "help": "A claims request for an X.509 authentication context.",
    },
    {
        "label": "Entra authentication context c1",
        "query": (
            "prompt=login&claims="
            + quote('{"access_token":{"acrs":{"essential":true,"value":"c1"}}}', safe="")
        ),
        "help": (
            "Entra ID step-up: asks for authentication context c1. Map c1 to an "
            "authentication strength (certificate, phishing-resistant) in Conditional "
            "Access at the provider first, or Entra will reject the request."
        ),
    },
    {
        "label": "Pick a different account",
        "query": "prompt=select_account",
        "help": "prompt=select_account — useful when several accounts share a browser.",
    },
]

SAML_RETEST_PRESETS: list[dict[str, str]] = [
    {
        "label": "Force re-authentication",
        "query": "force_authn=1",
        "help": "ForceAuthn=true in the AuthnRequest.",
    },
    {
        "label": "Request certificate (X.509)",
        "query": "force_authn=1&authn_context=urn:oasis:names:tc:SAML:2.0:ac:classes:X509",
        "help": "RequestedAuthnContext asking for certificate authentication.",
    },
    {
        "label": "Request smart card PKI",
        "query": "force_authn=1&authn_context=urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI",
        "help": "What a PIV or CAC card satisfies.",
    },
    {
        "label": "Request mutual TLS",
        "query": "force_authn=1&authn_context=urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient",
        "help": "Certificate presented in the TLS handshake at the IdP.",
    },
    {
        "label": "Request multi-factor (Entra)",
        "query": "force_authn=1&authn_context=http://schemas.microsoft.com/claims/multipleauthn",
        "help": "The context Entra ID uses for multi-factor over SAML.",
    },
]

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

    # Recomputed live rather than read from the session, so that editing a role
    # rule and reloading this page shows the new outcome immediately — without
    # that, testing a mapping change means a full sign-out/sign-in cycle.
    role_trace: list[dict[str, Any]] = []
    claim_lookup: dict[str, Any] = {}
    current_role = session.role
    if connection is not None:
        current_role, role_trace = resolve_role(connection, session.raw_claims or {})
        claim_lookup = describe_claim_lookup(connection, session.raw_claims or {})

    claims = session.raw_claims or {}
    presets: list[dict[str, str]] = []
    if connection is not None and connection.protocol == "oidc":
        presets = OIDC_RETEST_PRESETS
    elif connection is not None and connection.protocol == "saml":
        presets = SAML_RETEST_PRESETS

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "session": session,
            "connection": connection,
            "claims": claims,
            "policy_signals": authn_methods.policy_signals(claims),
            "authn": authn_methods.analyse(claims, protocol=session.protocol),
            "retest_presets": presets,
            "role_trace": role_trace,
            "claim_lookup": claim_lookup,
            "role_drifted": current_role != session.role,
            "current_role": current_role,
            "recent_events": events.recent(db, limit=15),
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
