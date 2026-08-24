"""Application entrypoint.

Wires together middleware, routers, and error handling. Two things here are
worth reading closely because they are where the previous version of this app
went wrong:

  * The Content Security Policy is strict — `default-src 'self'` with no
    inline scripts or styles anywhere. That is only possible because every
    script and stylesheet is a real file under /static and the weather call is
    proxied server-side. A CSP that has to be loosened to make the app work is
    not providing much.
  * Nothing that can fail at request time is allowed to take the process down.
    Every handler that talks to an IdP catches its own errors, and there is a
    catch-all below for anything that slips through.
  * Startup reconciles rather than assumes. It adds any columns the models have
    grown since the database was created, and brings the local administrator
    password back in line with the environment — so redeploying over an
    existing database, or editing .env to get back in, both just work.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from app.auth.router import AdminPasswordState, sync_local_admin
from app.auth.router import router as auth_router
from app.config import get_settings
from app.db import engine, session_scope
from app.models import PASSWORD_SOURCE_ENV, Base
from app.routes.account import router as account_router
from app.routes.admin import router as admin_router
from app.routes.api import router as api_router
from app.routes.help import router as help_router
from app.routes.pages import router as pages_router
from app.schema_sync import sync_schema
from app.scim import schemas as scim_schemas
from app.scim.router import ScimHttpError, ScimResponse
from app.scim.router import router as scim_router
from app.templating import STATIC_DIR, templates

logger = logging.getLogger("authlab")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings = get_settings()

    # create_all builds anything missing, but it never alters a table that
    # already exists — so an upgrade that adds a column would leave a populated
    # database unreadable. sync_schema closes that one gap, additively. Neither
    # is a substitute for Alembic once real data has to survive a schema
    # change; the models here are ordinary SQLAlchemy so that is a drop-in.
    Base.metadata.create_all(bind=engine)
    added_columns = sync_schema(engine)
    if added_columns:
        logger.warning(
            "Added missing columns to an existing database: %s",
            ", ".join(added_columns),
        )

    with session_scope() as db:
        admin = sync_local_admin(db)

    _log_admin_password(admin, settings.base_url.rstrip("/"))

    logger.info("AuthLab ready at %s", settings.base_url)
    yield


def _log_admin_password(admin: AdminPasswordState, base_url: str) -> None:
    """Say what happened to the local administrator password, every start.

    The banner is printed whenever the app knows the plaintext, which is
    whenever it just issued one. That is deliberate: an unconfigured password
    that scrolls past once in a wall of container output is a password you have
    lost. Reissuing and reprinting it means the worst case is a restart.

    The trade is that the password is then in the container log, and in
    anything collecting it. That is acceptable for a harness whose whole job is
    being taken apart and rebuilt, and it is why setting
    BOOTSTRAP_ADMIN_PASSWORD — which is never logged — is the better answer for
    anything that lives longer than an afternoon.
    """
    if admin.password:
        logger.warning(
            "\n%s\n  Local administrator %s\n    email:    %s\n    password: %s\n"
            "  Sign in at %s/login\n\n"
            "  This password was generated because BOOTSTRAP_ADMIN_PASSWORD is\n"
            "  not set, and it is regenerated and shown on every start. It is\n"
            "  therefore in this log. Set BOOTSTRAP_ADMIN_PASSWORD to choose a\n"
            "  stable one that is never printed, or change it in the console to\n"
            "  take it out of the app's hands entirely.\n%s",
            "=" * 68,
            "created" if admin.created else "password reissued",
            admin.email,
            admin.password,
            base_url,
            "=" * 68,
        )
        return

    if admin.source == PASSWORD_SOURCE_ENV:
        logger.info(
            "Local administrator %s: password %s from BOOTSTRAP_ADMIN_PASSWORD.",
            admin.email,
            "set" if admin.created else ("reapplied" if admin.changed else "matches"),
        )
        return

    logger.info(
        "Local administrator %s: password was changed in the console, so it is "
        "left alone and cannot be displayed. Set BOOTSTRAP_ADMIN_PASSWORD and "
        "restart to reset it.",
        admin.email,
    )


app = FastAPI(
    title="AuthLab",
    description=(
        "IdP-agnostic harness for OIDC/OAuth 2.0, SAML 2.0, SCIM 2.0 provisioning, "
        "access token validation, and Conditional Access evaluation."
    ),
    version="1.2.0",
    lifespan=lifespan,
    # The interactive docs are genuinely useful here — they give the SCIM
    # endpoints a browsable reference without writing one.
    docs_url="/docs",
    redoc_url=None,
    openapi_url="/openapi.json",
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# --- middleware --------------------------------------------------------------


@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    settings = get_settings()

    # The SP metadata endpoint returns XML for an IdP to consume, and the SCIM
    # endpoints are machine-to-machine; browser protections do not apply.
    if not request.url.path.startswith(("/scim/", "/auth/saml/")):
        response.headers.setdefault(
            "Content-Security-Policy",
            "; ".join(
                [
                    "default-src 'self'",
                    "base-uri 'self'",
                    "form-action 'self'",
                    "frame-ancestors 'none'",
                    "object-src 'none'",
                    "img-src 'self' data:",
                    "style-src 'self'",
                    "script-src 'self'",
                    "connect-src 'self'",
                ]
            ),
        )

    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(self), camera=(), microphone=()"
    )
    if settings.cookies_secure:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


# --- error handling ----------------------------------------------------------


def _wants_html(request: Request) -> bool:
    if request.url.path.startswith(("/scim/", "/api/")):
        return False
    return "text/html" in request.headers.get("accept", "")


@app.exception_handler(ScimHttpError)
async def handle_scim_error(_request: Request, exc: Exception) -> Response:
    assert isinstance(exc, ScimHttpError)
    return ScimResponse(
        status_code=exc.status_code,
        content=scim_schemas.scim_error(exc.status_code, exc.detail, exc.scim_type),
    )


@app.exception_handler(RequestValidationError)
async def handle_validation_error(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, RequestValidationError)
    detail = "; ".join(
        f"{'.'.join(str(p) for p in err['loc'][1:]) or 'body'}: {err['msg']}"
        for err in exc.errors()
    )
    if request.url.path.startswith("/scim/"):
        # Provisioning connectors surface this string in their own logs, so it
        # needs to name the offending attribute.
        return ScimResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=scim_schemas.scim_error(400, detail or "Invalid request body.", "invalidValue"),
        )
    if _wants_html(request):
        return templates.TemplateResponse(
            request,
            "auth_error.html",
            {"title": "Invalid request", "message": detail, "detail": {}},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": detail})


@app.exception_handler(HTTPException)
async def handle_http_exception(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, HTTPException)
    location = (exc.headers or {}).get("Location")
    if location and exc.status_code in (301, 302, 303, 307, 308):
        return RedirectResponse(location, status_code=exc.status_code)

    if request.url.path.startswith("/scim/"):
        return ScimResponse(
            status_code=exc.status_code,
            content=scim_schemas.scim_error(exc.status_code, str(exc.detail)),
        )

    if _wants_html(request):
        titles = {
            403: "Access denied",
            404: "Not found",
            429: "Too many requests",
        }
        return templates.TemplateResponse(
            request,
            "auth_error.html",
            {
                "title": titles.get(exc.status_code, f"Error {exc.status_code}"),
                "message": str(exc.detail),
                "detail": {},
            },
            status_code=exc.status_code,
        )

    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(Exception)
async def handle_unexpected(request: Request, exc: Exception) -> Response:
    """Catch-all.

    The full exception goes to the log; the response says only that something
    failed. An unexpected error must never become a stack trace rendered to a
    browser, and — more importantly for a long-running test harness — must
    never terminate the process.
    """
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)

    if request.url.path.startswith("/scim/"):
        return ScimResponse(
            status_code=500,
            content=scim_schemas.scim_error(500, "Internal server error."),
        )
    if _wants_html(request):
        return templates.TemplateResponse(
            request,
            "auth_error.html",
            {
                "title": "Something went wrong",
                "message": (
                    "An unexpected error occurred. The details were written to the "
                    "application log."
                ),
                "detail": {"type": exc.__class__.__name__},
            },
            status_code=500,
        )
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- routes ------------------------------------------------------------------

app.include_router(pages_router, tags=["app"])
app.include_router(auth_router, tags=["auth"])
app.include_router(account_router, tags=["account"])
app.include_router(help_router, tags=["help"])
app.include_router(admin_router, prefix="/admin", tags=["admin"])
app.include_router(api_router, tags=["automation"])
app.include_router(scim_router, prefix="/scim/v2", tags=["scim"])


def run() -> None:
    """Entrypoint for `python -m app.main`."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        # Tells uvicorn to honour X-Forwarded-* from the platform's load
        # balancer, which is what makes request.url.scheme correct behind
        # Container Apps, App Runner, and Cloud Run.
        proxy_headers=settings.trust_proxy_headers,
        forwarded_allow_ips="*" if settings.trust_proxy_headers else None,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run()
