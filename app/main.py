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
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from app.auth.router import bootstrap_local_admin
from app.auth.router import router as auth_router
from app.config import get_settings
from app.db import engine, session_scope
from app.models import Base
from app.routes.admin import router as admin_router
from app.routes.pages import router as pages_router
from app.scim import schemas as scim_schemas
from app.scim.router import ScimHttpError, ScimResponse
from app.scim.router import router as scim_router
from app.templating import STATIC_DIR, templates

logger = logging.getLogger("authlab")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings = get_settings()

    # create_all is enough for a self-contained harness whose schema only ever
    # changes with the code. A service carrying data across versions should use
    # Alembic instead; the models here are ordinary SQLAlchemy so that is a
    # drop-in change.
    Base.metadata.create_all(bind=engine)

    with session_scope() as db:
        created = bootstrap_local_admin(db)

    if created:
        email, password = created
        # Printed once, never stored in plaintext, and only when we generated
        # it ourselves.
        logger.warning(
            "\n%s\n  First-run local administrator created\n    email:    %s\n"
            "    password: %s\n  Sign in at %s/login and change it.\n%s",
            "=" * 68,
            email,
            password,
            settings.base_url.rstrip("/"),
            "=" * 68,
        )

    logger.info("AuthLab ready at %s", settings.base_url)
    yield


app = FastAPI(
    title="AuthLab",
    description=(
        "IdP-agnostic harness for OIDC/OAuth 2.0, SAML 2.0, certificate-based "
        "authentication, SCIM 2.0 provisioning, and access policy evaluation."
    ),
    version="1.0.0",
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
    #
    # Scoped to the metadata path rather than all of /auth/saml/, because the
    # ACS and SLS endpoints do render HTML — an assertion that fails validation
    # produces an error page carrying the provider's own text — and those pages
    # want the policy as much as any other.
    path = request.url.path
    exempt = path.startswith("/scim/") or (
        path.startswith("/auth/saml/") and path.endswith("/metadata")
    )
    if not exempt:
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
app.include_router(admin_router, prefix="/admin", tags=["admin"])
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
