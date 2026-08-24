"""In-app setup guides.

Configuring a provider is a back-and-forth between two browser tabs, and the
tab with the instructions in it should be the one that already knows your
redirect URI. Keeping the guides here rather than only in the repository means
the steps arrive with the real values substituted into them — a copy box with
`https://authlab.contoso.com/auth/saml/entra/acs` in it, rather than a pattern
you have to assemble.

The content comes from app/providers.py, which is also what supplies the
terminology hints on the connection form. One source, so a hint cannot
contradict the walkthrough two clicks away.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app import providers
from app.auth import connections as conn
from app.config import get_settings
from app.db import get_db
from app.deps import require_login
from app.models import UserSession
from app.templating import templates

router = APIRouter()


def urls_for(db: Session, slug: str) -> dict[str, str]:
    """The values a guide tells you to paste.

    With a real connection slug these are the actual URLs. Without one they are
    readable patterns containing {slug}, so the guides are worth reading before
    anything has been created — which is when people usually read them.
    """
    base = get_settings().base_url.rstrip("/")
    if not slug:
        slug = "{slug}"
    connection = conn.get_by_slug(db, slug) if slug != "{slug}" else None

    return {
        "base_url": base,
        "login_url": f"{base}/login",
        "redirect_uri": f"{base}/auth/oidc/{slug}/callback",
        "acs_url": f"{base}/auth/saml/{slug}/acs",
        "sls_url": f"{base}/auth/saml/{slug}/sls",
        "metadata_url": f"{base}/auth/saml/{slug}/metadata",
        "scim_tenant_url": f"{base}/scim/v2",
        "sp_entity_id": (
            conn.load_settings(connection).sp_entity_id  # type: ignore[union-attr]
            if connection is not None and connection.protocol == "saml"
            and conn.load_settings(connection).sp_entity_id  # type: ignore[union-attr]
            else f"{base}/auth/saml/{slug}/metadata"
        ),
    }


@router.get("/help", response_class=HTMLResponse)
def help_index(
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(require_login),
) -> Response:
    return templates.TemplateResponse(
        request,
        "help/index.html",
        {
            "session": session,
            "matrix": providers.capability_matrix(),
            "protocol_names": providers.PROTOCOL_NAMES,
            "connections": conn.list_all(db),
        },
    )


@router.get("/help/{provider_key}", response_class=HTMLResponse)
def help_provider(
    provider_key: str,
    request: Request,
    db: Session = Depends(get_db),
    session: UserSession = Depends(require_login),
) -> Response:
    provider = providers.get(provider_key)
    if provider is None:
        return RedirectResponse("/help", status_code=status.HTTP_303_SEE_OTHER)

    # A protocol may be requested; otherwise show the first one this provider
    # actually supports, so nobody lands on an "unsupported" page by default.
    requested = request.query_params.get("protocol", "")
    order = ("oidc", "saml", "scim")
    if requested not in order:
        requested = next(
            (p for p in order if provider.supports(p)),
            next(iter(provider.guides), "oidc"),
        )

    slug = request.query_params.get("slug", "")
    urls = urls_for(db, slug)
    guide = provider.guide(requested)

    steps: list[dict[str, Any]] = []
    if guide is not None and guide.supported:
        steps = [
            {
                "number": index + 1,
                "title": step.title,
                "body": providers.resolve(step.body, urls),
                "paste": urls.get(step.paste, "") if step.paste else "",
                "paste_label": step.paste.replace("_", " ") if step.paste else "",
            }
            for index, step in enumerate(guide.steps)
        ]

    connection = conn.get_by_slug(db, slug) if slug else None

    return templates.TemplateResponse(
        request,
        "help/provider.html",
        {
            "session": session,
            "provider": provider,
            "protocol": requested,
            "protocol_names": providers.PROTOCOL_NAMES,
            "guide": guide,
            "steps": steps,
            "connection": connection,
            "slug": slug,
            "using_real_urls": bool(connection),
            "connections": conn.list_all(db),
            "all_providers": providers.choices(),
        },
    )
