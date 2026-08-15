"""Jinja2 setup.

Autoescaping is on for every template, which is what makes it safe to render
IdP-supplied display names and SCIM-supplied attributes. Those are attacker-
influenced strings: an IdP can assert any name it likes, and anyone holding a
provisioning token can set any displayName they like.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.templating import Jinja2Templates

from app.config import get_settings

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
# Jinja2Templates enables autoescape for .html by default; assert it so a
# future refactor cannot quietly turn off the app's main XSS defence.
assert templates.env.autoescape, "Template autoescaping must stay enabled"


def pretty_json(value: Any) -> str:
    """Render claims for display. Never marked safe — the template escapes it."""
    try:
        return json.dumps(value, indent=2, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def _globals() -> dict[str, Any]:
    settings = get_settings()
    return {
        "app_name": "AuthLab",
        "base_url": settings.base_url,
    }


templates.env.filters["pretty_json"] = pretty_json
templates.env.globals.update(_globals())
