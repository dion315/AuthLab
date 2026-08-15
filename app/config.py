"""Bootstrap configuration.

Deliberately small. Everything about *identity providers* — issuers, client
IDs, secrets, certificates, role mappings, SCIM tokens — lives in the database
and is edited at runtime through the admin UI, not here. That is the whole
point of the local admin account: you should be able to stand this app up with
no IdP knowledge at all, sign in locally, and configure the rest by hand while
watching what happens.

What stays in the environment is only what the app needs *before* it can read
its own database.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- server ---
    host: str = "0.0.0.0"  # noqa: S104 — containers must bind all interfaces
    port: int = 8000
    base_url: str = "http://localhost:8000"
    log_level: str = "info"

    # Behind a cloud load balancer (Container Apps, App Runner, Cloud Run) the
    # client IP and original scheme only exist in X-Forwarded-* headers. Source
    # IP is a Conditional Access policy condition, so getting this wrong makes
    # the app lie to you about where a sign-in came from.
    trust_proxy_headers: bool = True

    # --- persistence ---
    # SQLite by default so `docker compose up` needs no database service at all.
    # Point at Postgres for any real deployment: postgresql+psycopg://user:pw@host/db
    database_url: str = "sqlite:///./data/authlab.db"

    # --- secrets ---
    # Signs session cookies AND derives the key that encrypts IdP client
    # secrets at rest. Rotating it logs everyone out and makes stored IdP
    # secrets unreadable — they must be re-entered in the admin UI.
    app_secret_key: str = ""

    session_ttl_minutes: int = 60
    session_cookie_name: str = "authlab_session"

    # --- first-run local admin ---
    # If no local account exists at startup, one is created with these values.
    # Leave the password blank and a random one is generated and printed once
    # to the startup log.
    bootstrap_admin_email: str = "admin@authlab.local"
    bootstrap_admin_password: str = ""

    @property
    def cookies_secure(self) -> bool:
        """Set the Secure flag whenever we are actually served over HTTPS.

        Derived from base_url rather than hardcoded, so local http development
        works while any real deployment gets the flag automatically.
        """
        return self.base_url.lower().startswith("https://")

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    settings = Settings()

    if not settings.app_secret_key:
        # Generating one keeps `docker run` with no arguments working, but it
        # is regenerated every start: sessions die on restart and any IdP
        # secret already stored becomes undecryptable. Loud warning, not a
        # silent default.
        settings.app_secret_key = secrets.token_urlsafe(48)
        print(
            "WARNING: APP_SECRET_KEY is not set. A temporary key was generated.\n"
            "         Sessions will not survive a restart and stored IdP secrets\n"
            "         will become unreadable. Set APP_SECRET_KEY for any real use."
        )

    if settings.is_sqlite:
        # sqlite:///./data/authlab.db -> ensure ./data exists before connecting.
        db_path = settings.database_url.split("///", 1)[-1]
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    return settings
