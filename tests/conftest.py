"""Test fixtures.

Environment is set before any app module is imported, because settings are
cached and the database engine is built at import time.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

_db_handle, _db_path = tempfile.mkstemp(suffix=".db")
os.close(_db_handle)

os.environ["APP_SECRET_KEY"] = "test-key-not-used-anywhere-real-0123456789"
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"
os.environ["BASE_URL"] = "http://testserver"
os.environ["BOOTSTRAP_ADMIN_EMAIL"] = "admin@authlab.local"
os.environ["BOOTSTRAP_ADMIN_PASSWORD"] = "TestAdminPassword123"

from fastapi.testclient import TestClient  # noqa: E402

from app.db import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Base, IdpConnection, ScimClient  # noqa: E402
from app.security import generate_token, hash_token  # noqa: E402

ADMIN_EMAIL = "admin@authlab.local"
ADMIN_PASSWORD = "TestAdminPassword123"


@pytest.fixture(autouse=True)
def _clean_database():
    """Fresh schema per test, so ordering never matters."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def scim_token(db) -> str:
    token = generate_token()
    db.add(ScimClient(name="test-client", token_hash=hash_token(token), token_hint=token[:6]))
    db.commit()
    return token


@pytest.fixture
def scim_headers(scim_token) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {scim_token}",
        "Content-Type": "application/scim+json",
    }


@pytest.fixture
def admin_client(client):
    """A client signed in as the bootstrapped local administrator."""
    response = client.post(
        "/auth/local/login",
        data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    return client


@pytest.fixture
def oidc_connection(db) -> IdpConnection:
    connection = IdpConnection(
        slug="testidp",
        name="Test IdP",
        protocol="oidc",
        enabled=True,
        role_claim="groups",
        default_role="user",
        role_rules=[
            {"operator": "equals", "value": "SEC-Admins", "role": "admin"},
            {"operator": "starts_with", "value": "SEC-Power", "role": "power"},
        ],
        config={},
    )
    db.add(connection)
    db.commit()
    return connection


def pytest_sessionfinish(session, exitstatus):
    # Dispose first: Windows refuses to unlink a file that still has an open
    # handle, and SQLAlchemy's pool holds one until told otherwise. Without
    # this the whole suite passes and then dies in teardown.
    engine.dispose()
    try:
        Path(_db_path).unlink(missing_ok=True)
        # WAL mode leaves these alongside the database.
        for suffix in ("-wal", "-shm"):
            Path(_db_path + suffix).unlink(missing_ok=True)
    except OSError:
        # A leaked handle should not fail an otherwise green run; the file is
        # in a temp directory the OS will reclaim.
        pass
