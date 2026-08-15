"""Database engine and session management.

SQLAlchemy against SQLite or Postgres with no code differences, which is what
lets the same image run under `docker compose up` with zero dependencies and
on any of the three clouds against their managed Postgres.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


def _build_engine() -> Engine:
    settings = get_settings()
    kwargs: dict = {"pool_pre_ping": True, "future": True}

    if settings.is_sqlite:
        # SQLite + threaded ASGI workers: the connection is shared across
        # threads, so the default same-thread check has to come off.
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        # Managed Postgres offerings close idle connections aggressively;
        # recycling below their timeout avoids surfacing stale-connection
        # errors on the first request after an idle period.
        kwargs["pool_size"] = 5
        kwargs["max_overflow"] = 5
        kwargs["pool_recycle"] = 300

    return create_engine(settings.database_url, **kwargs)


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_connection, connection_record) -> None:
    """WAL + enforced foreign keys on SQLite.

    Foreign keys are OFF by default in SQLite, which would silently let the
    SCIM group-membership rows outlive the users they point at.
    """
    if get_settings().is_sqlite:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency — one session per request, always closed."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session for startup tasks and background work."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
