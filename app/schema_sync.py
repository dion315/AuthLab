"""Additive schema reconciliation for an existing database.

`create_all` creates missing *tables* but never touches an existing one, so a
release that adds a column to `idp_connections` leaves every deployment that
already has data with a table the ORM cannot read. For a harness that people
redeploy over a database holding their configured connections, "drop the
database" is a bad answer to a new checkbox.

This closes that gap for the only case a test harness actually hits: columns
added to a table that already exists. It is deliberately **not** a migration
framework:

  * It only ever runs `ALTER TABLE ... ADD COLUMN`. Nothing is dropped,
    renamed, retyped, or reordered.
  * New columns are added nullable — SQLite cannot add a NOT NULL column
    without a server-side default — and existing rows are then filled in with
    the model's Python-side default, so reads come back with the value the code
    expects rather than None.
  * A column whose default it cannot reproduce faithfully is left alone and
    logged loudly, rather than guessed at.

Anything beyond that (dropping a column, changing a type, backfilling from
another table) is a real migration and wants Alembic. The models are ordinary
SQLAlchemy, so that remains a drop-in addition.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.schema import Column

from app.models import Base

logger = logging.getLogger("authlab")

# Defaults we can reproduce in a plain UPDATE. A datetime or a callable that
# depends on request context is not in this list on purpose.
_FILLABLE = (str, int, float, bool, list, dict)


def _default_value(column: Column) -> tuple[bool, Any]:
    """Resolve a column's Python-side default into something UPDATE can bind.

    Returns (usable, value). `usable` is False when the column has no default
    we can reproduce, which is the signal to leave existing rows NULL and warn.
    """
    if column.nullable and column.default is None:
        # Genuinely optional — NULL is the correct value for existing rows.
        return True, None

    default = column.default
    if default is None:
        return False, None

    value: Any
    if getattr(default, "is_callable", False):
        # SQLAlchemy wraps zero-argument callables to accept an execution
        # context, but does not do so for every construction path.
        try:
            value = default.arg(None)
        except TypeError:
            value = default.arg()
    elif getattr(default, "is_scalar", False):
        value = default.arg
    else:
        return False, None

    if not isinstance(value, _FILLABLE):
        return False, None

    if isinstance(value, (list, dict)):
        # JSON columns store serialised text; bind the same representation
        # SQLAlchemy would have written.
        return True, json.dumps(value)
    if isinstance(value, bool):
        return True, int(value)
    return True, value


def sync_schema(engine: Engine) -> list[str]:
    """Add columns present in the models but missing from the database.

    Returns the names of the columns added, as "table.column", for logging.
    Safe to call on every startup: with nothing to do it issues one round of
    reflection and no DDL.
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    added: list[str] = []

    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            # create_all builds this one in full; nothing to reconcile.
            continue

        present = {col["name"] for col in inspector.get_columns(table.name)}
        missing = [col for col in table.columns if col.name not in present]
        if not missing:
            continue

        for column in missing:
            usable, value = _default_value(column)
            if not usable:
                logger.warning(
                    "Schema drift: %s.%s is missing and its default cannot be "
                    "backfilled automatically. Add it by hand or recreate the "
                    "database.",
                    table.name,
                    column.name,
                )
                continue

            # Identifiers are interpolated because no database accepts them as
            # bind parameters. They are not user input: every name here comes
            # from this application's own model metadata, and the *value* — the
            # only part that could carry anything hostile — is bound properly.
            type_sql = column.type.compile(engine.dialect)
            add_column = f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {type_sql}'
            backfill = f'UPDATE "{table.name}" SET "{column.name}" = :value'  # noqa: S608
            with engine.begin() as connection:
                connection.execute(text(add_column))
                if value is not None:
                    connection.execute(text(backfill), {"value": value})
            added.append(f"{table.name}.{column.name}")

    return added
