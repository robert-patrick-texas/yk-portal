"""Where SQLite and PostgreSQL differ, made alike (spec §30; addendum §18.3).

The application's queries are written once, for both backends. These are the
few places that need backend-specific SQL, isolated here:

- CodePoint orders text by Unicode code point, as SQLite does, also on a
  PostgreSQL database whose collation is a language's (en_US.UTF-8 would sort
  "ab" before "a.b");
- icontains ignores the case of every letter on SQLite, as on PostgreSQL:
  SQLite's LIKE and UPPER() fold only ASCII, so "émile" wouldn't find "Émile";
- UnicodeJSONEncoder keeps non-ASCII characters in stored JSON, so its text
  can be searched on SQLite as on PostgreSQL, which stores JSON parsed;
- recheck_on_conflict gives a unique value taken at the same moment by
  another transaction the same ValidationError on PostgreSQL as on SQLite;
- take_turns makes transactions take turns on PostgreSQL, as all writers do
  on SQLite, where there is no row to lock.

Writers take turns on SQLite (IMMEDIATE transactions) but not on PostgreSQL,
where a check made in one transaction can be overtaken by another: rows are
locked where that matters (addendum §18.4).
"""

import hashlib
import json
from collections.abc import Callable, Generator
from contextlib import contextmanager
from typing import Any

from django.db import IntegrityError, connection, transaction
from django.db.backends.base.base import BaseDatabaseWrapper
from django.db.models import CharField, Func, TextField
from django.db.models.lookups import IContains


class CodePoint(Func):
    """A text expression compared code point by code point, for order_by()."""

    arity = 1
    template = '%(expressions)s COLLATE "C"'  # PostgreSQL's byte order: code points in UTF-8
    output_field = TextField()

    def as_sqlite(self, compiler: Any, connection: Any, **extra_context: Any) -> Any:
        # SQLite's default collation, BINARY, already compares code points.
        return self.as_sql(compiler, connection, template="%(expressions)s", **extra_context)


class UnicodeIContains(IContains):
    """icontains, with SQLite folding every letter's case as PostgreSQL's UPPER() does."""

    def as_sqlite(self, compiler: Any, connection: Any) -> Any:
        if not self.rhs_is_direct_value():
            return super().as_sql(compiler, connection)
        lhs, lhs_params = self.process_lhs(compiler, connection)
        rhs, rhs_params = self.process_rhs(compiler, connection)
        return f"yk_upper({lhs}) LIKE yk_upper({rhs}) ESCAPE '\\'", (*lhs_params, *rhs_params)


def _upper(text: str | None) -> str | None:
    return None if text is None else text.upper()


def add_sqlite_functions(sender: object, connection: BaseDatabaseWrapper, **kwargs: object) -> None:
    """On each new SQLite connection, add yk_upper(), for UnicodeIContains.

    Only queries use it, never the schema, so the sqlite3 shell can still read and
    change the database.
    """
    if connection.vendor == "sqlite":
        connection.connection.create_function("yk_upper", 1, _upper, deterministic=True)


def register() -> None:
    """Use UnicodeIContains for every text field's icontains. Called once, at startup."""
    CharField.register_lookup(UnicodeIContains)
    TextField.register_lookup(UnicodeIContains)


@contextmanager
def recheck_on_conflict(check: Callable[[], None]) -> Generator[None]:
    """Run the block, an insert or update, in a savepoint; if a unique constraint refuses
    it, run CHECK again, so it raises its ValidationError, before the IntegrityError.

    CHECK is the test made before the block, such as "that username is taken". On
    PostgreSQL another transaction can pass the same test and commit first: the
    constraint then refuses this one, and CHECK, run again, sees the other's row. On
    SQLite the other transaction would have committed before CHECK first ran.
    """
    try:
        with transaction.atomic():
            yield
    except IntegrityError:
        check()
        raise


def take_turns(name: str) -> None:
    """Make transactions that call this with the same NAME wait for each other's end.

    On PostgreSQL, a transaction-level advisory lock, which needs no privilege; on
    SQLite nothing, since its IMMEDIATE transactions already take turns. Call it in a
    transaction.
    """
    if connection.vendor == "postgresql":
        key = int.from_bytes(hashlib.sha256(f"yk-portal:{name}".encode()).digest()[:8], signed=True)
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(%s)", [key])


class UnicodeJSONEncoder(json.JSONEncoder):
    """Writes "Clé", not "Cl\\u00e9"."""

    def __init__(self, **kwargs: Any) -> None:
        kwargs["ensure_ascii"] = False
        super().__init__(**kwargs)
