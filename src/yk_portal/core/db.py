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
  on SQLite, where there is no row to lock;
- snapshot gives a backup one consistent view of every table, without making
  writers wait; exclude_writers makes them wait for a restore; short_message
  gives an error's message without the row PostgreSQL quotes.

Writers take turns on SQLite (IMMEDIATE transactions) but not on PostgreSQL,
where a check made in one transaction can be overtaken by another: rows are
locked where that matters (addendum §18.4).
"""

import hashlib
import json
import random
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from typing import Any

from django.db import DatabaseError, IntegrityError, OperationalError, connection, transaction
from django.db.backends.base.base import BaseDatabaseWrapper
from django.db.models import CharField, Func, Model, TextField
from django.db.models.lookups import IContains
from django.db.transaction import TransactionManagementError


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


@contextmanager
def snapshot() -> Generator[None]:
    """Read the database as it was when the block began, all tables at the same moment,
    while other transactions go on writing (spec §28.2-§28.3).

    On PostgreSQL, a read-only REPEATABLE READ transaction, as pg_dump uses. On SQLite,
    a deferred transaction, made read-only: in WAL mode it reads the database as of its
    first read and takes no write lock, where Django's IMMEDIATE transactions would
    make every login wait for the backup.
    """
    if connection.in_atomic_block:
        raise TransactionManagementError("a snapshot can't start inside a transaction")
    if connection.vendor == "postgresql":
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            yield
        return
    with connection.cursor() as cursor:
        cursor.execute("PRAGMA query_only = ON")
        cursor.execute("BEGIN DEFERRED")
        try:
            yield
        finally:
            cursor.execute("ROLLBACK")
            cursor.execute("PRAGMA query_only = OFF")


class Busy(DatabaseError):
    """Other transactions kept the tables exclude_writers() needs for too long."""


def exclude_writers(*models: type[Model], patience: float = 30.0) -> None:
    """Make other transactions wait to change these models' tables until this one ends;
    they can still read them, as they were. Call it in a transaction, before reading.

    On PostgreSQL, LOCK TABLE ... IN EXCLUSIVE MODE, which the tables' owner may take.
    The locks are taken all at once or not at all (NOWAIT, in a savepoint), and tried
    again until PATIENCE seconds have passed: waiting for one table while holding
    another could deadlock with a request that locks them in the other order. On
    SQLite nothing, since an IMMEDIATE transaction already excludes other writers.

    Raises:
        Busy: The tables were never all free at once.
    """
    if connection.vendor != "postgresql":
        return
    tables = ", ".join(connection.ops.quote_name(m._meta.db_table) for m in models)
    deadline = time.monotonic() + patience
    while True:
        try:
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute(f"LOCK TABLE {tables} IN EXCLUSIVE MODE NOWAIT")
            return
        except OperationalError as e:
            if getattr(e.__cause__, "sqlstate", None) != "55P03":  # lock_not_available
                raise
        if time.monotonic() > deadline:
            raise Busy(f"other transactions kept the tables busy for {patience:g} seconds")
        time.sleep(random.uniform(0.01, 0.1))  # noqa: S311 - not for security


def short_message(error: DatabaseError) -> str:
    """The database's message for ERROR without PostgreSQL's DETAIL, which can quote
    the row it refused, secrets and all."""
    diag = getattr(error.__cause__, "diag", None)
    message = getattr(diag, "message_primary", None) or str(error)
    return " ".join(message.splitlines()[0].split()) if message else type(error).__name__


class UnicodeJSONEncoder(json.JSONEncoder):
    """Writes "Clé", not "Cl\\u00e9"."""

    def __init__(self, **kwargs: Any) -> None:
        kwargs["ensure_ascii"] = False
        super().__init__(**kwargs)
