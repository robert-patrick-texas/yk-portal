"""Rewriting the audit log, which only restoring a backup does (addendum §17.1).

Audit events can't be changed or deleted: the model refuses, and database
triggers refuse SQL that goes around it (migration 0004). A restore replaces
every table, the audit log included, so inside rewritable() both allow it, for
that one transaction, without any privilege beyond writing the table: on
PostgreSQL a transaction-local setting tells the trigger to allow changes; on
SQLite the triggers are dropped and created again, and if the restore fails,
the rollback brings them back. Backing up only reads the table: nothing stands
in its way.
"""

from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar

from django.db import DEFAULT_DB_ALIAS, connections, transaction

_rewriting: ContextVar[bool] = ContextVar("audit_rewriting", default=False)


def rewriting() -> bool:
    """Whether the model may change and delete audit events: inside rewritable()."""
    return _rewriting.get()


@contextmanager
def rewritable(using: str = DEFAULT_DB_ALIAS) -> Generator[None]:
    """Allow changing and deleting audit events in one transaction, for a restore."""
    connection = connections[using]
    with transaction.atomic(using=using), connection.cursor() as cursor:
        token = _rewriting.set(True)
        try:
            if connection.vendor == "postgresql":
                cursor.execute("SELECT set_config('yk_portal.audit_rewrite', 'on', true)")
                yield
                # Off again, in case the transaction goes on after this block.
                cursor.execute("SELECT set_config('yk_portal.audit_rewrite', 'off', true)")
            else:
                cursor.execute(
                    "SELECT name, sql FROM sqlite_master "
                    "WHERE type = 'trigger' AND tbl_name = 'audit_events' ORDER BY name"
                )
                triggers = cursor.fetchall()
                for name, _ in triggers:
                    cursor.execute(f'DROP TRIGGER "{name}"')
                yield
                for _, sql in triggers:
                    cursor.execute(sql)
        finally:
            _rewriting.reset(token)
