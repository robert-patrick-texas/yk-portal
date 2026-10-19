"""Shared by the backup commands."""

from django.core.management.base import OutputWrapper

from .service import Summary, made_at

_BACKENDS = {"sqlite": "SQLite", "postgresql": "PostgreSQL"}


def show_backup(out: OutputWrapper, summary: Summary) -> None:
    """Which backup it is, and what it holds."""
    header = summary.header
    database = _BACKENDS.get(header.database, header.database)
    out.write(f"Backup {header.id}")
    out.write(f"Made {made_at(header)} by yk-portal {header.application_version}, from {database}")
    out.write(f"Holds {summary.contents()}")
