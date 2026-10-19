"""Backing up and restoring the database (spec §28-§29; addendum §19).

A backup is the logical export of every table (data.py) in an encrypted file
(encrypted.py) whose key is derived from the master key. It is read in one
consistent snapshot, without making logins wait, so it can be made while the
application runs, on either backend, and restored into either.

A restore checks the whole backup first (backup-verify), then replaces every
table in one transaction, in which any failure changes nothing. It never
moves a YubiKey's OTP counters backwards, keeps the audit events recorded
since the backup, and ends every session.
"""

import importlib.metadata
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC
from typing import Any, BinaryIO

from django.db import DataError, IntegrityError, connection
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.loader import MigrationLoader
from django.db.models import Field, JSONField, Model
from django.utils import timezone

from yk_portal.accounts.models import Group, User
from yk_portal.audit.immutability import rewritable
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.audit.service import Actor, record
from yk_portal.authentication.models import Session
from yk_portal.core.db import Busy, exclude_writers, short_message, snapshot
from yk_portal.core.encryption import derived_keys
from yk_portal.portal_settings.models import Setting
from yk_portal.yubikeys.models import YubikeyCredential

from . import data
from .encrypted import BackupError, EncryptingWriter, Header, decrypt_segments, read_header

_BATCH_ROWS = 500

# How summaries name the tables people know; the others are left out.
_NAMES = {
    "users": ("account", "accounts"),
    "yubikey_credentials": ("YubiKey", "YubiKeys"),
    "groups": ("group", "groups"),
    "settings": ("setting", "settings"),
    "audit_events": ("audit event", "audit events"),
}


@dataclass(frozen=True)
class Summary:
    """A backup: its header, and how many rows each table has."""

    header: Header
    counts: dict[str, int]

    def contents(self) -> str:
        return describe(self.counts)


def describe(counts: dict[str, int]) -> str:
    """Such as "2 accounts, 1 YubiKey, 0 groups, 0 settings and 9 audit events", for the
    tables in COUNTS."""
    parts = [count(counts[name], *forms) for name, forms in _NAMES.items() if name in counts]
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def count(number: int, singular: str, plural: str) -> str:
    return f"{number:,} {singular if number == 1 else plural}"


def application_version() -> str:
    return importlib.metadata.version("yk-portal")


def schema() -> dict[str, str]:
    """Each app's last migration in this version of yk-portal."""
    return dict(sorted(MigrationLoader(None, ignore_no_migrations=True).graph.leaf_nodes()))


def _check_migrated() -> None:
    """Refuse a database whose migrations aren't exactly this version's."""
    executor = MigrationExecutor(connection)
    graph = executor.loader.graph
    if set(executor.loader.applied_migrations) - set(graph.nodes):
        raise BackupError("the database is newer than this version of yk-portal")
    if executor.migration_plan(graph.leaf_nodes()):
        raise BackupError("the database isn't fully migrated; run yk-portal migrate first")


def create(out: BinaryIO) -> tuple[Summary, int]:
    """Write an encrypted backup of the database to OUT, as of one moment.

    Returns:
        What the backup holds, and its size in bytes.

    Raises:
        BackupError: The database isn't migrated.
        MasterKeyError: The master key can't be read.
    """
    _check_migrated()
    keys = derived_keys()
    with snapshot():
        header = Header.new(
            application_version(), connection.vendor, schema(), keys.key_id, timezone.now()
        )
        writer = EncryptingWriter(out, header, keys.backup)
        counts = data.dump(writer.write)
    writer.close()
    return Summary(header, counts), writer.size


def record_created(actor: Actor, summary: Summary, destination: str, size: int) -> None:
    """The BACKUP_CREATED audit event."""
    record(
        EventType.BACKUP_CREATED,
        actor,
        details={
            "backup_id": str(summary.header.id),
            "destination": destination,
            "bytes": size,
            **_counts_detail(summary.counts),
        },
    )


def _counts_detail(counts: dict[str, int]) -> dict[str, int]:
    return {
        "accounts": counts["users"],
        "yubikeys": counts["yubikey_credentials"],
        "audit_events": counts["audit_events"],
    }


def verify(file: BinaryIO) -> Summary:
    """Check a backup completely, as a restore would before changing anything: its
    format, every segment's authentication, every row, and that this installation can
    restore it (the same master key and schema).

    Raises:
        BackupError: It can't be restored here, and why.
        MasterKeyError: The master key can't be read.
    """
    header = read_header(file)
    _check_restorable(file, header)
    counts = dict.fromkeys(map(data.table, data.TABLES), 0)
    for model, _ in data.parse(decrypt_segments(file, header, derived_keys().backup)):
        counts[data.table(model)] += 1
    return Summary(header, counts)


def _check_restorable(file: BinaryIO, header: Header) -> None:
    keys = derived_keys()
    if header.key_id != keys.key_id:
        raise BackupError(
            f"made with another master key (ID {header.key_id.hex()}; this one's is "
            f"{keys.key_id.hex()}): restore it with the master key it was made with"
        )
    if header.schema != schema():
        # Authentic or not? Say which, before saying why it can't be restored.
        for _ in decrypt_segments(file, header, keys.backup):
            pass
        made_by = f"yk-portal {header.application_version}"
        raise BackupError(
            f"the backup is authentic, but {made_by} made it with another schema "
            f"({_schema_difference(header.schema, schema())}): restore it with {made_by}, "
            "then upgrade"
        )


def _schema_difference(theirs: dict[str, str], ours: dict[str, str]) -> str:
    return ", ".join(
        f"{app} {theirs.get(app, 'none')} here {ours.get(app, 'none')}"
        for app in sorted(theirs.keys() | ours.keys())
        if theirs.get(app) != ours.get(app)
    )


def database_contents() -> dict[str, int]:
    """What the database holds that a restore replaces. Its audit events are kept."""
    return {
        "users": User.objects.count(),
        "yubikey_credentials": YubikeyCredential.objects.count(),
        "groups": Group.objects.count(),
        "settings": Setting.objects.count(),
    }


def holds_data(contents: dict[str, int]) -> bool:
    """Whether the database holds anything a restore would replace."""
    return any(contents.values())


@dataclass(frozen=True)
class Restored:
    summary: Summary
    # Whether the database held accounts, YubiKeys, groups or settings, now replaced.
    replaced: bool
    # YubiKeys whose OTP counters in the database were ahead of the backup's, and kept.
    counters_kept: int
    # Audit events in the database but not in the backup, recorded since it was made.
    audit_events_kept: int
    # Audit events in both that differed, put back as the backup has them.
    audit_events_restored: int


def restore(file: BinaryIO, actor: Actor, *, replace: bool, backup_id: uuid.UUID) -> Restored:
    """Replace the database's contents with a backup's, in one transaction, and record
    BACKUP_RESTORED. BACKUP_ID is the ID verify() saw: the file must still be that backup.

    Other transactions can read while it runs, and wait to write until it ends.

    Raises:
        BackupError: The backup fails a check, the database isn't migrated, or it isn't
            empty and REPLACE is false. Nothing was changed.
        MasterKeyError: The master key can't be read.
        DatabaseError: The database refused the restore. Nothing was changed.
    """
    header = read_header(file)
    if header.id != backup_id:
        raise BackupError("the file is no longer the backup that was checked")
    _check_restorable(file, header)
    rows = data.parse(decrypt_segments(file, header, derived_keys().backup))
    with rewritable():
        try:
            exclude_writers(*data.TABLES, Session)
        except Busy as e:
            raise BackupError(f"{e}; stop yk-portal, then try again") from None
        _check_migrated()
        contents = database_contents()
        if holds_data(contents) and not replace:
            raise BackupError(
                f"the database isn't empty: it holds {describe(contents)}; "
                "to replace them, use --replace"
            )
        loader = _Loader(audit_events_before=AuditEvent.objects.count())
        loader.load(rows)
        restored = Restored(
            summary=Summary(header, loader.counts),
            replaced=holds_data(contents),
            counters_kept=loader.counters_kept,
            audit_events_kept=loader.audit_events_kept,
            audit_events_restored=loader.audit_events_restored,
        )
        record(
            EventType.BACKUP_RESTORED,
            actor,
            details={
                "backup_id": str(header.id),
                "made_at": header.created_at.isoformat(),
                "made_by": f"yk-portal {header.application_version}",
                "replaced": restored.replaced,
                **_counts_detail(loader.counts),
                "counters_kept": restored.counters_kept,
                "audit_events_kept": restored.audit_events_kept,
                "audit_events_restored": restored.audit_events_restored,
            },
        )
    return restored


class _Loader:
    """Empties the tables a restore replaces, then writes the backup's rows."""

    def __init__(self, audit_events_before: int) -> None:
        self.counts = dict.fromkeys(map(data.table, data.TABLES), 0)
        self.counters_kept = 0
        self.audit_events_restored = 0
        self._audit_events_before = audit_events_before
        self._audit_events_matched = 0
        self._counters = _counters()

    @property
    def audit_events_kept(self) -> int:
        return self._audit_events_before - self._audit_events_matched

    def load(self, rows: Iterator[tuple[type[Model], data.Row]]) -> None:
        # The audit log is kept: only the backup's events it lacks are added.
        for model in (Session, *reversed(data.TABLES)):
            if model is not AuditEvent:
                _delete_all(model)
        batch: list[data.Row] = []
        current: type[Model] | None = None
        for model, row in rows:
            if model is not current or len(batch) == _BATCH_ROWS:
                self._store(current, batch)
                current, batch = model, []
            batch.append(row)
            self.counts[data.table(model)] += 1
        self._store(current, batch)

    def _store(self, model: type[Model] | None, rows: list[data.Row]) -> None:
        if model is None or not rows:
            return
        if model is YubikeyCredential:
            self._keep_counters(rows)
        if model is AuditEvent:
            rows = self._missing_audit_events(rows)
        try:
            _insert(model, rows)
        except (IntegrityError, DataError) as e:
            # Such as a value longer than its column, which SQLite stored and PostgreSQL
            # refuses. The message names no value: they can be secrets.
            raise BackupError(
                f"{data.table(model)}: the database refused a row: {short_message(e)}"
            ) from None

    def _keep_counters(self, rows: list[data.Row]) -> None:
        """A restore never moves an OTP counter back (spec §17): for a YubiKey the
        database has with the same private ID, keep its counters if they are ahead."""
        column = _columns(YubikeyCredential)
        usage, session, used = (
            column["last_usage_counter"],
            column["last_session_counter"],
            column["last_used_at"],
        )
        for row in rows:
            current = self._counters.get(row[column["public_id"]])
            if current is None or current[0] != row[column["private_id_digest"]]:
                continue
            if current[1:3] > (row[usage], row[session]):
                row[usage], row[session] = current[1:3]
                if current[3] is not None and (row[used] is None or current[3] > row[used]):
                    row[used] = current[3]
                self.counters_kept += 1

    def _missing_audit_events(self, rows: list[data.Row]) -> list[data.Row]:
        """The backup's events to write: those the database lacks, and those it holds
        otherwise than the backup, which are deleted first."""
        pk = _columns(AuditEvent)["id"]
        stored = AuditEvent.objects.filter(pk__in=[row[pk] for row in rows]).values_list(
            *(f.attname for f in data.fields(AuditEvent))
        )
        # Compared as a restore reads them: PostgreSQL's inet, for one, writes some IPv6
        # addresses otherwise than Django.
        existing = {values[pk]: data.canonical(AuditEvent, values) for values in stored}
        self._audit_events_matched += len(existing)
        changed = [row for row in rows if row[pk] in existing and existing[row[pk]] != row]
        if changed:
            AuditEvent.objects.filter(pk__in=[row[pk] for row in changed]).delete()
            self.audit_events_restored += len(changed)
        return [row for row in rows if row[pk] not in existing] + changed


def _counters() -> dict[str, tuple[Any, ...]]:
    """Each YubiKey's private ID digest, counters and last use, by public ID."""
    return {
        values[0]: tuple(values[1:])
        for values in YubikeyCredential.objects.values_list(
            "public_id",
            "private_id_digest",
            "last_usage_counter",
            "last_session_counter",
            "last_used_at",
        )
    }


def _columns(model: type[Model]) -> dict[str, int]:
    """Where each field's value is in a row."""
    return {f.attname: n for n, f in enumerate(data.fields(model))}


def _delete_all(model: type[Model]) -> None:
    with connection.cursor() as cursor:
        cursor.execute(f"DELETE FROM {connection.ops.quote_name(data.table(model))}")  # noqa: S608 - a model's table


def _insert(model: type[Model], rows: list[data.Row]) -> None:
    """Insert ROWS as they are: unlike the ORM, without setting auto_now times."""
    if not rows:
        return
    fields = data.fields(model)
    quote = connection.ops.quote_name
    columns = ", ".join(quote(f.column) for f in fields)
    placeholders = ", ".join(["%s"] * len(fields))
    sql = f"INSERT INTO {quote(data.table(model))} ({columns}) VALUES ({placeholders})"  # noqa: S608 - a model's table and columns
    params = [[_prepare(f, value) for f, value in zip(fields, row, strict=True)] for row in rows]
    with connection.cursor() as cursor:
        cursor.executemany(sql, params)


def _prepare(field: Field, value: Any) -> Any:
    if value is None and isinstance(field, JSONField) and not field.null:
        # JSON's null; Django would write SQL's NULL, which the column refuses.
        return connection.ops.adapt_json_value(None, field.encoder)
    return field.get_db_prep_save(value, connection)


def made_at(header: Header) -> str:
    """When a backup was made, for people: 2026-10-18 02:30:00 UTC."""
    return f"{header.created_at.astimezone(UTC):%Y-%m-%d %H:%M:%S} UTC"
