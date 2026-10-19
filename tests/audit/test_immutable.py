"""Audit events can't be changed or deleted (spec §9; addendum §17.1)."""

import logging
import socket

import pytest
from django.core.management import call_command
from django.db import IntegrityError, connection, transaction

from yk_portal.audit.immutability import rewritable
from yk_portal.audit.journal import journal_handler
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.audit.service import record

pytestmark = pytest.mark.django_db


@pytest.fixture
def event(actor) -> AuditEvent:
    return record(EventType.SETTING_CHANGED, actor, details={"setting": "portal_name"})


def test_the_model_refuses_changes(event):
    event.details = {"setting": "something else"}
    with pytest.raises(IntegrityError, match="immutable"):
        event.save()
    with pytest.raises(IntegrityError, match="immutable"):
        event.delete()
    with pytest.raises(IntegrityError, match="immutable"):
        AuditEvent.objects.filter(pk=event.pk).update(result="FAILURE")
    with pytest.raises(IntegrityError, match="immutable"):
        AuditEvent.objects.all().delete()
    assert AuditEvent.objects.get().details == {"setting": "portal_name"}


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE audit_events SET actor_username_snapshot = 'someone else'",
        "UPDATE audit_events SET details = '{}' WHERE id = %s",
        "DELETE FROM audit_events",
        "DELETE FROM audit_events WHERE id = %s",
    ],
)
def test_the_database_refuses_changes(event, sql):
    """Triggers refuse SQL that bypasses the model. A later migration that rebuilds the
    table must create them again (migration 0004)."""
    params = [event.pk.hex if connection.vendor == "sqlite" else event.pk] if "%s" in sql else []
    with pytest.raises(IntegrityError, match="immutable"):
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(sql, params)
    stored = AuditEvent.objects.get()
    assert stored.actor_username_snapshot == event.actor_username_snapshot
    assert stored.details == {"setting": "portal_name"}


def test_new_events_are_still_added(event, actor):
    record(EventType.SETTING_CHANGED, actor)
    assert AuditEvent.objects.count() == 2


def test_the_journal_handler(tmp_path):
    """Records reach the syslog socket as yk-portal-audit, facility authpriv (spec §40)."""
    path = str(tmp_path / "log")
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as server:
        server.bind(path)
        handler = journal_handler(path)
        try:
            handler.emit(logging.makeLogRecord({"msg": "LOGOUT id=1", "levelname": "INFO"}))
        finally:
            handler.close()
        # authpriv (10) * 8 + info (6) = 86
        assert server.recv(1024) == b"<86>yk-portal-audit: LOGOUT id=1\x00"


# Restoring a backup (addendum §17.1)


def rows() -> list[dict]:
    return list(AuditEvent.objects.order_by("pk").values())


def refused() -> bool:
    """Whether the database refuses to delete audit events, as outside a restore."""
    try:
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute("DELETE FROM audit_events")
    except IntegrityError:
        return True
    return False


def triggers() -> list[tuple[str, ...]]:
    with connection.cursor() as cursor:
        if connection.vendor == "sqlite":
            cursor.execute(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type = 'trigger' AND tbl_name = 'audit_events' ORDER BY name"
            )
        else:
            cursor.execute(
                "SELECT tgname, tgenabled FROM pg_trigger "
                "WHERE tgrelid = 'audit_events'::regclass AND NOT tgisinternal"
            )
        return [tuple(row) for row in cursor.fetchall()]


def test_a_restore_rewrites_the_audit_log(event, actor):
    record(EventType.LOGOUT, actor)
    backup = rows()
    before = triggers()
    with rewritable():
        AuditEvent.objects.all().delete()
        assert not AuditEvent.objects.exists()
        AuditEvent.objects.bulk_create(AuditEvent(**row) for row in backup)
        with connection.cursor() as cursor:  # SQL too
            cursor.execute("UPDATE audit_events SET details = details")
        restored = AuditEvent.objects.get(pk=event.pk)
        restored.save()
    assert rows() == backup
    assert triggers() == before and refused()
    with pytest.raises(IntegrityError, match="immutable"):
        AuditEvent.objects.all().delete()


def test_a_failed_restore_changes_nothing(event):
    before = triggers()
    with pytest.raises(RuntimeError), rewritable():
        AuditEvent.objects.all().delete()
        raise RuntimeError("the backup is corrupt")
    assert AuditEvent.objects.get() == event
    assert triggers() == before and refused()


def test_a_restore_ends_with_its_block(event):
    with transaction.atomic():
        with rewritable():
            pass
        assert refused()  # later in the same transaction


def test_dumpdata_and_loaddata_restore_it(event, actor, tmp_path):
    """Django's own commands back up and restore the audit log without obstacle. XML,
    because Django's JSON keeps only milliseconds of a time."""
    record(EventType.LOGOUT, actor)
    backup = rows()
    dump = tmp_path / "audit.xml"
    call_command("dumpdata", "audit", format="xml", output=str(dump), verbosity=0)
    with rewritable():
        AuditEvent.objects.all().delete()
        call_command("loaddata", str(dump), verbosity=0)
    assert rows() == backup and refused()
