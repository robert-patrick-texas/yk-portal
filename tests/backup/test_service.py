"""Backing up and restoring (spec §28-§29, §44.7; addendum §19).

The tests are transactional: a backup reads in a snapshot, which can't start
inside the transaction that wraps other tests.
"""

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from django.db import connection

from yk_portal.accounts import groups, services
from yk_portal.accounts.models import Role
from yk_portal.audit.immutability import rewritable
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.audit.service import Actor, record
from yk_portal.authentication.models import Session
from yk_portal.authentication.sessions import Client, start_session
from yk_portal.backup import data, service
from yk_portal.backup.encrypted import BackupError
from yk_portal.core.database_status import database_status
from yk_portal.core.master_key import create_master_key
from yk_portal.portal_settings import service as portal_settings
from yk_portal.yubikeys.models import YubikeyCredential

pytestmark = [pytest.mark.django_db(transaction=True), pytest.mark.usefixtures("master_key")]

USED = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def roles() -> None:
    """The roles of migration 0002, which an earlier transactional test's flush removed."""
    for name in (Role.USER, Role.ADMIN):
        Role.objects.get_or_create(name=name)


@pytest.fixture
def populated(make_user, make_credential, actor) -> None:
    """Accounts, YubiKeys, a group and settings, made as the application makes them."""
    alice = services.create_user("alice", actor, email="alice@example.com").user
    bob = make_user("bob", admin=True, display_name="Bob", comment="on call\n\tweekends")
    make_credential(alice, pin="alice-pin-1234", label="Desk", last_usage_counter=5)
    make_credential(bob, last_used_at=USED, last_usage_counter=9, last_session_counter=3)
    ops = groups.create_group("Ops", actor, description="Network operations")
    groups.add_member(ops, alice, actor)
    portal_settings.update({"portal_name": "Ops portal", "default_group": ops.pk}, actor)


def everything() -> dict[str, list[tuple[object, ...]]]:
    """Every row a restore replaces, as Django reads them."""
    return {
        data.table(model): list(
            model._base_manager.order_by("pk").values_list(*(f.attname for f in data.fields(model)))
        )
        for model in data.TABLES
        if model is not AuditEvent
    }


def audit_log() -> dict[uuid.UUID, tuple[object, ...]]:
    """Every audit event's values, by ID."""
    columns = (f.attname for f in data.fields(AuditEvent))
    return {row[0]: row for row in AuditEvent.objects.values_list(*columns)}


def added(before: dict[uuid.UUID, tuple[object, ...]]) -> list[str]:
    """The types of the events added since BEFORE, which must all be unchanged."""
    after = audit_log()
    assert all(after.get(pk) == row for pk, row in before.items())
    return sorted(str(row[2]) for pk, row in after.items() if pk not in before)


def backup(tmp_path: Path, name: str = "test.backup") -> Path:
    path = tmp_path / name
    with path.open("wb") as out:
        service.create(out)
    return path


def verify(path: Path) -> service.Summary:
    with path.open("rb") as file:
        return service.verify(file)


def restore(path: Path, replace: bool = True) -> service.Restored:
    backup_id = verify(path).header.id
    with path.open("rb") as file:
        return service.restore(file, Actor.cli(), replace=replace, backup_id=backup_id)


def wipe() -> None:
    """Empty every table, then add the roles, as a newly migrated database has them."""
    with rewritable():
        AuditEvent.objects.all().delete()
        for model in (Session, *reversed(data.TABLES)):
            model._base_manager.all().delete()
    for name in (Role.USER, Role.ADMIN):
        Role.objects.create(name=name)


def audit_triggers_in_place() -> bool:
    status = database_status(connection)
    return ("Audit log", "protected by triggers") in status.lines


def test_a_backup_and_its_summary(populated, tmp_path):
    path = backup(tmp_path)
    summary = verify(path)
    assert summary.counts == {
        "roles": 2,
        "users": 2,
        "user_roles": 3,
        "groups": 1,
        "user_groups": 1,
        "yubikey_credentials": 2,
        "settings": 2,
        "audit_events": AuditEvent.objects.count(),
    }
    assert summary.header.schema == service.schema()
    assert summary.header.application_version == service.application_version()
    contents = "2 accounts, 2 YubiKeys, 1 group, 2 settings and"
    assert summary.contents().startswith(contents)


def test_restoring_into_an_empty_database_recreates_everything(populated, tmp_path):
    before, log = everything(), audit_log()
    path = backup(tmp_path)
    wipe()
    restored = restore(path, replace=False)
    assert everything() == before  # IDs, times to the microsecond, hashes, secrets
    assert added(log) == [EventType.BACKUP_RESTORED]
    assert not restored.replaced
    assert (restored.counters_kept, restored.audit_events_kept) == (0, 0)
    alice_key = YubikeyCredential.objects.get(user__username="alice")
    assert len(alice_key.private_id()) == 6 and len(alice_key.aes_key()) == 16
    assert audit_triggers_in_place()


def test_restoring_replaces_what_changed_since(populated, tmp_path, make_user, actor):
    before = everything()
    path = backup(tmp_path)
    services.delete_user(services.User.objects.get(username="alice"), actor)
    make_user("carol")
    groups.create_group("New", actor)
    portal_settings.update({"portal_name": "Changed"}, actor)
    restored = restore(path)
    assert everything() == before
    assert restored.replaced


def test_a_database_that_isnt_empty_is_replaced_only_when_asked(populated, tmp_path):
    path = backup(tmp_path)
    before, log = everything(), audit_log()
    held = "it holds 2 accounts, 2 YubiKeys, 1 group and 2 settings; to replace them"
    with pytest.raises(BackupError, match=f"the database isn't empty: {held}"):
        restore(path, replace=False)
    assert everything() == before and audit_log() == log


def test_the_restore_is_recorded(populated, tmp_path):
    path = backup(tmp_path)
    summary = verify(path)
    restore(path)
    event = AuditEvent.objects.get(event_type=EventType.BACKUP_RESTORED)
    assert event.actor_username_snapshot.startswith("cli:")
    assert event.details == {
        "backup_id": str(summary.header.id),
        "made_at": summary.header.created_at.isoformat(),
        "made_by": f"yk-portal {service.application_version()}",
        "replaced": True,
        "accounts": 2,
        "yubikeys": 2,
        "audit_events": summary.counts["audit_events"],
        "counters_kept": 0,
        "audit_events_kept": 0,
        "audit_events_restored": 0,
    }


def test_every_session_ends(populated, tmp_path):
    alice = services.User.objects.get(username="alice")
    start_session(alice, Client("192.0.2.1", "browser"))
    path = backup(tmp_path)
    start_session(alice, Client("192.0.2.1", "browser"))
    restore(path)
    assert not Session.objects.exists()


def test_otp_counters_never_move_back(make_user, make_credential, tmp_path):
    user = make_user("alice")
    used = make_credential(user, private_id="0000000000a1", last_usage_counter=5)
    reprogrammed = make_credential(user, private_id="0000000000a2", last_usage_counter=5)
    behind = make_credential(user, private_id="0000000000a3", last_usage_counter=5)
    path = backup(tmp_path)

    later = USED + timedelta(days=1)
    YubikeyCredential.objects.filter(pk=used.pk).update(
        last_usage_counter=7, last_session_counter=2, last_used_at=later
    )
    # The same public ID, programmed with a new private ID: its counters started again.
    YubikeyCredential.objects.filter(pk=reprogrammed.pk).delete()
    replacement = make_credential(
        user, public_id=reprogrammed.public_id, private_id="0000000000b2", last_usage_counter=9
    )
    YubikeyCredential.objects.filter(pk=behind.pk).update(last_usage_counter=4)

    restored = restore(path)
    assert restored.counters_kept == 1
    counters = {
        k.pk: (k.last_usage_counter, k.last_session_counter, k.last_used_at)
        for k in YubikeyCredential.objects.all()
    }
    assert counters == {
        used.pk: (7, 2, later),  # ahead in the database: kept
        reprogrammed.pk: (5, 0, None),  # another key now: the backup's
        behind.pk: (5, 0, None),  # behind in the database: the backup's
    }
    assert not YubikeyCredential.objects.filter(pk=replacement.pk).exists()


def test_the_audit_log_keeps_events_recorded_since(populated, tmp_path, actor):
    path = backup(tmp_path)
    log = audit_log()
    record(EventType.LOGOUT, actor)
    restored = restore(path)
    assert restored.audit_events_kept == 1 and restored.audit_events_restored == 0
    assert added(log) == [EventType.BACKUP_RESTORED, EventType.LOGOUT]


def test_an_audit_event_changed_since_is_put_back(populated, tmp_path):
    path = backup(tmp_path)
    log = audit_log()
    event = AuditEvent.objects.order_by("timestamp").first()
    assert event is not None
    with rewritable():
        AuditEvent.objects.filter(pk=event.pk).update(details={"forged": True})
    restored = restore(path)
    assert restored.audit_events_restored == 1 and restored.audit_events_kept == 0
    assert added(log) == [EventType.BACKUP_RESTORED]  # the forged event is as it was


def test_a_failed_restore_changes_nothing(make_user, tmp_path, actor):
    # Enough for several segments, so the restore has written rows when one fails.
    for n in range(80):
        make_user(f"user{n}", comment="x" * 1000)
    path = backup(tmp_path)
    data_ = path.read_bytes()
    path.write_bytes(data_[:-1] + bytes([data_[-1] ^ 1]))
    make_user("since")
    record(EventType.LOGOUT, actor)
    before, log = everything(), audit_log()
    header_id = uuid.UUID(data_.split(b"\n")[1].split(b'"id":"')[1][:36].decode())
    with path.open("rb") as file, pytest.raises(BackupError, match="authentication failed"):
        service.restore(file, actor, replace=True, backup_id=header_id)
    assert everything() == before and audit_log() == log
    assert audit_triggers_in_place()


def test_a_restore_that_fails_at_its_end_changes_nothing(
    populated, tmp_path, monkeypatch, make_user, actor
):
    """Every row written, the audit log merged, then a failure: all of it rolls back,
    and SQLite's audit triggers are back."""
    path = backup(tmp_path)
    make_user("since")
    record(EventType.LOGOUT, actor)
    event = AuditEvent.objects.order_by("timestamp").first()
    assert event is not None
    with rewritable():
        AuditEvent.objects.filter(pk=event.pk).update(details={"forged": True})
    before, log = everything(), audit_log()
    written = []
    real_insert = service._insert

    def insert(model, rows):
        written.append(data.table(model))
        real_insert(model, rows)

    def fail(*args, **kwargs):
        raise RuntimeError("the disk is full")

    monkeypatch.setattr(service, "_insert", insert)
    monkeypatch.setattr(service, "record", fail)
    with pytest.raises(RuntimeError):
        restore(path)
    assert {"users", "yubikey_credentials", "audit_events"} <= set(written)
    assert everything() == before and audit_log() == log
    assert audit_triggers_in_place()


def test_audit_events_that_didnt_change_arent_put_back(tmp_path, actor):
    """Not even an IPv6 address PostgreSQL writes otherwise than Django, or JSON's null."""
    record(EventType.LOGOUT, Actor(None, "cli:test", source_ip="::192.0.2.1"))
    record(EventType.LOGOUT, actor)
    with rewritable(), connection.cursor() as cursor:
        cursor.execute("UPDATE audit_events SET details = 'null' WHERE source_ip IS NULL")
    log = audit_log()
    path = backup(tmp_path)
    assert restore(path).audit_events_restored == 0
    wipe()
    restore(path, replace=False)
    assert added(log) == [EventType.BACKUP_RESTORED]  # the null too


def test_the_file_must_still_be_the_backup_checked(populated, tmp_path, actor):
    path = backup(tmp_path)
    with path.open("rb") as file, pytest.raises(BackupError, match="no longer the backup"):
        service.restore(file, actor, replace=True, backup_id=uuid.uuid4())


def test_another_master_key_cant_restore_it(populated, tmp_path, settings):
    path = backup(tmp_path)
    other = tmp_path / "other.key"
    create_master_key(other)
    settings.YK_MASTER_KEY_PATH = str(other)
    with pytest.raises(BackupError, match="made with another master key \\(ID [0-9a-f]{16}; "):
        verify(path)


def test_another_schema_cant_be_restored(populated, tmp_path, monkeypatch):
    newer = service.schema() | {"accounts": "0099_future"}
    monkeypatch.setattr(service, "schema", lambda: newer)
    path = backup(tmp_path)
    monkeypatch.undo()
    with pytest.raises(
        BackupError,
        match="the backup is authentic, but yk-portal .* made it with another schema "
        "\\(accounts 0099_future here 0006_user_display_name_comment\\): restore it with "
        "yk-portal .*, then upgrade",
    ):
        verify(path)
    # Tampered with, it says so instead.
    data_ = path.read_bytes()
    path.write_bytes(data_[:-1] + bytes([data_[-1] ^ 1]))
    with pytest.raises(BackupError, match="authentication failed"):
        verify(path)


def test_a_backup_holds_no_plaintext(populated, tmp_path):
    contents = backup(tmp_path).read_bytes()
    key = YubikeyCredential.objects.get(user__username="alice")
    for secret in (
        b"alice",
        b"alice@example.com",
        b"on call",
        key.pin_hash.encode(),
        key.radius_pin_hash.encode(),
        key.private_id(),
        key.aes_key(),
        key.public_id.encode(),
    ):
        assert secret not in contents
