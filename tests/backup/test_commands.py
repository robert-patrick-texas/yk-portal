"""backup-create, backup-verify and backup-restore (spec §36; addendum §19)."""

import io
import os
import re
import stat
from io import StringIO
from pathlib import Path

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import OperationalError, connection

from yk_portal.accounts.models import Role, User
from yk_portal.audit.immutability import rewritable
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.audit.service import record
from yk_portal.authentication.models import Session
from yk_portal.backup import data, service
from yk_portal.yubikeys.models import YubikeyCredential

pytestmark = [pytest.mark.django_db(transaction=True), pytest.mark.usefixtures("master_key")]


@pytest.fixture(autouse=True)
def roles() -> None:
    """The roles of migration 0002, which an earlier transactional test's flush removed."""
    for name in (Role.USER, Role.ADMIN):
        Role.objects.get_or_create(name=name)


@pytest.fixture
def populated(make_user, make_credential, actor) -> None:
    alice = make_user("alice", email="alice@example.com")
    make_credential(alice)
    record(EventType.ACCOUNT_CREATED, actor, alice)


def run(*args: str) -> tuple[str, str]:
    """Run a command; its standard output and standard error."""
    out, err = StringIO(), StringIO()
    call_command(*args, stdout=out, stderr=err)
    return out.getvalue(), err.getvalue()


def lines(text: str) -> list[str]:
    return text.splitlines()


def create(tmp_path: Path) -> Path:
    path = tmp_path / "test.backup"
    run("backup-create", str(path))
    return path


def wipe() -> None:
    with rewritable():
        AuditEvent.objects.all().delete()
        for model in (Session, *reversed(data.TABLES)):
            model._base_manager.all().delete()


# backup-create


def test_create_a_backup(populated, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    umask = os.umask(0)  # even so, only the owner may read it
    try:
        out, err = run("backup-create", "nightly.backup")
    finally:
        os.umask(umask)
    path = tmp_path / "nightly.backup"
    assert out == ""
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert list(tmp_path.iterdir()) == [path]
    size = path.stat().st_size
    summary = service.verify(path.open("rb"))
    assert lines(err) == [
        f"Backed up 1 account, 1 YubiKey, 0 groups, 0 settings and 1 audit event to "
        f"nightly.backup (mode 0600, {size:,} bytes).",
        f"Backup ID {summary.header.id}. Restoring it needs this master key (ID "
        f"{summary.header.key_id.hex()}): keep a copy of the key apart from the backups.",
    ]
    event = AuditEvent.objects.get(event_type=EventType.BACKUP_CREATED)
    assert event.actor_username_snapshot.startswith("cli:")
    assert event.details == {
        "backup_id": str(summary.header.id),
        "destination": str(path),
        "bytes": size,
        "accounts": 1,
        "yubikeys": 1,
        "audit_events": 1,
    }


def test_quiet_for_cron(populated, tmp_path):
    assert run("backup-create", "-v", "0", str(tmp_path / "test.backup")) == ("", "")
    assert AuditEvent.objects.filter(event_type=EventType.BACKUP_CREATED).exists()


def test_if_database_backs_up_a_database(populated, tmp_path):
    _, err = run("backup-create", "--if-database", str(tmp_path / "test.backup"))
    assert err.startswith("Backed up 1 account, 1 YubiKey,")
    assert service.verify((tmp_path / "test.backup").open("rb")).counts["users"] == 1


def test_if_database_before_the_first_migrate(tmp_path, monkeypatch):
    # The package's upgrade of an installation never set up (packaging/deb/preinst).
    monkeypatch.setattr(connection.introspection, "table_names", lambda *args, **kwargs: [])
    out, err = run("backup-create", "--if-database", str(tmp_path))
    assert (out, err) == ("", "No database yet: nothing to back up.\n")
    assert run("backup-create", "--if-database", "-v", "0", str(tmp_path)) == ("", "")
    assert list(tmp_path.iterdir()) == []
    assert not AuditEvent.objects.filter(event_type=EventType.BACKUP_CREATED).exists()
    with pytest.raises(CommandError, match="isn't fully migrated; run yk-portal migrate first"):
        run("backup-create", str(tmp_path))  # without the option, as before


def test_if_database_never_creates_the_sqlite_file(tmp_path, monkeypatch):
    if connection.vendor != "sqlite":
        pytest.skip("SQLite only")
    missing = tmp_path / "yk-portal.sqlite3"
    monkeypatch.setitem(connection.settings_dict, "NAME", str(missing))
    _, err = run("backup-create", "--if-database", str(tmp_path))
    assert err == "No database yet: nothing to back up.\n"
    assert list(tmp_path.iterdir()) == []


def test_a_directory_gets_a_dated_name(populated, tmp_path):
    run("backup-create", str(tmp_path))
    [path] = tmp_path.iterdir()
    assert re.fullmatch(r"yk-portal-\d{8}T\d{6}Z\.backup", path.name)
    assert service.verify(path.open("rb")).counts["users"] == 1


def test_an_existing_file_is_replaced_only_with_force(populated, tmp_path):
    path = tmp_path / "test.backup"
    path.write_text("old")
    with pytest.raises(CommandError, match="already exists \\(use --force to replace it\\); no b"):
        run("backup-create", str(path))
    assert path.read_text() == "old"
    assert not AuditEvent.objects.filter(event_type=EventType.BACKUP_CREATED).exists()
    run("backup-create", "--force", str(path))
    assert service.verify(path.open("rb")).counts["users"] == 1


def test_a_failed_backup_leaves_no_file(populated, tmp_path, monkeypatch):
    def fail(write):
        write(b'{"table":"roles"}\n')
        raise service.BackupError("the disk is full")

    monkeypatch.setattr(data, "dump", fail)
    with pytest.raises(CommandError, match="the disk is full; no backup made"):
        run("backup-create", str(tmp_path / "test.backup"))
    assert list(tmp_path.iterdir()) == []
    assert not AuditEvent.objects.filter(event_type=EventType.BACKUP_CREATED).exists()


def test_a_missing_directory(populated, tmp_path):
    with pytest.raises(CommandError, match="backups/: no such directory; no backup made"):
        run("backup-create", f"{tmp_path}/backups/")
    assert list(tmp_path.iterdir()) == []


def test_a_database_error_stops_the_backup(populated, tmp_path, monkeypatch):
    def locked(write):
        raise OperationalError("database is locked")

    monkeypatch.setattr(data, "dump", locked)
    with pytest.raises(
        CommandError, match="the database can't be read: database is locked; no backup made"
    ):
        run("backup-create", str(tmp_path / "test.backup"))
    assert list(tmp_path.iterdir()) == []


def test_a_backup_whose_event_cant_be_recorded(populated, tmp_path, monkeypatch):
    def refused(*args):
        raise OperationalError("database is locked")

    monkeypatch.setattr(service, "record_created", refused)
    path = tmp_path / "test.backup"
    message = "its BACKUP_CREATED audit event couldn't be recorded: database is locked"
    with pytest.raises(
        CommandError, match=rf"backed up to {path} \(mode 0600, .*\), but {message}"
    ):
        run("backup-create", str(path))
    assert service.verify(path.open("rb")).counts["users"] == 1


class ClosedPipe:
    """Standard output whose reader has gone."""

    def __init__(self) -> None:
        self.buffer = self

    def isatty(self) -> bool:
        return False

    def write(self, data: bytes) -> int:
        raise BrokenPipeError(32, "Broken pipe")

    def flush(self) -> None:
        pass


def test_standard_output_closed(populated, monkeypatch):
    monkeypatch.setattr("sys.stdout", ClosedPipe())
    with pytest.raises(CommandError, match="cannot write to standard output: Broken pipe"):
        run("backup-create", "-")
    assert not AuditEvent.objects.filter(event_type=EventType.BACKUP_CREATED).exists()


class Terminal(io.TextIOWrapper):
    def isatty(self) -> bool:
        return True


def test_to_standard_output(populated, monkeypatch):
    stdout = io.TextIOWrapper(io.BytesIO())
    monkeypatch.setattr("sys.stdout", stdout)
    _, err = run("backup-create", "-")
    contents = "1 account, 1 YubiKey, 0 groups, 0 settings and 1 audit event"
    assert err.startswith(f"Backed up {contents} to standard output.\n")
    backup = stdout.buffer.getvalue()  # type: ignore[attr-defined]
    assert service.verify(io.BytesIO(backup)).counts["users"] == 1
    event = AuditEvent.objects.get(event_type=EventType.BACKUP_CREATED)
    assert event.details["destination"] == "standard output"
    assert event.details["bytes"] == len(backup)


def test_never_to_a_terminal(populated, monkeypatch):
    monkeypatch.setattr("sys.stdout", Terminal(io.BytesIO()))
    with pytest.raises(CommandError, match="won't write a backup to a terminal"):
        run("backup-create", "-")


# backup-verify


def test_verify(populated, tmp_path):
    path = create(tmp_path)
    summary = service.verify(path.open("rb"))
    out, _ = run("backup-verify", str(path))
    assert lines(out) == [
        f"Backup {summary.header.id}",
        f"Made {service.made_at(summary.header)} by yk-portal "
        f"{service.application_version()}, from "
        f"{'SQLite' if summary.header.database == 'sqlite' else 'PostgreSQL'}",
        "Holds 1 account, 1 YubiKey, 0 groups, 0 settings and 1 audit event",
        "Verified: authentic and complete, and this installation can restore it (the same "
        "master key and schema).",
    ]


def test_verify_from_standard_input(populated, tmp_path, monkeypatch):
    path = create(tmp_path)
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(path.read_bytes())))
    out, _ = run("backup-verify", "-")
    assert lines(out)[-1].startswith("Verified: authentic and complete")


def test_verify_a_tampered_backup(populated, tmp_path):
    path = create(tmp_path)
    data_ = bytearray(path.read_bytes())
    data_[-20] ^= 1
    path.write_bytes(bytes(data_))
    with pytest.raises(CommandError, match=f"{path}: authentication failed at segment 0"):
        run("backup-verify", str(path))


@pytest.mark.parametrize(("content", "message"), [(None, "cannot read"), (b"x", "not a yk-p")])
def test_verify_what_isnt_a_backup(tmp_path, content, message):
    path = tmp_path / "test.backup"
    if content is not None:
        path.write_bytes(content)
    with pytest.raises(CommandError, match=message):
        run("backup-verify", str(path))


# backup-restore


def test_restore_into_an_empty_database(populated, tmp_path):
    path = create(tmp_path)
    wipe()
    out, err = run("backup-restore", "--no-input", str(path))
    summary = service.verify(path.open("rb"))
    assert lines(out)[3:] == [
        "Verified: authentic and complete.",
        f"Restored backup {summary.header.id}: 1 account, 1 YubiKey, 0 groups, 0 settings "
        "and 1 audit event.",
        "A YubiKey used since the backup was made can have OTP counters behind its last OTP. "
        "If radiator-yubikey has newer ones, move them forward:",
        "  yubikey-db.sh export - | yk-portal radiator-import --counters-only -",
    ]
    assert err == ""
    assert User.objects.get().username == "alice"
    assert AuditEvent.objects.filter(event_type=EventType.BACKUP_RESTORED).exists()


def test_a_database_with_data_needs_replace(populated, tmp_path):
    path = create(tmp_path)
    with pytest.raises(
        CommandError,
        match="the database isn't empty: it holds 1 account, 1 YubiKey, 0 groups and 0 "
        "settings; to replace them, use --replace; nothing was restored",
    ):
        run("backup-restore", "--no-input", str(path))
    assert not AuditEvent.objects.filter(event_type=EventType.BACKUP_RESTORED).exists()


def test_restore_asks_first(populated, tmp_path, monkeypatch, make_user, actor):
    path = create(tmp_path)
    make_user("since")
    key = YubikeyCredential.objects.get()
    YubikeyCredential.objects.filter(pk=key.pk).update(last_usage_counter=99)
    record(EventType.LOGOUT, actor)
    event = AuditEvent.objects.get(event_type=EventType.ACCOUNT_CREATED)
    with rewritable():
        AuditEvent.objects.filter(pk=event.pk).update(details={"forged": True})
    prompts = []

    def answer(prompt: str) -> str:
        prompts.append(prompt)
        return "restore\n"

    monkeypatch.setattr("builtins.input", answer)
    out, err = run("backup-restore", "--replace", str(path))
    assert lines(out)[4:6] == [
        "The database holds 2 accounts, 1 YubiKey, 0 groups and 0 settings: the restore "
        "replaces them with the backup's. Its audit events are kept, and the backup's added.",
        "Every session ends: everyone signs in again.",
    ]
    assert prompts == ['Type "restore" to restore this backup: ']
    assert lines(out)[6].startswith("Restored backup ")
    assert lines(out)[7:9] == [
        "Kept the database's OTP counters for 1 YubiKey, which were ahead of the backup's.",
        "Kept 2 audit events that the backup doesn't have.",
    ]
    assert lines(err) == [
        "Warning: put back 1 audit event as the backup has them: the database's differed, "
        "so the audit log was changed outside yk-portal."
    ]
    assert list(User.objects.values_list("username", flat=True)) == ["alice"]
    assert YubikeyCredential.objects.get().last_usage_counter == 99


@pytest.mark.parametrize("answer", ["yes", "", EOFError])
def test_restore_not_confirmed(populated, tmp_path, monkeypatch, answer):
    path = create(tmp_path)

    def respond(prompt: str) -> str:
        if answer is EOFError:
            raise EOFError
        return str(answer)

    monkeypatch.setattr("builtins.input", respond)
    message = "use --no-input" if answer is EOFError else "not confirmed; nothing was restored"
    with pytest.raises(CommandError, match=message):
        run("backup-restore", "--replace", str(path))
    assert not AuditEvent.objects.filter(event_type=EventType.BACKUP_RESTORED).exists()


def test_restore_a_missing_file(tmp_path):
    with pytest.raises(CommandError, match="cannot read .*: No such file"):
        run("backup-restore", "--no-input", str(tmp_path / "none.backup"))
