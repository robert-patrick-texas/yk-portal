"""yk-portal database-status (spec §36; addendum §18.6)."""

from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.db.utils import ConnectionHandler

from yk_portal.audit.immutability import TRIGGERS
from yk_portal.core.config import postgresql_database, sqlite_database
from yk_portal.core.database_status import _is_local, _unicode_case, database_status

LABELS = {
    "sqlite": ["Backend", "Database", "Settings", "Migrations", "Audit log"],
    "postgresql": [
        "Backend",
        "Database",
        "Driver",
        "TLS",
        "Role",
        "Encoding",
        "Migrations",
        "Audit log",
    ],
}


def run() -> str:
    out = StringIO()
    call_command("database-status", stdout=out, stderr=out)
    return out.getvalue()


@pytest.mark.django_db
def test_the_test_database_is_ready():
    status = database_status(connection)
    assert [label for label, _ in status.lines] == LABELS[connection.vendor]
    assert status.problems == []
    shown = dict(status.lines)
    assert shown["Migrations"].startswith("all ")
    assert shown["Audit log"] == "protected by triggers"


@pytest.mark.django_db
@pytest.mark.skipif(connection.vendor != "postgresql", reason="psycopg")
def test_the_postgresql_driver_is_shown(monkeypatch):
    import psycopg

    shown = dict(database_status(connection).lines)
    assert shown["Driver"] == f"psycopg {psycopg.__version__} ({psycopg.pq.__impl__})"
    monkeypatch.setattr(psycopg.pq, "__impl__", "python")
    assert any("pure-Python" in w for w in database_status(connection).warnings)
    monkeypatch.setattr(psycopg.pq, "__impl__", "c")
    assert not any("pure-Python" in w for w in database_status(connection).warnings)


@pytest.mark.django_db
def test_the_command_lists_the_checks():
    output = run()
    assert "Migrations: all " in output
    assert "Audit log:  protected by triggers" in output


@pytest.mark.django_db
def test_missing_audit_triggers_are_a_problem():
    with connection.cursor() as cursor:  # undone with the test's transaction
        for name in TRIGGERS[connection.vendor]:
            on = " ON audit_events" if connection.vendor == "postgresql" else ""
            cursor.execute(f"DROP TRIGGER {name}{on}")
    with pytest.raises(CommandError, match=r"isn't ready \(1 problem\)"):
        run()
    (problem,) = database_status(connection).problems
    assert problem.startswith("the audit log's triggers are missing")


@pytest.mark.django_db(transaction=True)
def test_a_migration_not_applied_is_a_problem():
    executor = MigrationExecutor(connection)
    try:
        executor.migrate([("audit", "0005_details_unicode")])
        status = database_status(connection)
        assert dict(status.lines)["Migrations"].endswith("applied, 1 not")
        assert status.problems == [
            "not applied: audit.0006_login_throttled_source_ip; run yk-portal migrate"
        ]
    finally:
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())


def test_no_sqlite_database_yet(tmp_path):
    path = tmp_path / "absent.sqlite3"
    status = database_status(ConnectionHandler({"default": sqlite_database(path)})["default"])
    assert status.problems == ["there is no database yet; run yk-portal migrate"]
    assert not path.exists()  # not created by looking


def test_a_postgresql_server_out_of_reach(tmp_path, django_db_blocker):
    settings = postgresql_database({"dbname": "yk_portal", "host": str(tmp_path / "no-socket")})
    with django_db_blocker.unblock():
        status = database_status(ConnectionHandler({"default": settings})["default"])
    assert status.lines == [
        ("Backend", "PostgreSQL"),
        ("Database", f"yk_portal on {tmp_path / 'no-socket'}"),
    ]
    (problem,) = status.problems
    assert problem.startswith("the database can't be used: ") and "no-socket" in problem


@pytest.mark.parametrize(("mode", "warned"), [(0o600, False), (0o640, False), (0o644, True)])
def test_a_sqlite_file_others_can_open(tmp_path, django_db_blocker, mode, warned):
    path = tmp_path / "db.sqlite3"
    db = ConnectionHandler({"default": sqlite_database(path)})["default"]
    with django_db_blocker.unblock():
        db.ensure_connection()
        path.chmod(mode)
        status = database_status(db)
        db.close()
    shown = dict(status.lines)
    assert shown["Database"].startswith(f"{path} (mode {mode:04o}, ")
    assert shown["Settings"] == "journal WAL, synchronous FULL, foreign keys on"
    assert any("other users can open" in w for w in status.warnings) == warned


@pytest.mark.parametrize(
    ("provider", "ctype", "locale", "unicode"),
    [
        ("libc", "C.UTF-8", None, True),
        ("libc", "en_US.utf8", None, True),
        ("libc", "C", None, False),
        ("libc", "POSIX", None, False),
        ("builtin", "C", "C.UTF-8", True),
        ("builtin", "C", "C", False),
        ("ICU", "C", "und", True),
    ],
)
def test_which_locales_know_every_letters_case(provider, ctype, locale, unicode):
    assert _unicode_case(provider, ctype, locale) == unicode


@pytest.mark.parametrize(
    ("host", "local"),
    [
        ("/var/run/postgresql", True),
        ("", True),
        ("localhost", True),
        ("127.0.0.1", True),
        ("::1", True),
        ("db.example.com", False),
        ("192.0.2.5", False),
    ],
)
def test_which_hosts_are_this_machine(host, local):
    assert _is_local(host) == local
