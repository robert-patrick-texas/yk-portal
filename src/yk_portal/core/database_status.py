"""yk-portal database-status: which database, and whether it is ready (spec §30, §36;
addendum §18.6).

A problem means the application won't work as it should: the database can't be
reached, migrations are missing, the audit log's triggers are gone, SQLite runs
without its settings, or PostgreSQL's encoding isn't UTF-8. A warning is a
setup worth changing: a role with more privileges than it needs, a connection
over the network without TLS, a database file other users can read.
"""

import grp
import ipaddress
import pwd
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from django.db import DatabaseError
from django.db.migrations.executor import MigrationExecutor

from yk_portal.audit.immutability import TRIGGERS


@dataclass
class Status:
    lines: list[tuple[str, str]] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def show(self, label: str, text: str) -> None:
        self.lines.append((label, text))


def database_status(connection: Any) -> Status:
    """Check the database of CONNECTION, a Django connection."""
    status = Status()
    if connection.vendor == "sqlite":
        path = Path(connection.settings_dict["NAME"])
        status.show("Backend", f"SQLite {connection.Database.sqlite_version}")
        if not path.exists():  # connecting would create it
            status.show("Database", f"{path}: none yet")
            status.problems.append("there is no database yet; run yk-portal migrate")
            return status
        _sqlite_file(status, path)
    try:
        if connection.vendor == "postgresql":
            _postgresql(status, connection)
        else:
            _sqlite(status, connection)
        _migrations(status, connection)
        _triggers(status, connection)
    except DatabaseError as e:
        if not status.lines:  # PostgreSQL, never reached
            status.show("Backend", "PostgreSQL")
            status.show("Database", _configured(connection.settings_dict))
        status.problems.append(f"the database can't be used: {' '.join(str(e).split())}")
    return status


def _configured(settings: dict[str, Any]) -> str:
    """The PostgreSQL database the settings name, for when it can't be reached."""
    name = settings["NAME"] or settings["OPTIONS"].get("service", "")
    host = settings["HOST"] or "the local socket"
    port = f":{settings['PORT']}" if settings["PORT"] else ""
    return f"{name} on {host}{port}"


def _sqlite_file(status: Status, path: Path) -> None:
    info = path.stat()
    owner = _name(pwd.getpwuid, info.st_uid)
    group = _name(grp.getgrgid, info.st_gid)
    status.show("Database", f"{path} (mode {stat.S_IMODE(info.st_mode):04o}, {owner}:{group})")
    if info.st_mode & stat.S_IRWXO:
        status.warnings.append(f"other users can open the file; chmod o-rwx {path}")


def _name(lookup: Any, number: int) -> str:
    try:
        return lookup(number)[0]
    except KeyError:
        return str(number)


def _sqlite(status: Status, connection: Any) -> None:
    with connection.cursor() as cursor:
        journal = cursor.execute("PRAGMA journal_mode").fetchone()[0]
        synchronous = cursor.execute("PRAGMA synchronous").fetchone()[0]
        foreign_keys = cursor.execute("PRAGMA foreign_keys").fetchone()[0]
    sync_names = {0: "OFF", 1: "NORMAL", 2: "FULL", 3: "EXTRA"}
    status.show(
        "Settings",
        f"journal {journal.upper()}, synchronous {sync_names.get(synchronous, synchronous)}, "
        f"foreign keys {'on' if foreign_keys else 'off'}",
    )
    if journal != "wal" or synchronous < 2 or not foreign_keys:
        status.problems.append(
            "SQLite should run with journal WAL, synchronous FULL and foreign keys on "
            "(WAL needs a local file system)"
        )


def _postgresql(status: Status, connection: Any) -> None:
    with connection.cursor() as cursor:
        info = connection.connection.info
        version = info.server_version
        status.show("Backend", f"PostgreSQL {version // 10000}.{version % 10000}")
        local = _is_local(info.host)
        where = f"{info.host}" if info.host.startswith("/") else f"{info.host}:{info.port}"
        status.show("Database", f"{info.dbname} on {where}, as {info.user}")

        cursor.execute("SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
        ssl, protocol = cursor.fetchone() or (False, None)
        if ssl:
            status.show("TLS", protocol or "yes")
        else:
            status.show("TLS", "not used" + (" (same host)" if local else ""))
            if not local:
                status.warnings.append(
                    "the connection to the database isn't encrypted; "
                    "add sslmode=verify-full to postgres_dsn (spec §30)"
                )

        cursor.execute(
            "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls "
            "FROM pg_roles WHERE rolname = current_user"
        )
        names = ("SUPERUSER", "CREATEDB", "CREATEROLE", "REPLICATION", "BYPASSRLS")
        extra = [name for name, has in zip(names, cursor.fetchone(), strict=True) if has]
        status.show("Role", f"{info.user}: {', '.join(extra) or 'no extra privileges'}")
        if extra:
            status.warnings.append(
                f"the role {info.user} has {', '.join(extra)}, and needs none of them: "
                "owning the database is enough (spec §30)"
            )

        columns = "pg_encoding_to_char(encoding), datcollate, datctype"
        if version >= 170000:
            columns += ", datlocprovider, datlocale"
        elif version >= 150000:
            columns += ", datlocprovider, NULL"
        else:
            columns += ", 'c', NULL"
        cursor.execute(f"SELECT {columns} FROM pg_database WHERE datname = current_database()")  # noqa: S608
        encoding, collate, ctype, provider, locale = cursor.fetchone()
    provider = {"b": "builtin", "c": "libc", "i": "ICU"}.get(provider, provider)
    shown = locale or (collate if collate == ctype else f"{collate}, character type {ctype}")
    status.show("Encoding", f"{encoding}, locale {shown} ({provider})")
    if encoding != "UTF8":
        status.problems.append(
            f"the database's encoding is {encoding}; create it with ENCODING 'UTF8' (README)"
        )
    elif not _unicode_case(provider, ctype, locale):
        status.warnings.append(
            "the database's locale knows the case of ASCII letters only, so searches don't "
            "match as on SQLite; create it with LOCALE 'C.UTF-8' (README)"
        )


def _is_local(host: str) -> bool:
    """Whether HOST, as libpq reports it, is a Unix socket or this machine."""
    if not host or host.startswith("/") or host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _unicode_case(provider: str, ctype: str, locale: str | None) -> bool:
    """Whether the database's UPPER() and LOWER() know every letter, not only ASCII."""
    if provider == "ICU":
        return True
    if provider == "builtin":
        return locale in ("C.UTF-8", "PG_UNICODE_FAST")
    return bool(re.search(r"\.utf-?8$", ctype, re.IGNORECASE))


def _migrations(status: Status, connection: Any) -> None:
    executor = MigrationExecutor(connection)
    graph = executor.loader.graph
    pending = executor.migration_plan(graph.leaf_nodes())
    unknown = sorted(set(executor.loader.applied_migrations) - set(graph.nodes))
    applied = len(graph.nodes) - len(pending)
    if unknown:
        names = ", ".join(f"{app}.{name}" for app, name in unknown)
        status.show("Migrations", f"{len(unknown)} applied that this version doesn't have")
        status.problems.append(f"the database is newer than this version of yk-portal: {names}")
    elif pending:
        names = ", ".join(f"{m.app_label}.{m.name}" for m, _ in pending[:3])
        more = f" and {len(pending) - 3} more" if len(pending) > 3 else ""
        status.show("Migrations", f"{applied} applied, {len(pending)} not")
        status.problems.append(f"not applied: {names}{more}; run yk-portal migrate")
    else:
        status.show("Migrations", f"all {applied} applied")


def _triggers(status: Status, connection: Any) -> None:
    if "audit_events" not in connection.introspection.table_names():
        return
    with connection.cursor() as cursor:
        if connection.vendor == "postgresql":
            cursor.execute(
                "SELECT tgname FROM pg_trigger "
                "WHERE tgrelid = 'audit_events'::regclass AND NOT tgisinternal"
            )
        else:
            cursor.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'trigger' AND tbl_name = 'audit_events'"
            )
        found = {name for (name,) in cursor.fetchall()}
    missing = sorted(TRIGGERS[connection.vendor] - found)
    if missing:
        status.show("Audit log", "not protected")
        status.problems.append(
            f"the audit log's triggers are missing ({', '.join(missing)}): events can be "
            "changed or deleted with SQL (addendum §17.1)"
        )
    else:
        status.show("Audit log", "protected by triggers")
