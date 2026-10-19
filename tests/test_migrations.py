"""Migration parity (spec §30, §44.6, Phase 8; addendum §18.5).

The same migrations run on SQLite and PostgreSQL. On each, the schema they
build must be the one the models describe, apart from the audit log's
triggers, and they must undo to nothing and redo to the same schema. With
test_project's makemigrations check, both backends hold the same logical
schema.
"""

import importlib
import re
from collections.abc import Generator
from typing import Any

import pytest
from django.apps import apps
from django.db import DEFAULT_DB_ALIAS, connection, connections
from django.db.migrations.executor import MigrationExecutor

from yk_portal.audit import immutability

pytestmark = pytest.mark.django_db(transaction=True)

_immutable = importlib.import_module("yk_portal.audit.migrations.0004_immutable")

ALIAS = "from_models"


def explicit_names() -> set[str]:
    """The constraint and index names the models give; the others are made up by Django
    or the database, differently by how the table came to be."""
    return {
        item.name
        for model in apps.get_models()
        for item in [*model._meta.constraints, *model._meta.indexes]
    }


def schema(db: Any) -> dict[str, Any]:
    """Each table's columns, constraints and indexes, as the database reports them."""
    names = explicit_names()
    found: dict[str, Any] = {}
    with db.cursor() as cursor:
        introspection = db.introspection
        for table in sorted(t.name for t in introspection.get_table_list(cursor) if t.type == "t"):
            if table == "django_migrations":
                continue
            columns = {c.name: c for c in introspection.get_table_description(cursor, table)}
            constraints = sorted(
                repr((name if name in names else None, sorted(c.items(), key=lambda kv: kv[0])))
                for name, c in introspection.get_constraints(cursor, table).items()
            )
            found[table] = {"columns": columns, "constraints": constraints}
    return found


def triggers(db: Any) -> set[str]:
    with db.cursor() as cursor:
        if db.vendor == "postgresql":
            cursor.execute("SELECT tgname FROM pg_trigger WHERE NOT tgisinternal")
        else:
            cursor.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
        return {name for (name,) in cursor.fetchall()}


def expected_triggers(vendor: str) -> set[str]:
    create, _ = _immutable.TRIGGERS[vendor]
    return {m[1] for s in create if (m := re.match(r"CREATE TRIGGER (\w+)", s))}


@pytest.fixture
def from_models(tmp_path) -> Generator[Any]:
    """A second, empty database of the same backend, with tables made from the models."""
    settings = dict(connection.settings_dict)
    if connection.vendor == "postgresql":
        settings["NAME"] = f"{connection.settings_dict['NAME']}_{ALIAS}"
        with connection._nodb_cursor() as cursor:
            cursor.execute(f'DROP DATABASE IF EXISTS "{settings["NAME"]}"')
            cursor.execute(f'CREATE DATABASE "{settings["NAME"]}"')
    else:
        settings["NAME"] = tmp_path / f"{ALIAS}.sqlite3"
    # Outside django.db.connections, which the test may not use, so nothing may look it up
    # by alias: no atomic schema editor, and SQLite's JSON check answered beforehand.
    db = type(connections[DEFAULT_DB_ALIAS])(settings, alias=ALIAS)
    if db.vendor == "sqlite":
        db.features.supports_json_field = connection.features.supports_json_field
    try:
        with db.schema_editor(atomic=False) as editor:
            for model in apps.get_models():
                editor.create_model(model)
        yield db
    finally:
        db.close()
        if connection.vendor == "postgresql":
            with connection._nodb_cursor() as cursor:
                cursor.execute(f'DROP DATABASE "{settings["NAME"]}"')


def test_migrations_build_the_models_schema(from_models):
    assert schema(connection) == schema(from_models)


def test_migrations_add_the_audit_triggers():
    assert triggers(connection) == expected_triggers(connection.vendor)
    assert expected_triggers(connection.vendor) == immutability.TRIGGERS[connection.vendor]


def test_migrations_undo_to_nothing_and_redo():
    before = schema(connection)
    executor = MigrationExecutor(connection)
    try:
        executor.migrate([(app, None) for app in executor.loader.migrated_apps])
        assert connection.introspection.table_names() == ["django_migrations"]
        assert triggers(connection) == set()
    finally:
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())
    assert schema(connection) == before
    assert triggers(connection) == expected_triggers(connection.vendor)
