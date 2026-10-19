"""Audit events can't be changed or deleted, even by SQL that bypasses the model
(spec §9; addendum §17.1).

Triggers refuse UPDATE and DELETE on audit_events with an integrity error.
TRUNCATE and DROP TABLE, which need the table's owner, stay possible: the copy
in the system journal is the record that survives them (addendum §17.6).

Restoring a backup rewrites the table through yk_portal.audit.immutability:
the PostgreSQL trigger allows changes while the transaction-local setting
yk_portal.audit_rewrite is "on", which needs no privilege; on SQLite the
triggers are dropped and created again in the restore's transaction.

A later migration that rebuilds audit_events on SQLite (most column changes do)
drops these triggers, and must create them again; tests/audit check that they
are there.
"""

from django.db import migrations

TRIGGERS = {
    "sqlite": (
        [
            "CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END",
            "CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END",
        ],
        [
            "DROP TRIGGER audit_events_no_update",
            "DROP TRIGGER audit_events_no_delete",
        ],
    ),
    "postgresql": (
        [
            "CREATE FUNCTION audit_events_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN "
            "IF current_setting('yk_portal.audit_rewrite', true) = 'on' THEN "
            "IF TG_OP = 'DELETE' THEN RETURN OLD; END IF; RETURN NEW; "
            "END IF; "
            "RAISE EXCEPTION 'audit events are immutable' "
            "USING ERRCODE = 'integrity_constraint_violation'; "
            "END $$",
            "CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON audit_events "
            "FOR EACH ROW EXECUTE FUNCTION audit_events_immutable()",
        ],
        [
            "DROP TRIGGER audit_events_immutable ON audit_events",
            "DROP FUNCTION audit_events_immutable()",
        ],
    ),
}


def _run(schema_editor, forward: bool) -> None:
    vendor = schema_editor.connection.vendor
    if vendor not in TRIGGERS:
        raise NotImplementedError(f"no audit triggers for {vendor}")
    create, drop = TRIGGERS[vendor]
    for statement in create if forward else drop:
        schema_editor.execute(statement)


def create_triggers(apps, schema_editor):
    _run(schema_editor, forward=True)


def drop_triggers(apps, schema_editor):
    _run(schema_editor, forward=False)


class Migration(migrations.Migration):
    dependencies = [
        ("audit", "0003_logout_access_denied_indexes"),
    ]

    operations = [
        migrations.RunPython(create_triggers, drop_triggers),
    ]
