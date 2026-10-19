import json
import uuid
from datetime import UTC, datetime

import pytest
from django.db import connection

from yk_portal.accounts.models import Group, Role, User, UserGroup, UserRole
from yk_portal.audit.immutability import rewritable
from yk_portal.audit.models import AuditEvent
from yk_portal.backup import data
from yk_portal.backup.encrypted import BackupError
from yk_portal.portal_settings.models import Setting
from yk_portal.yubikeys.models import ProvisioningMethod, YubikeyCredential

pytestmark = pytest.mark.django_db

T1 = datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=UTC)
T2 = datetime(2026, 10, 18, 23, 59, 59, 1, tzinfo=UTC)


def u(n: int) -> uuid.UUID:
    return uuid.UUID(int=n)


def dumped() -> bytes:
    out = bytearray()
    data.dump(out.extend)
    return bytes(out)


@pytest.fixture
def database() -> None:
    """One row in every table, with known values, of every type a column holds."""
    Role.objects.all().delete()
    user_role = Role.objects.create(id=u(1), name="user")
    Role.objects.create(id=u(2), name="admin")
    alice = User.objects.create(
        id=u(3),
        username="alice",
        email="alice@example.com",
        display_name="Émile 😀",
        comment='line 1\n\tline "2"',
        temporary_password_expires_at=T2,
        failed_login_count=2,
        theme="dark",
    )
    User.objects.filter(pk=alice.pk).update(created_at=T1, updated_at=T2)
    UserRole.objects.create(id=u(4), user=alice, role=user_role)
    group = Group.objects.create(id=u(5), name="Ops", description="Network")
    Group.objects.filter(pk=group.pk).update(created_at=T1, updated_at=T1)
    UserGroup.objects.create(id=u(6), user=alice, group=group)
    key = YubikeyCredential.objects.create(
        id=u(7),
        user=alice,
        public_id="vvcccccccccb",
        encrypted_private_id=b"\x01\x00\xff",
        private_id_digest="d" * 64,
        encrypted_aes_secret=b"",
        radius_pin_hash="{crypt}$6$salt$hash",
        last_usage_counter=300,
        last_session_counter=255,
        provisioning_method=ProvisioningMethod.MIGRATED,
        created_by=alice,
    )
    YubikeyCredential.objects.filter(pk=key.pk).update(created_at=T1, updated_at=T1)
    Setting.objects.create(key="portal_name", value="Ops portal", updated_by=alice)
    Setting.objects.create(key="default_group", value=None)
    Setting.objects.filter().update(updated_at=T2)
    AuditEvent.objects.create(
        id=u(8),
        timestamp=T1,
        event_type="SETTING_CHANGED",
        actor_user_id=u(3),
        actor_username_snapshot="alice",
        source_ip="2001:db8::1",
        session_id=u(9),
        details={"name": "Clé  "},
    )


def test_the_text_is_the_same_on_both_backends(database):
    expected = [
        '{"table":"roles","columns":["id","name"]}',
        '["00000000-0000-0000-0000-000000000001","user"]',
        '["00000000-0000-0000-0000-000000000002","admin"]',
        '{"table":"users","columns":["id","username","email","display_name","comment",'
        '"temporary_password_hash","temporary_password_expires_at","state",'
        '"failed_login_count","theme","created_at","updated_at","last_login_at"]}',
        '["00000000-0000-0000-0000-000000000003","alice","alice@example.com",'
        '"\\u00c9mile \\ud83d\\ude00","line 1\\n\\tline \\"2\\"","",'
        '"2026-10-18T23:59:59.000001+00:00","PROVISIONING",2,"dark",'
        '"2026-01-02T03:04:05.678901+00:00","2026-10-18T23:59:59.000001+00:00",null]',
        '{"table":"user_roles","columns":["id","user_id","role_id"]}',
        '["00000000-0000-0000-0000-000000000004","00000000-0000-0000-0000-000000000003",'
        '"00000000-0000-0000-0000-000000000001"]',
        '{"table":"groups","columns":["id","name","description","created_at","updated_at"]}',
        '["00000000-0000-0000-0000-000000000005","Ops","Network",'
        '"2026-01-02T03:04:05.678901+00:00","2026-01-02T03:04:05.678901+00:00"]',
        '{"table":"user_groups","columns":["id","user_id","group_id"]}',
        '["00000000-0000-0000-0000-000000000006","00000000-0000-0000-0000-000000000003",'
        '"00000000-0000-0000-0000-000000000005"]',
        '{"table":"yubikey_credentials","columns":["id","user_id","label","slot_number",'
        '"public_id","encrypted_private_id","private_id_digest","encrypted_aes_secret",'
        '"pin_hash","radius_pin_hash","failed_login_count","enabled","last_usage_counter",'
        '"last_session_counter","provisioning_method","migration_source",'
        '"created_by_user_id","created_at","updated_at","last_used_at"]}',
        '["00000000-0000-0000-0000-000000000007","00000000-0000-0000-0000-000000000003",'
        f'"",null,"vvcccccccccb","AQD/","{"d" * 64}","","","{{crypt}}$6$salt$hash",0,true,'
        '300,255,"MIGRATED","","00000000-0000-0000-0000-000000000003",'
        '"2026-01-02T03:04:05.678901+00:00","2026-01-02T03:04:05.678901+00:00",null]',
        '{"table":"settings","columns":["key","value","updated_at","updated_by_user_id"]}',
        '["default_group",null,"2026-10-18T23:59:59.000001+00:00",null]',
        '["portal_name","Ops portal","2026-10-18T23:59:59.000001+00:00",'
        '"00000000-0000-0000-0000-000000000003"]',
        '{"table":"audit_events","columns":["id","timestamp","event_type","actor_user_id",'
        '"actor_username_snapshot","target_user_id","target_username_snapshot","source_ip",'
        '"session_id","result","details"]}',
        '["00000000-0000-0000-0000-000000000008","2026-01-02T03:04:05.678901+00:00",'
        '"SETTING_CHANGED","00000000-0000-0000-0000-000000000003","alice",null,"",'
        '"2001:db8::1","00000000-0000-0000-0000-000000000009","SUCCESS",'
        '{"name":"Cl\\u00e9 \\u2028"}]',
    ]
    text = dumped()
    assert text.decode("ascii").split("\n") == [*expected, ""]
    assert dumped() == text  # the same database, the same text


def database_rows() -> dict[str, list[list[object]]]:
    """Every row of every table, as Django reads them, in primary-key order."""
    return {
        data.table(model): [
            list(row)
            for row in model._base_manager.order_by("pk").values_list(
                *(f.attname for f in data.fields(model))
            )
        ]
        for model in data.TABLES
    }


def parsed(text: bytes, chunk: int = 7) -> dict[str, list[list[object]]]:
    rows: dict[str, list[list[object]]] = {data.table(model): [] for model in data.TABLES}
    chunks = (text[n : n + chunk] for n in range(0, len(text), chunk))
    for model, row in data.parse(chunks):
        rows[data.table(model)].append(row)
    return rows


def test_parse_gives_the_values_django_reads(database):
    assert parsed(dumped()) == database_rows()


def test_counts(database):
    counts = data.dump(lambda line: None)
    assert counts == {
        "roles": 2,
        "users": 1,
        "user_roles": 1,
        "groups": 1,
        "user_groups": 1,
        "yubikey_credentials": 1,
        "settings": 2,
        "audit_events": 1,
    }


def test_an_empty_database():
    Role.objects.all().delete()
    text = dumped()
    assert text.count(b"\n") == len(data.TABLES)
    assert all(not rows for rows in parsed(text).values())


def lines(text: bytes) -> list[bytes]:
    return text.split(b"\n")[:-1]


def joined(lines: list[bytes]) -> bytes:
    return b"".join(line + b"\n" for line in lines)


def replaced(text: bytes, old: bytes, new: bytes) -> bytes:
    assert text.count(old) >= 1
    return text.replace(old, new, 1)


def refused(text: bytes, message: str) -> None:
    with pytest.raises(BackupError, match=message):
        parsed(text)


def test_tables_in_another_order_or_missing(database):
    text = lines(dumped())
    refused(joined(text[3:]), "expected the table roles, found users")
    refused(joined(text[:3]), "the data ends before the table users")
    refused(joined([*text, text[0]]), "the data goes on after the last table")
    refused(joined(text[1:]), "the data doesn't start with a table")
    refused(joined([b"{", *text[1:]]), "expected the table roles, found damaged data")


def test_columns_must_be_this_versions(database):
    refused(replaced(dumped(), b'"theme",', b""), "users: its columns aren't this version's")


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        (b'"alice@example.com"', b'"alice@example.com",7', "users, row 1: not a list of 13"),
        (b'"alice","alice@', b'7,"alice@', "users, row 1: username: expected text"),
        (b'"dark"', b"null", "users, row 1: theme: null in a column that doesn't allow it"),
        (b'"PROVISIONING",2,', b'"PROVISIONING",true,', "failed_login_count: expected a whole"),
        (b",300,", b',"300",', "last_usage_counter: expected a whole number"),
        (b",true,", b",1,", "enabled: expected true or false"),
        (b'"AQD/"', b'"AQD"', "encrypted_private_id: (Incorrect padding|Invalid base64)"),
        (b'"AQD/"', b'"AQ!/"', "encrypted_private_id: "),
        (
            b'"2026-01-02T03:04:05.678901+00:00","SETTING',
            b'"2026-01-02","SETTING',
            "audit_events, row 1: timestamp: a time without a time zone",
        ),
        (
            b'"2026-01-02T03:04:05.678901+00:00","SETTING',
            b'"yesterday","SETTING',
            "timestamp: Invalid isoformat",
        ),
        (b'"00000000-0000-0000-0000-000000000009"', b'"session"', "session_id: badly formed"),
        (
            b'["00000000-0000-0000-0000-000000000004"',
            b'["00000000-0000-0000-0000-000000000004"x',
            "user_roles, row 1: not JSON",
        ),
    ],
)
def test_values_of_the_wrong_type(database, old, new, message):
    refused(replaced(dumped(), old, new), message)


def test_references_to_rows_the_backup_doesnt_hold(database):
    role_row = b'["00000000-0000-0000-0000-000000000001","user"]\n'
    refused(replaced(dumped(), role_row, b""), "user_roles, row 1: role_id refers to a row")
    creator = b'"MIGRATED","","00000000-0000-0000-0000-000000000003"'
    other = b'"MIGRATED","","00000000-0000-0000-0000-00000000000a"'
    refused(replaced(dumped(), creator, other), "created_by_user_id refers to a row")
    # The audit log refers to accounts by plain IDs, which outlive them.
    actor = b'"SETTING_CHANGED","00000000-0000-0000-0000-000000000003"'
    deleted = b'"SETTING_CHANGED","00000000-0000-0000-0000-00000000000a"'
    assert parsed(replaced(dumped(), actor, deleted))["audit_events"]


def test_a_cut_line_or_a_huge_one(database, monkeypatch):
    text = dumped()
    refused(text[:-1], "cut short \\(no line break at its end\\)")
    monkeypatch.setattr(data, "_MAX_LINE_BYTES", 100)
    refused(text, "a line too long")


def test_json_values_are_kept_as_they_are(database):
    Setting.objects.create(key="login_notice", value={"nested": [1, "two", None]})
    rows = parsed(dumped())["settings"]
    assert [row[1] for row in rows] == [None, {"nested": [1, "two", None]}, "Ops portal"]
    line = next(line for line in lines(dumped()) if line.startswith(b'["login_notice"'))
    assert json.loads(line)[1] == {"nested": [1, "two", None]}


def test_json_objects_keep_the_order_django_reads(database):
    details = {"setting": "portal_name", "old": "a", "new": "b"}
    AuditEvent.objects.create(id=u(10), event_type="SETTING_CHANGED", details=details)
    stored = AuditEvent.objects.get(pk=u(10)).details
    [restored] = [row[-1] for row in parsed(dumped())["audit_events"] if row[0] == u(10)]
    assert isinstance(restored, dict)
    assert list(restored.items()) == list(stored.items())


def test_ip_addresses_are_written_one_way_on_both_backends(database):
    # PostgreSQL's inet gives "::192.0.2.1" where Django writes "::c000:201".
    AuditEvent.objects.create(id=u(10), event_type="LOGOUT", source_ip="::192.0.2.1")
    line = next(line for line in lines(dumped()) if line.startswith(b'["' + str(u(10)).encode()))
    assert json.loads(line)[7] == "::c000:201"
    stored = AuditEvent.objects.values_list(*(f.attname for f in data.fields(AuditEvent)))
    assert data.canonical(AuditEvent, stored.get(pk=u(10)))[7] == "::c000:201"


def test_json_null_in_a_column_that_cant_be_null(database):
    """SQL around yk-portal could store it; a backup must still restore."""
    with rewritable(), connection.cursor() as cursor:
        cursor.execute("UPDATE audit_events SET details = 'null'")
    assert AuditEvent.objects.get().details is None
    assert parsed(dumped())["audit_events"][0][-1] is None


@pytest.mark.skipif(connection.vendor != "sqlite", reason="PostgreSQL refuses such a value")
def test_a_row_a_restore_would_refuse_stops_the_backup(database):
    with connection.cursor() as cursor:
        cursor.execute("UPDATE users SET failed_login_count = 'many'")
    with pytest.raises(
        BackupError,
        match=f"users {u(3)}: failed_login_count: expected a whole number: a restore would "
        "refuse this row",
    ):
        dumped()
