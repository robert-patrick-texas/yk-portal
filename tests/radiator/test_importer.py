import io
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import pytest
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.core.management.base import CommandError
from django.urls import reverse

from yk_portal.accounts.groups import create_group
from yk_portal.accounts.models import AccountState, User
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.authentication.passwords import check_web_password
from yk_portal.core import sha512_crypt
from yk_portal.portal_settings import service as portal_settings
from yk_portal.radiator import csvfile
from yk_portal.yubikeys.models import ProvisioningMethod, YubikeyCredential

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("master_key")]

K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"
K2 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
PUB1, PUB2, PUB3 = "vvccccbbcdef", "vvccccbbcdeg", "vvccccbbcdeh"
PRIV1, PRIV2, PRIV3 = "4a6f8e2d1c3b", "4a6f8e2d1c3c", "4a6f8e2d1c3d"
HASH = sha512_crypt.make_hash("Passw0rd")
HASH2 = sha512_crypt.make_hash("Passw0rd")
CREATED = "2025-01-02 03:04:05"
ACCESSED = "2026-10-16 09:00:01"
BOBS_PIN = "Bobs-pin-9"  # noqa: S105 - a test password


def at(text: str) -> datetime:
    return datetime.strptime(text, csvfile.TIME_FORMAT).replace(tzinfo=UTC)


def row(
    username: str = "alice",
    public_id: str = PUB1,
    private_id: str = PRIV1,
    aes_key: str = K1,
    password: str = HASH,
    active: str = "1",
    created: str = CREATED,
    accessed: str = ACCESSED,
    counter: str = "12",
    low: str = "3",
    high: str = "0",
    label: str = "",
) -> list[str]:
    return [
        username,
        public_id,
        private_id,
        aes_key,
        password,
        active,
        created,
        accessed,
        counter,
        low,
        high,
        label,
    ]


def export_file(*rows: list[str], header: str = csvfile.HEADER) -> bytes:
    return (header + "\n" + "".join(csvfile.format_row(r) for r in rows)).encode()


class Importer:
    """Runs radiator-import on a file of rows, and keeps its output lines, also when it fails."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.output: list[str] = []

    def __call__(
        self, *rows: list[str], args: tuple[str, ...] = (), data: bytes | None = None
    ) -> list[str]:
        self.path.write_bytes(export_file(*rows) if data is None else data)
        out = StringIO()
        try:
            call_command("radiator-import", *args, str(self.path), stdout=out)
        finally:
            self.output = out.getvalue().splitlines()
        return self.output


@pytest.fixture
def run(tmp_path) -> Importer:
    return Importer(tmp_path / "radiator.csv")


def key(public_id: str = PUB1) -> YubikeyCredential:
    return YubikeyCredential.objects.select_related("user").get(public_id=public_id)


def events(event_type: EventType) -> list[AuditEvent]:
    return list(AuditEvent.objects.filter(event_type=event_type).order_by("timestamp"))


# Full import


def test_full_import_creates_accounts_and_adds_keys(run, actor):
    netops = create_group("netops", actor)
    portal_settings.update({"default_group": netops.pk}, actor)
    AuditEvent.objects.all().delete()
    output = run(
        row(label="primary, slot 2"),
        row(public_id=PUB2, private_id=PRIV2, aes_key=K2, password="", active="0", accessed=""),
        row("bob", PUB3, PRIV3, password=BOBS_PIN, label="Slot 1"),
    )
    assert output == [
        f"line 2: alice {PUB1}: added, new account",
        f"line 3: alice {PUB2}: added, disabled",
        f"line 4: bob {PUB3}: added, new account",
        "3 rows: 2 accounts created, 3 added.",
    ]
    alice = User.objects.get(username="alice")
    assert alice.state == AccountState.ACTIVE
    assert set(alice.roles.values_list("name", flat=True)) == {"user"}
    assert list(alice.groups.all()) == [netops]
    assert (alice.email, alice.temporary_password_hash) == ("", "")

    first = key(PUB1)
    assert first.user == alice
    assert (first.private_id().hex(), first.aes_key().hex()) == (PRIV1, K1)
    assert first.provisioning_method == ProvisioningMethod.MIGRATED
    assert first.migration_source == "radiator-yubikey export"
    assert first.enabled
    assert (first.last_usage_counter, first.last_session_counter) == (12, 3)
    assert (first.created_at, first.last_used_at) == (at(CREATED), at(ACCESSED))
    assert (first.label, first.slot_number) == ("primary, slot 2", 2)
    assert (first.pin_hash, first.radius_pin_hash) == ("", HASH)
    second = key(PUB2)
    assert not second.enabled
    assert (second.last_used_at, second.slot_number) == (None, None)
    assert not second.has_pin
    third = key(PUB3)
    assert third.slot_number == 1
    assert check_web_password(BOBS_PIN, third.pin_hash)
    assert sha512_crypt.check_hash(BOBS_PIN, third.radius_pin_hash)

    assert [e.target_username_snapshot for e in events(EventType.ACCOUNT_CREATED)] == [
        "alice",
        "bob",
    ]
    added = events(EventType.YUBIKEY_ADDED)
    assert [e.details["public_id"] for e in added] == [PUB1, PUB2, PUB3]
    assert added[1].details["enabled"] is False
    details = AuditEvent.objects.get(event_type=EventType.RADIATOR_IMPORT_COMPLETED).details
    assert details == {
        "mode": "full",
        "source": str(run.path),
        "rows": 3,
        "accounts_created": 2,
        "yubikeys_added": 3,
        "moved_forward": 0,
        "unchanged": 0,
        "skipped": 0,
        "invalid": 0,
    }
    secrets = (PRIV1, PRIV2, PRIV3, K1, K2, BOBS_PIN, HASH)
    assert not any(s in str(e.details) for e in AuditEvent.objects.all() for s in secrets)
    assert not any(s in "\n".join(output) for s in secrets)


@pytest.mark.parametrize(
    ("password", "web", "radius"),
    [
        (HASH, "", HASH),
        ("", "", ""),
        ("{clear}", "", ""),
        ("Passw0rd", "Passw0rd", "Passw0rd"),
        ("{clear}{not-a-scheme}1", "{not-a-scheme}1", "{not-a-scheme}1"),
        ("1234", "1234", "1234"),
    ],
)
def test_password_column_becomes_the_keys_pin(run, password, web, radius):
    run(row(password=password))
    stored = key()
    if web:
        assert check_web_password(web, stored.pin_hash)
    else:
        assert stored.pin_hash == ""
    if radius == HASH:
        assert stored.radius_pin_hash == HASH
    elif radius:
        assert sha512_crypt.check_hash(radius, stored.radius_pin_hash)
    else:
        assert stored.radius_pin_hash == ""


@pytest.mark.parametrize(
    ("password", "reason"),
    [
        ("{SSHA}abcdef", "password hash format"),
        ("{crypt}$1$abc$def", "password hash not SHA-512"),
        ("{crypt}$6$short", "password hash not SHA-512"),
        ("$6$abcdefgh$" + "x" * 86, "password hash format"),
        ("$2a$10$abc", "password hash format"),
        ("pass\tw0rd", "password has a control character"),
    ],
)
def test_unusable_passwords(run, password, reason):
    with pytest.raises(CommandError, match="nothing imported: 1 invalid row"):
        run(row(password=password))
    assert run.output[0] == f"line 2: alice {PUB1}: invalid: {reason}"
    assert password not in "\n".join(run.output)
    assert not User.objects.exists()


def test_each_key_keeps_its_own_pin(run):
    run(row(), row(public_id=PUB2, private_id=PRIV2, password=HASH2))
    assert (key(PUB1).radius_pin_hash, key(PUB2).radius_pin_hash) == (HASH, HASH2)


def test_keys_are_added_to_existing_accounts(run, make_user, make_credential):
    alice = make_user("alice", state=AccountState.LOCKED, email="alice@example.com")
    own = make_credential(alice, public_id=PUB2, private_id=PRIV2)
    output = run(row())
    assert output[0] == f"line 2: alice {PUB1}: added"
    alice.refresh_from_db()
    assert (alice.state, alice.email) == (AccountState.LOCKED, "alice@example.com")
    assert key().user == alice
    assert key().radius_pin_hash == HASH
    assert key(PUB2).radius_pin_hash == own.radius_pin_hash
    assert not events(EventType.ACCOUNT_CREATED)


def test_an_imported_key_with_only_a_radius_hash_can_sign_in(run, client, make_otp):
    run(row(password=sha512_crypt.make_hash("Passw0rd!")))
    response = client.post(
        reverse("login"),
        {"username": "alice", "passcode": "Passw0rd!" + make_otp(PUB1, PRIV1, K1, 12, 4)},
    )
    assert response.headers["Location"] == reverse("home")
    assert check_web_password("Passw0rd!", key().pin_hash)


# Invalid rows


@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        (row()[:11], "11 fields, expected 12"),
        ([*row(), "extra"], "13 fields, expected 12"),
        (row("Alice"), "username"),
        (row(""), "username"),
        (row("svc.backup"), "reserved username"),
        (row("anycast-check1"), "reserved username"),
        (row(public_id="vvccccbb"), "public ID not 12 characters"),
        (row(public_id="vvccccbbcdea"), "public ID"),
        (row(private_id="4a6f8e2d1c3"), "private ID"),
        (row(private_id="4a6f8e2d1c3g"), "private ID"),
        (row(aes_key=K1[:-1]), "AES key"),
        (row(active="maybe"), "active 'maybe'"),
        (row(counter="-1"), "counter, low or high"),
        (row(high=""), "counter, low or high"),
        (row(counter="32768"), "counter or low out of range"),
        (row(low="256"), "counter or low out of range"),
        (row(label="a\tb"), "label"),
        (row(label="x" * 256), "label"),
    ],
)
def test_invalid_rows(run, fields, reason):
    with pytest.raises(CommandError, match="nothing imported: 1 invalid row \\(or use --skip"):
        run(fields)
    assert run.output[0].startswith("line 2: ")
    assert run.output[0].endswith(f": invalid: {reason}")
    assert not User.objects.exists()
    assert not AuditEvent.objects.exists()


def test_a_row_that_is_not_utf_8(run):
    data = export_file(row()).replace(b"alice", b"al\xffce")
    with pytest.raises(CommandError):
        run(data=data)
    assert run.output[0] == f"line 2: al�ce {PUB1}: invalid: not UTF-8"


def test_skip_invalid_imports_the_valid_rows(run):
    output = run(
        row("Alice"),
        row("bob", PUB2, PRIV2),
        row("anycast-x", PUB3, PRIV3),
        row("svc.backup", "vvccccbbcdei", "4a6f8e2d1c3e"),
        args=("--skip-invalid",),
    )
    assert output == [
        f"line 2: Alice {PUB1}: invalid: username",
        f"line 3: bob {PUB2}: added, new account",
        f"line 4: anycast-x {PUB3}: skipped: reserved username",
        "line 5: svc.backup vvccccbbcdei: skipped: reserved username",
        "4 rows: 1 account created, 1 added, 2 skipped, 1 invalid.",
    ]
    assert list(User.objects.values_list("username", flat=True)) == ["bob"]


def test_rows_for_reserved_usernames_are_skipped_without_error(run):
    output = run(row("anycast-x"), row("bob", PUB2, PRIV2), args=("--skip-invalid",))
    assert output[-1] == "2 rows: 1 account created, 1 added, 1 skipped."
    assert list(User.objects.values_list("username", flat=True)) == ["bob"]


@pytest.mark.parametrize(
    ("private_id", "aes_key"),
    [
        ("4A:6F:8E:2D:1C:3B", K1.upper()),
        ("flhvjudtbren", " ".join(K1[i : i + 4] for i in range(0, 32, 4))),
    ],
)
def test_key_values_are_read_as_yubikey_db_sh_reads_them(run, private_id, aes_key):
    run(row(public_id=PUB1.upper(), private_id=private_id, aes_key=aes_key))
    assert (key().private_id().hex(), key().aes_key().hex()) == (PRIV1, K1)


@pytest.mark.parametrize(
    ("active", "enabled"), [("", True), ("TRUE", True), ("yes", True), ("off", False), ("N", False)]
)
def test_active_values(run, active, enabled):
    run(row(active=active))
    assert key().enabled is enabled


def test_times_that_are_not_utc_times(run):
    output = run(row(created="yesterday", accessed="2026-02-30 00:00:00"))
    assert output[0] == (
        f"line 2: alice {PUB1}: added, new account; bad created time, now used; "
        "bad accessed time, ignored"
    )
    assert key().created_at.year >= 2026
    assert key().last_used_at is None


def test_an_export_from_before_radiator_yubikey_1_8_0(run):
    old = export_file(row(label="")[:11], header=csvfile.OLD_HEADER)
    run(data=old)
    assert key().label == ""


def test_conflicts_with_yk_portal(run, make_user, make_credential):
    bob = make_user("bob")
    make_credential(bob, public_id=PUB1, private_id=PRIV1, aes_key=K1)
    make_credential(make_user("alice"), public_id=PUB2, private_id=PRIV2, aes_key=K1)
    with pytest.raises(CommandError):
        run(
            row(),  # bob's YubiKey
            row(public_id=PUB2, private_id=PRIV3),  # another private ID
            row(public_id=PUB3, private_id=PRIV2),  # another YubiKey's private ID
        )
    assert run.output[:3] == [
        f"line 2: alice {PUB1}: invalid: key belongs to bob",
        f"line 3: alice {PUB2}: invalid: key values differ",
        f"line 4: alice {PUB3}: invalid: private ID used by {PUB2}",
    ]


def test_the_same_key_twice_in_the_file(run):
    with pytest.raises(CommandError):
        run(row(), row("bob"), row("carol", PUB2))
    assert run.output[1:3] == [
        f"line 3: bob {PUB1}: invalid: public ID also on line 2",
        f"line 4: carol {PUB2}: invalid: private ID also on line 2",
    ]


def test_the_maximum_yubikeys_per_user(run, actor, make_user, make_credential):
    portal_settings.update({"max_yubikeys_per_user": 2}, actor)
    make_credential(make_user("alice"))
    with pytest.raises(CommandError):
        run(row(), row(public_id=PUB2, private_id=PRIV2), row("bob", PUB3, PRIV3))
    assert run.output[1] == f"line 3: alice {PUB2}: invalid: over 2 YubiKeys"
    assert run.output[2] == f"line 4: bob {PUB3}: added, new account"


def test_a_key_yk_portal_has_only_moves_forward(run, make_user, make_credential):
    alice = make_user("alice")
    make_credential(
        alice,
        public_id=PUB1,
        private_id=PRIV1,
        aes_key=K1,
        label="mine",
        enabled=True,
        last_usage_counter=10,
        last_session_counter=7,
    )
    output = run(row(active="0", label="theirs", password=HASH2, counter="12", low="3"))
    assert output == [
        f"line 2: alice {PUB1}: counters 10/7 -> 12/3, last use {ACCESSED}",
        "1 row: 1 moved forward.",
    ]
    stored = key()
    assert (stored.label, stored.enabled) == ("mine", True)
    assert (stored.last_usage_counter, stored.last_session_counter) == (12, 3)
    assert stored.last_used_at == at(ACCESSED)
    assert stored.provisioning_method == ProvisioningMethod.ADMIN_PROVISIONED
    assert stored.radius_pin_hash != HASH2
    # Moving counters is routine: no audit event (addendum §7.1).
    assert not AuditEvent.objects.exists()


def test_a_full_import_again_changes_nothing(run):
    run(row())
    output = run(row())
    assert output[0] == f"line 2: alice {PUB1}: unchanged"
    # Only the first import is recorded: one that changes nothing isn't (addendum §7.1).
    assert len(events(EventType.RADIATOR_IMPORT_COMPLETED)) == 1


def test_an_import_of_only_invalid_rows_records_nothing(run):
    run(row("Alice"), args=("--skip-invalid",))
    assert not AuditEvent.objects.exists()


def test_dry_run_changes_nothing(run):
    output = run(row(), args=("--dry-run",))
    assert output == [
        f"line 2: alice {PUB1}: added, new account",
        "1 row: 1 account created, 1 added.",
        "Dry run: nothing changed.",
    ]
    assert not User.objects.exists()
    assert not AuditEvent.objects.exists()


def test_a_dry_run_with_invalid_rows_fails_too(run):
    with pytest.raises(CommandError, match="nothing imported"):
        run(row("Alice"), args=("--dry-run",))


def test_a_change_while_importing_rolls_everything_back(run, monkeypatch):
    def refuse(*args, **kwargs):
        raise ValidationError("A YubiKey with this public ID is registered already.")

    monkeypatch.setattr("yk_portal.radiator.importer.add_yubikey", refuse)
    with pytest.raises(CommandError, match="yk-portal changed during the import \\(A YubiKey"):
        run(row())
    assert not User.objects.exists()
    assert not AuditEvent.objects.exists()


# Counter sync (addendum §7.5)


@pytest.fixture
def alices_key(make_user, make_credential):
    return make_credential(
        make_user("alice"),
        public_id=PUB1,
        private_id=PRIV1,
        aes_key=K1,
        last_usage_counter=10,
        last_session_counter=7,
        last_used_at=at("2026-05-01 00:00:00"),
    )


@pytest.mark.parametrize(
    ("counter", "low", "accessed", "expected", "text"),
    [
        ("12", "3", ACCESSED, (12, 3, ACCESSED), f"counters 10/7 -> 12/3, last use {ACCESSED}"),
        ("10", "8", "", (10, 8, "2026-05-01 00:00:00"), "counters 10/7 -> 10/8"),
        ("10", "7", ACCESSED, (10, 7, ACCESSED), f"last use {ACCESSED}"),
        ("10", "7", "2026-04-01 00:00:00", (10, 7, "2026-05-01 00:00:00"), "unchanged"),
        ("10", "6", "", (10, 7, "2026-05-01 00:00:00"), "unchanged"),
        ("9", "200", "", (10, 7, "2026-05-01 00:00:00"), "unchanged"),
    ],
)
def test_counter_sync(run, alices_key, counter, low, accessed, expected, text):
    output = run(row(counter=counter, low=low, accessed=accessed), args=("--counters-only",))
    assert output[0] == f"line 2: alice {PUB1}: {text}"
    stored = key()
    assert (stored.last_usage_counter, stored.last_session_counter) == expected[:2]
    assert stored.last_used_at == at(expected[2])
    assert not AuditEvent.objects.exists()  # routine (addendum §7.1)


def test_counter_sync_skips_what_yk_portal_does_not_have(run, alices_key):
    output = run(
        row("anycast-check", PUB2, PRIV2, K1, "{SSHA}x", active="?", label="\t"),
        row(aes_key=K2),
        row("Bob", PUB3, PRIV3, created="?"),
        args=("--counters-only",),
    )
    assert output == [
        f"line 2: anycast-check {PUB2}: skipped: unknown key",
        f"line 3: alice {PUB1}: skipped: key values differ",
        f"line 4: Bob {PUB3}: skipped: unknown key",
        "3 rows: 3 skipped.",
    ]
    assert (key().last_usage_counter, key().last_session_counter) == (10, 7)
    assert not AuditEvent.objects.exists()


def test_counter_sync_follows_the_key_under_any_username(run, alices_key):
    output = run(row("bob", counter="11"), args=("--counters-only",))
    assert output[0] == (
        f"line 2: bob {PUB1}: counters 10/7 -> 11/3, last use {ACCESSED} (yk-portal user alice)"
    )
    assert key().last_usage_counter == 11


def test_counter_sync_rejects_malformed_key_fields(run, alices_key):
    with pytest.raises(CommandError, match="nothing imported"):
        run(row(counter="x"), args=("--counters-only",))


def test_counter_sync_from_standard_input(alices_key, monkeypatch):
    stdin = io.TextIOWrapper(io.BytesIO(export_file(row(counter="11"))))
    monkeypatch.setattr("sys.stdin", stdin)
    out = StringIO()
    call_command("radiator-import", "--counters-only", "-", stdout=out)
    assert f"line 2: alice {PUB1}: counters 10/7 -> 11/3" in out.getvalue()


def test_a_full_import_from_standard_input(monkeypatch):
    stdin = io.TextIOWrapper(io.BytesIO(export_file(row())))
    monkeypatch.setattr("sys.stdin", stdin)
    call_command("radiator-import", "-", stdout=StringIO())
    completed = AuditEvent.objects.get(event_type=EventType.RADIATOR_IMPORT_COMPLETED)
    assert completed.details["source"] == "standard input"


def test_an_export_imports_back_unchanged(run, make_user, make_credential):
    alice = make_user("alice")
    make_credential(alice, label="spare, slot 2", last_usage_counter=4, radius_pin_hash=HASH)
    bob = make_user("bob", state=AccountState.LOCKED)
    make_credential(bob, enabled=False, radius_pin_hash=HASH2)
    out = StringIO()
    call_command("radiator-export", "-", stdout=out, stderr=StringIO())
    output = run(data=out.getvalue().encode())
    assert [line.rpartition(": ")[2] for line in output[:2]] == ["unchanged", "unchanged"]


# Not an export file


@pytest.mark.parametrize(
    ("data", "message"),
    [(b"", "the file is empty"), (b"username,public_id\n", "not an export file")],
)
def test_a_file_that_is_not_an_export(run, data, message):
    with pytest.raises(CommandError, match=message):
        run(data=data)


def test_a_file_that_cannot_be_read(tmp_path):
    with pytest.raises(CommandError, match="cannot read .*: No such file"):
        call_command("radiator-import", str(tmp_path / "missing.csv"))
