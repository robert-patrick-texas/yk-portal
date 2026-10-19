"""SQLite and PostgreSQL made alike (yk_portal.core.db; addendum §18.3)."""

import threading
import time
from collections.abc import Callable

import pytest
from django.core.exceptions import ValidationError
from django.db import (
    IntegrityError,
    InternalError,
    OperationalError,
    connection,
    connections,
    transaction,
)
from django.db.models import F, TextField
from django.db.models.functions import Cast, Collate
from django.db.transaction import TransactionManagementError

from yk_portal.accounts.models import Group, Role, User
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.audit.service import record
from yk_portal.core.db import (
    Busy,
    CodePoint,
    exclude_writers,
    recheck_on_conflict,
    short_message,
    snapshot,
    take_turns,
)

pytestmark = pytest.mark.django_db

# Orders that differ between code points and a language's collation.
USERNAMES = ["ab", "a.c", "a-b", "a_d", "b@a", "b+c"]
GROUP_NAMES = ["Zeta", "alpha", "Beta", "b-c"]


def found(**lookup: str) -> list[str]:
    return sorted(User.objects.filter(**lookup).values_list("username", flat=True))


@pytest.mark.parametrize("text", ["émile", "ÉMILE", "Émile", "øster", "ØSTER", "le ø"])
def test_icontains_ignores_the_case_of_every_letter(make_user, text):
    make_user("emile", display_name="Émile Øster")
    make_user("emil", display_name="Emil Oster")
    assert found(display_name__icontains=text) == ["emile"]


def test_icontains_matches_wildcards_as_they_are(make_user):
    make_user("a", display_name="100% a_b \\")
    make_user("b", display_name="1000 axb")
    assert found(display_name__icontains="100%") == ["a"]
    assert found(display_name__icontains="A_B") == ["a"]
    assert found(display_name__icontains="\\") == ["a"]
    assert found(display_name__icontains="%") == ["a"]


def test_icontains_on_an_expression(actor):
    record(EventType.YUBIKEY_UPDATED, actor, details={"new_label": "Clé de secours"})
    events = AuditEvent.objects.annotate(text=Cast("details", TextField()))
    assert events.filter(text__icontains="CLÉ").count() == 1


def test_json_keeps_letters_as_they_are(actor):
    """Not as \\u escapes, which SQLite would store and its search wouldn't find."""
    record(EventType.SETTING_CHANGED, actor, details={"new": "Portail d’accès"})
    events = AuditEvent.objects.annotate(text=Cast("details", TextField()))
    text = events.values_list("text", flat=True).get()
    assert "Portail d’accès" in text


def test_code_point_order(make_user):
    for username in USERNAMES:
        make_user(username)
    for name in GROUP_NAMES:
        Group.objects.create(name=name)
    users = User.objects.order_by(CodePoint("username")).values_list("username", flat=True)
    groups = Group.objects.order_by(CodePoint("name")).values_list("name", flat=True)
    assert (list(users), list(groups)) == (sorted(USERNAMES), sorted(GROUP_NAMES))


@pytest.mark.skipif(connection.vendor != "postgresql", reason="PostgreSQL's collations")
def test_code_point_order_whatever_the_databases_collation():
    """As on a database created with a language's collation, such as en_US.UTF-8."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_collation WHERE collname = 'und-x-icu'")
        if cursor.fetchone() is None:
            pytest.skip("PostgreSQL without ICU")
    for name in GROUP_NAMES:
        Group.objects.create(name=name)
    linguistic = Collate(F("name"), "und-x-icu")
    names = Group.objects.values_list("name", flat=True)
    assert list(names.order_by(linguistic)) != sorted(GROUP_NAMES)
    assert list(names.order_by(CodePoint(linguistic))) == sorted(GROUP_NAMES)


def name_free(name: str) -> None:
    if Group.objects.filter(name__iexact=name).exists():
        raise ValidationError("A group with that name exists.", code="group_name_taken")


def test_a_conflict_raises_the_checks_error():
    """As when another transaction took the name after this one checked it."""
    Group.objects.create(name="noc")
    with pytest.raises(ValidationError) as excinfo, transaction.atomic():
        with recheck_on_conflict(lambda: name_free("NOC")):
            Group.objects.create(name="NOC")
    assert excinfo.value.code == "group_name_taken"


def test_a_conflict_the_check_doesnt_explain_stays_an_integrity_error():
    Group.objects.create(name="noc")
    with pytest.raises(IntegrityError), transaction.atomic():
        with recheck_on_conflict(lambda: name_free("other")):
            Group.objects.create(name="NOC")


def test_the_transaction_goes_on_after_a_conflict():
    """The savepoint keeps PostgreSQL's transaction usable, as SQLite's always is."""
    Group.objects.create(name="noc")
    with transaction.atomic():
        with pytest.raises(ValidationError), recheck_on_conflict(lambda: name_free("NOC")):
            Group.objects.create(name="NOC")
        Group.objects.create(name="ops")
    assert Group.objects.count() == 2


def test_take_turns_in_a_transaction():
    with transaction.atomic():
        take_turns("settings")
        take_turns("settings")  # the same transaction may take it again


def in_another_thread(call: Callable[[], object]) -> threading.Thread:
    """Start CALL in a thread with its own database connection."""

    def run() -> None:
        try:
            call()
        finally:
            connections.close_all()

    thread = threading.Thread(target=run)
    thread.start()
    return thread


def usernames() -> list[str]:
    return sorted(User.objects.values_list("username", flat=True))


@pytest.mark.django_db(transaction=True)
def test_a_snapshot_reads_one_moment_and_lets_others_write(make_user):
    """A backup reads every table as of one moment, while logins go on (spec §28)."""
    make_user("before")
    with snapshot():
        assert usernames() == ["before"]  # its moment: the first read
        writer = in_another_thread(lambda: User.objects.create(username="during"))
        writer.join(timeout=10)
        assert not writer.is_alive()  # it didn't wait for the snapshot
        assert usernames() == ["before"]
        if connection.vendor == "postgresql":
            with pytest.raises(InternalError, match="read-only"), transaction.atomic():
                User.objects.create(username="inside")
        else:
            with pytest.raises(OperationalError, match="readonly"):
                User.objects.create(username="inside")
    assert usernames() == ["before", "during"]
    User.objects.create(username="after")  # writable again


def test_a_snapshot_cant_start_inside_a_transaction():
    with pytest.raises(TransactionManagementError), snapshot():
        pass


@pytest.mark.django_db(transaction=True)
def test_exclude_writers_makes_writers_wait_and_lets_readers_read(make_user):
    """A restore's tables change all at once for everyone else (addendum §19)."""
    make_user("alice")
    seen: list[list[str]] = []
    with transaction.atomic():
        exclude_writers(User)
        User.objects.update(display_name="restoring")
        writer = in_another_thread(lambda: User.objects.update(display_name="other"))
        reader = in_another_thread(lambda: seen.append(usernames()))
        reader.join(timeout=10)
        writer.join(timeout=0.5)
        assert seen == [["alice"]] and writer.is_alive()
    writer.join(timeout=10)
    assert not writer.is_alive()
    assert User.objects.get().display_name == "other"


postgresql_only = pytest.mark.skipif(
    connection.vendor != "postgresql", reason="SQLite's writers already take turns"
)


@postgresql_only
@pytest.mark.django_db(transaction=True)
def test_exclude_writers_never_deadlocks_with_a_request(make_user):
    """A request that locks an account, then the admin role (as removing an admin
    does), while a restore locks the tables: before, PostgreSQL detected a deadlock
    and aborted one of them."""
    user = make_user("alice")
    Role.objects.get_or_create(name=Role.ADMIN)
    locked = threading.Event()
    done: list[str] = []

    def request() -> None:
        with transaction.atomic():
            User.objects.select_for_update().get(pk=user.pk)
            locked.set()
            time.sleep(0.3)
            Role.objects.select_for_update().get(name=Role.ADMIN)
        done.append("request")

    thread = in_another_thread(request)
    locked.wait(timeout=10)
    with transaction.atomic():
        exclude_writers(Role, User)  # the request's order reversed
        done.append("restore")
    thread.join(timeout=10)
    assert done == ["request", "restore"]


@postgresql_only
@pytest.mark.django_db(transaction=True)
def test_exclude_writers_gives_up_when_the_tables_stay_busy(make_user):
    user = make_user("alice")
    locked, release = threading.Event(), threading.Event()

    def request() -> None:
        with transaction.atomic():
            User.objects.select_for_update().get(pk=user.pk)
            locked.set()
            release.wait(timeout=10)

    thread = in_another_thread(request)
    locked.wait(timeout=10)
    try:
        with pytest.raises(Busy, match="kept the tables busy for 0.3 seconds"):
            with transaction.atomic():
                exclude_writers(User, patience=0.3)
    finally:
        release.set()
        thread.join(timeout=10)


def test_short_message_leaves_out_the_row(make_user):
    make_user("alice", email="alice@example.com")
    with pytest.raises(IntegrityError) as excinfo, transaction.atomic():
        User.objects.create(username="alice", email="secret@example.com")
    message = short_message(excinfo.value)
    assert "unique" in message.lower()
    if connection.vendor == "postgresql":  # whose DETAIL quotes the row
        assert "Key (username)=(alice)" in str(excinfo.value)
    assert "(alice)" not in message and "DETAIL" not in message and "\n" not in message
