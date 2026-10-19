"""SQLite and PostgreSQL made alike (yk_portal.core.db; addendum §18.3)."""

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, transaction
from django.db.models import F, TextField
from django.db.models.functions import Cast, Collate

from yk_portal.accounts.models import Group, User
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.audit.service import record
from yk_portal.core.db import CodePoint, recheck_on_conflict, take_turns

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
