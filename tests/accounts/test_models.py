import uuid

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import ProtectedError

from yk_portal.accounts.models import AccountState, Role, Theme, User, UserRole
from yk_portal.accounts.validators import validate_username

pytestmark = pytest.mark.django_db


def test_new_user_defaults():
    user = User.objects.create(username="alice")
    assert isinstance(user.id, uuid.UUID)
    assert user.state == AccountState.PROVISIONING
    assert user.failed_login_count == 0
    assert user.theme == Theme.BROWSER
    assert user.password_hash == user.radius_password_hash == user.temporary_password_hash == ""
    assert user.temporary_password_expires_at is None
    assert user.last_login_at is None
    assert user.created_at is not None


def test_roles_are_seeded():
    assert set(Role.objects.values_list("name", flat=True)) == {Role.USER, Role.ADMIN}


@pytest.mark.parametrize(
    "fields",
    [
        {"username": "Alice"},
        {"username": "bob", "state": "DELETED"},
        {"username": "carol", "theme": "sepia"},
        {"username": "dave", "failed_login_count": -1},
    ],
    ids=["lowercase", "state", "theme", "failed_login_count"],
)
def test_database_constraints(fields):
    with pytest.raises(IntegrityError), transaction.atomic():
        User.objects.create(**fields)


def test_usernames_are_unique():
    User.objects.create(username="alice")
    with pytest.raises(IntegrityError), transaction.atomic():
        User.objects.create(username="alice")


def test_a_role_is_given_once():
    user = User.objects.create(username="alice")
    admin = Role.objects.get(name=Role.ADMIN)
    UserRole.objects.create(user=user, role=admin)
    with pytest.raises(IntegrityError), transaction.atomic():
        UserRole.objects.create(user=user, role=admin)


def test_roles_through_the_user():
    user = User.objects.create(username="alice")
    user.roles.add(*Role.objects.all())
    assert set(user.roles.values_list("name", flat=True)) == {"user", "admin"}


def test_deleting_a_user_removes_its_roles_but_a_role_in_use_is_protected():
    user = User.objects.create(username="alice")
    role = Role.objects.get(name=Role.USER)
    UserRole.objects.create(user=user, role=role)
    with pytest.raises(ProtectedError):
        role.delete()
    user.delete()
    assert not UserRole.objects.exists()


@pytest.mark.parametrize(
    "username", ["alice", "a", "alice.smith", "a_b-c+d@example.com", "0123", "x" * 255]
)
def test_valid_usernames(username):
    validate_username(username)


@pytest.mark.parametrize(
    ("username", "code"),
    [
        ("", "invalid_username"),
        ("Alice", "invalid_username"),
        ("alice smith", "invalid_username"),
        ("alice:1", "invalid_username"),
        ("ålice", "invalid_username"),
        ("x" * 256, "invalid_username"),
        ("svc.backup", "reserved_username"),
        ("anycast-west1", "reserved_username"),
    ],
)
def test_invalid_usernames(username, code):
    with pytest.raises(ValidationError) as excinfo:
        validate_username(username)
    assert excinfo.value.code == code


def test_full_clean_applies_the_username_rule():
    with pytest.raises(ValidationError, match="reserved"):
        User(username="svc.backup").full_clean()
