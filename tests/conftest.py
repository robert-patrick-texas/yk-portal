import itertools

import pytest

from yk_portal.accounts.models import AccountState, Role, User
from yk_portal.audit.service import Actor
from yk_portal.core.master_key import create_master_key

_numbers = itertools.count(1)


@pytest.fixture
def actor() -> Actor:
    return Actor.cli()


@pytest.fixture(scope="session")
def master_key_path(tmp_path_factory) -> str:
    path = tmp_path_factory.mktemp("master-key") / "master.key"
    create_master_key(path)
    return str(path)


@pytest.fixture
def master_key(master_key_path, settings) -> str:
    """A master key for the test, for stored YubiKey secrets."""
    settings.YK_MASTER_KEY_PATH = master_key_path
    return master_key_path


@pytest.fixture
def make_user(db):
    """Make an account directly, without the services: fast, and without audit events.

    It has both password hashes (dummies) unless they are given.
    """

    def make(
        username: str = "",
        state: AccountState = AccountState.ACTIVE,
        admin: bool = False,
        **fields: object,
    ) -> User:
        fields.setdefault("password_hash", "argon2$dummy")
        fields.setdefault("radius_password_hash", "{crypt}$6$dummy")
        user = User.objects.create(
            username=username or f"user{next(_numbers)}", state=state, **fields
        )
        user.roles.add(*Role.objects.filter(name__in=[Role.USER, Role.ADMIN][: 1 + admin]))
        return user

    return make
