import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

BEFORE = [("accounts", "0004_user_theme_unset"), ("yubikeys", "0002_private_id_digest")]
AFTER = [("accounts", "0005_pins_on_yubikeys"), ("yubikeys", "0003_pins")]


def migrate(targets):
    """Migrate to TARGETS; the historical models there."""
    executor = MigrationExecutor(connection)
    executor.migrate(targets)
    return executor.loader.project_state(targets).apps


def pins(apps) -> dict[str, set[tuple[str, str]]]:
    keys = apps.get_model("yubikeys", "YubikeyCredential").objects
    found: dict[str, set[tuple[str, str]]] = {}
    for username, web, radius in keys.values_list("user__username", "pin_hash", "radius_pin_hash"):
        found.setdefault(username, set()).add((web, radius))
    return found


@pytest.mark.django_db(transaction=True)
def test_account_passwords_become_their_yubikeys_pins_and_back():
    try:
        apps = migrate(BEFORE)
        users = apps.get_model("accounts", "User").objects
        keys = apps.get_model("yubikeys", "YubikeyCredential").objects
        hashes = {"password_hash": "argon2$a", "radius_password_hash": "{crypt}$6$a"}
        alice = users.create(username="alice", **hashes)
        bob = users.create(username="bob")
        for n, user in enumerate([alice, alice, bob]):
            keys.create(
                user=user,
                public_id=f"vvcccccccc{'bcd'[n]}c",
                encrypted_private_id=b"",
                private_id_digest=str(n),
                encrypted_aes_secret=b"",
                provisioning_method="MIGRATED",
            )

        apps = migrate(AFTER)
        assert pins(apps) == {"alice": {("argon2$a", "{crypt}$6$a")}, "bob": {("", "")}}

        apps = migrate(BEFORE)
        users = apps.get_model("accounts", "User").objects
        assert set(users.values_list("username", "password_hash", "radius_password_hash")) == {
            ("alice", "argon2$a", "{crypt}$6$a"),
            ("bob", "", ""),
        }
    finally:
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())
