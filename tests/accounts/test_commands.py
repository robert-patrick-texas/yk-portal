import re
from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from yk_portal.accounts.models import AccountState, User
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.authentication.passwords import check_web_password

pytestmark = pytest.mark.django_db


def run(*args: str) -> str:
    out = StringIO()
    call_command(*args, stdout=out)
    return out.getvalue()


def temporary_password(output: str) -> str:
    match = re.search(r"^Temporary password: (\S+)$", output, re.MULTILINE)
    assert match
    return match.group(1)


def test_bootstrap_admin(monkeypatch):
    monkeypatch.setattr("getpass.getuser", lambda: "root")
    monkeypatch.setenv("SUDO_USER", "rob")
    output = run("bootstrap-admin", "Alice")
    assert "Created the admin account alice." in output
    assert re.search(r"It expires \d{4}-\d\d-\d\d \d\d:\d\d UTC", output)
    user = User.objects.get()
    assert user.username == "alice"
    assert user.state == AccountState.PROVISIONING
    assert user.is_admin
    assert check_web_password(temporary_password(output), user.temporary_password_hash)
    event = AuditEvent.objects.get()
    assert event.event_type == EventType.ADMIN_BOOTSTRAPPED
    assert event.actor_username_snapshot == "cli:root (sudo by rob)"


def test_bootstrap_admin_prompts_for_the_username(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt: "alice")
    assert "Created the admin account alice." in run("bootstrap-admin")


def test_bootstrap_admin_runs_once():
    run("bootstrap-admin", "alice")
    with pytest.raises(CommandError, match="already exists; use create-admin"):
        run("bootstrap-admin", "bob")


def test_bootstrap_admin_rejects_a_bad_username():
    with pytest.raises(CommandError, match="reserved"):
        run("bootstrap-admin", "svc.admin")


def test_create_admin():
    run("bootstrap-admin", "alice")
    output = run("create-admin", "bob", "--email", "bob@example.com")
    assert "Created the admin account bob." in output
    bob = User.objects.get(username="bob")
    assert bob.is_admin
    assert bob.email == "bob@example.com"
    assert check_web_password(temporary_password(output), bob.temporary_password_hash)


def test_create_admin_rejects_a_taken_username():
    run("bootstrap-admin", "alice")
    with pytest.raises(CommandError, match="taken"):
        run("create-admin", "alice")


def test_reset_admin_resets_to_provisioning(make_user):
    make_user("alice", state=AccountState.LOCKED, admin=True)
    output = run("reset-admin", "ALICE")
    assert "Reset to PROVISIONING the admin account alice." in output
    alice = User.objects.get(username="alice")
    assert alice.state == AccountState.PROVISIONING
    assert check_web_password(temporary_password(output), alice.temporary_password_hash)
    assert AuditEvent.objects.get().event_type == EventType.ACCOUNT_RESET_TO_PROVISIONING


def test_reset_admin_reissues_an_expired_temporary_password():
    first = temporary_password(run("bootstrap-admin", "alice"))
    output = run("reset-admin", "alice")
    assert "Issued a new temporary password to the admin account alice." in output
    second = temporary_password(output)
    alice = User.objects.get()
    assert check_web_password(second, alice.temporary_password_hash)
    assert not check_web_password(first, alice.temporary_password_hash)
    assert AuditEvent.objects.filter(event_type=EventType.TEMPORARY_PASSWORD_SET).exists()


@pytest.mark.parametrize("username", ["bob", "nobody"])
def test_reset_admin_only_resets_admins(make_user, username):
    make_user("bob")
    with pytest.raises(CommandError, match=f"{username} is not an admin account"):
        run("reset-admin", username)
