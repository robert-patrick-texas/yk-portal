from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone

from yk_portal.accounts import services
from yk_portal.accounts.groups import create_group
from yk_portal.accounts.models import AccountState, User
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.audit.service import Actor
from yk_portal.authentication.passwords import check_web_password
from yk_portal.portal_settings import service as portal_settings
from yk_portal.yubikeys.models import YubikeyCredential

pytestmark = pytest.mark.django_db

P, A, L, D = (
    AccountState.PROVISIONING,
    AccountState.ACTIVE,
    AccountState.LOCKED,
    AccountState.DISABLED,
)


def roles(user: User) -> set[str]:
    return set(user.roles.values_list("name", flat=True))


def events() -> list[str]:
    return list(AuditEvent.objects.order_by("timestamp").values_list("event_type", flat=True))


def raises(code: str):
    """pytest.raises for a ValidationError with CODE."""

    class Check:
        def __enter__(self):
            self.cm = pytest.raises(ValidationError)
            self.excinfo = self.cm.__enter__()
            return self.excinfo

        def __exit__(self, *exc):
            suppressed = self.cm.__exit__(*exc)
            assert self.excinfo.value.error_list[0].code == code
            return suppressed

    return Check()


# Creating accounts


def test_create_user(actor):
    before = timezone.now()
    account = services.create_user("  Alice ", actor, email="alice@example.com")
    user = User.objects.get(pk=account.user.pk)
    assert user.username == "alice"
    assert user.email == "alice@example.com"
    assert user.state == P
    assert user.failed_login_count == 0
    assert roles(user) == {"user"}
    assert check_web_password(account.temporary_password, user.temporary_password_hash)
    assert user.temporary_password_expires_at is not None
    expected = before + timedelta(hours=72)
    assert expected <= user.temporary_password_expires_at <= expected + timedelta(minutes=1)
    assert account.temporary_password not in repr(account)


def test_create_user_audit_event_holds_no_secret_or_email(actor):
    account = services.create_user("alice", actor, email="alice@example.com", admin=True)
    event = AuditEvent.objects.get()
    assert event.event_type == EventType.ACCOUNT_CREATED
    assert event.actor_username_snapshot == actor.name
    assert event.target_user_id == account.user.pk
    assert event.target_username_snapshot == "alice"
    assert event.details == {"roles": ["user", "admin"], "groups": []}
    assert "alice@example.com" not in str(event.details)
    assert account.temporary_password not in str(event.details)


def test_temporary_password_lifetime_follows_the_setting(actor):
    portal_settings.update({"temp_password_hours": 1}, actor)
    user = services.create_user("alice", actor).user
    assert user.temporary_password_expires_at is not None
    assert user.temporary_password_expires_at <= timezone.now() + timedelta(hours=1)


def test_create_admin(actor):
    user = services.create_user("alice", actor, admin=True).user
    assert roles(user) == {"user", "admin"}
    assert user.is_admin


@pytest.mark.parametrize(
    ("username", "code"),
    [
        ("alice smith", "invalid_username"),
        ("", "invalid_username"),
        ("svc.backup", "reserved_username"),
        ("Anycast-West", "reserved_username"),
    ],
)
def test_create_user_checks_the_username(actor, username, code):
    with raises(code):
        services.create_user(username, actor)
    assert not User.objects.exists()
    assert not AuditEvent.objects.exists()


def test_usernames_are_taken_regardless_of_case(actor):
    services.create_user("alice", actor)
    with raises("username_taken"):
        services.create_user("ALICE", actor)


def test_create_user_checks_the_email(actor):
    with raises("invalid"):
        services.create_user("alice", actor, email="not-an-address")


def test_new_users_get_the_default_group(actor):
    netops = create_group("netops", actor)
    portal_settings.update({"default_group": netops.pk}, actor)
    user = services.create_user("alice", actor).user
    assert list(user.groups.all()) == [netops]
    assert AuditEvent.objects.get(event_type=EventType.ACCOUNT_CREATED).details["groups"] == [
        "netops"
    ]


def test_groups_given_replace_the_default(actor):
    netops = create_group("netops", actor)
    noc = create_group("noc", actor)
    portal_settings.update({"default_group": netops.pk}, actor)
    assert list(services.create_user("alice", actor, groups=[noc]).user.groups.all()) == [noc]
    assert not services.create_user("bob", actor, groups=[]).user.groups.exists()


def test_bootstrap_admin(actor, make_user):
    make_user("bob")  # an ordinary account doesn't stop the bootstrap
    account = services.bootstrap_admin("Root.Admin", actor)
    assert account.user.username == "root.admin"
    assert account.user.state == P
    assert roles(account.user) == {"user", "admin"}
    assert events() == [EventType.ADMIN_BOOTSTRAPPED]


@pytest.mark.parametrize("state", [P, A, L, D])
def test_bootstrap_admin_only_while_there_is_no_admin(actor, make_user, state):
    make_user("first", state=state, admin=True)
    with raises("admin_exists"):
        services.bootstrap_admin("second", actor)


# State transitions (spec §7.1)

ALLOWED = {
    services.disable: {P, A, L},
    services.enable: {D},
    services.lock: {P, A},
    services.unlock: {L},
    services.reset_to_provisioning: {A, L, D},
    services.set_temporary_password: {P},
}


@pytest.mark.parametrize("change", ALLOWED, ids=lambda f: f.__name__)
@pytest.mark.parametrize("state", [P, A, L, D])
def test_state_transitions(actor, make_user, make_credential, change, state):
    user = make_user(state=state)
    if change is services.enable:
        make_credential(user)  # with a PIN, which enable needs
    if state in ALLOWED[change]:
        change(user, actor)
        assert AuditEvent.objects.filter(target_user_id=user.pk).count() == 1
    else:
        with raises("invalid_state"):
            change(user, actor)
        assert User.objects.get(pk=user.pk).state == state
        assert not AuditEvent.objects.exists()


@pytest.mark.parametrize(
    ("change", "start", "end", "event"),
    [
        (services.disable, A, D, EventType.ACCOUNT_DISABLED),
        (services.enable, D, A, EventType.ACCOUNT_ENABLED),
        (services.lock, A, L, EventType.ACCOUNT_LOCKED),
        (services.unlock, L, A, EventType.ACCOUNT_UNLOCKED),
    ],
    ids=lambda v: getattr(v, "__name__", None),
)
def test_state_change_refreshes_the_user_and_audits(
    actor, make_user, make_credential, change, start, end, event
):
    user = make_user(state=start)
    if change is services.enable:
        make_credential(user)
    change(user, actor)
    assert user.state == end
    audit = AuditEvent.objects.get()
    assert audit.event_type == event
    assert audit.details == {"old_state": start, "new_state": end}


def key_failures(user: User) -> list[int]:
    return list(
        YubikeyCredential.objects.filter(user=user).values_list("failed_login_count", flat=True)
    )


@pytest.mark.parametrize(
    ("change", "state"),
    [(services.unlock, L), (services.enable, D), (services.reset_to_provisioning, L)],
    ids=lambda v: getattr(v, "__name__", None),
)
def test_changes_that_clear_every_failed_login_count(
    actor, make_user, make_credential, change, state
):
    user = make_user(state=state, failed_login_count=3)
    make_credential(user, failed_login_count=2)
    make_credential(user, failed_login_count=3)
    change(user, actor)
    assert user.failed_login_count == 0
    assert key_failures(user) == [0, 0]


def test_enable_needs_a_key_with_a_pin(actor, make_user, make_credential):
    user = make_user(state=D)
    make_credential(user, pin_hash="", radius_pin_hash="")
    with raises("no_pin"):
        services.enable(user, actor)
    assert user.state == D


def test_enable_with_an_imported_key_that_has_only_the_radius_hash(
    actor, make_user, make_credential
):
    user = make_user(state=D)
    make_credential(user, pin_hash="")
    services.enable(user, actor)
    assert user.state == A


def test_reset_to_provisioning(actor, make_user):
    user = make_user(state=L, failed_login_count=3)
    temporary = services.reset_to_provisioning(user, actor)
    assert user.state == P
    assert user.failed_login_count == 0
    assert check_web_password(temporary, user.temporary_password_hash)
    assert user.temporary_password_expires_at is not None
    assert user.temporary_password_expires_at > timezone.now() + timedelta(hours=71)
    audit = AuditEvent.objects.get()
    assert audit.event_type == EventType.ACCOUNT_RESET_TO_PROVISIONING
    assert temporary not in str(audit.details)


def test_set_temporary_password(actor):
    account = services.create_user("alice", actor)
    user = account.user
    User.objects.filter(pk=user.pk).update(failed_login_count=2)
    temporary = services.set_temporary_password(user, actor)
    assert temporary != account.temporary_password
    assert check_web_password(temporary, user.temporary_password_hash)
    assert not check_web_password(account.temporary_password, user.temporary_password_hash)
    assert user.failed_login_count == 0
    audit = AuditEvent.objects.get(event_type=EventType.TEMPORARY_PASSWORD_SET)
    assert audit.details == {"expires_at": user.temporary_password_expires_at.isoformat()}


def test_temporary_passwords_differ(actor):
    passwords = {services.create_user(f"user{n}", actor).temporary_password for n in range(5)}
    assert len(passwords) == 5


# Roles and last-admin protection (spec §6, §9.1)


def test_grant_and_revoke_admin(actor, make_user):
    make_user(admin=True)
    user = make_user()
    services.grant_admin(user, actor)
    services.grant_admin(user, actor)  # already an admin: nothing happens
    assert roles(user) == {"user", "admin"}
    services.revoke_admin(user, actor)
    services.revoke_admin(user, actor)  # no longer an admin: nothing happens
    assert roles(user) == {"user"}
    assert events() == [EventType.ADMIN_ROLE_GRANTED, EventType.ADMIN_ROLE_REVOKED]


@pytest.mark.parametrize("change", [services.disable, services.revoke_admin])
@pytest.mark.parametrize("state", [P, A, L])
def test_the_last_enabled_admin_is_kept(actor, make_user, change, state):
    admin = make_user(state=state, admin=True)
    make_user(state=D, admin=True)  # a disabled admin doesn't count
    with raises("last_admin"):
        change(admin, actor)
    assert User.objects.get(pk=admin.pk).state == state
    assert admin.is_admin
    assert not AuditEvent.objects.exists()


@pytest.mark.parametrize("change", [services.disable, services.revoke_admin])
@pytest.mark.parametrize("other_state", [P, A, L])
def test_an_admin_can_go_while_another_enabled_admin_remains(actor, make_user, change, other_state):
    admin = make_user(admin=True)
    make_user(state=other_state, admin=True)
    change(admin, actor)
    assert AuditEvent.objects.count() == 1


def test_a_disabled_admin_can_lose_the_admin_role(actor, make_user):
    make_user(admin=True)
    disabled = make_user(state=D, admin=True)
    services.revoke_admin(disabled, actor)
    assert not disabled.is_admin


def test_ordinary_accounts_can_be_disabled_with_no_admin_at_all(actor, make_user):
    user = make_user()
    services.disable(user, actor)
    assert user.state == D


def test_actions_by_a_signed_in_admin_record_the_admin(make_user):
    admin = make_user("boss", admin=True)
    user = make_user()
    services.disable(user, Actor.for_user(admin))
    audit = AuditEvent.objects.get()
    assert audit.actor_user_id == admin.pk
    assert audit.actor_username_snapshot == "boss"
