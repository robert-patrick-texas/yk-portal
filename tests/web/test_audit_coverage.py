"""Every sensitive action on the pages is audited with who did it, from where, in which
session (spec §9, §27; addendum §17.4)."""

from collections.abc import Callable
from dataclasses import dataclass

import pytest
from django.urls import reverse

from yk_portal.accounts import groups
from yk_portal.accounts.models import AccountState, User
from yk_portal.audit.models import AuditEvent, EventType, Result
from yk_portal.audit.service import Actor
from yk_portal.authentication.models import Session
from yk_portal.authentication.sessions import COOKIE, start_session
from yk_portal.authentication.sessions import Client as SessionClient
from yk_portal.portal_settings import service as portal_settings
from yk_portal.yubikeys.models import YubikeyCredential

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("master_key")]

PIN = "Passw0rd!"
K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"


@dataclass
class World:
    """root, an admin signed in, and the accounts and YubiKeys the actions need."""

    root: User
    alice: User
    key: YubikeyCredential
    make_user: Callable[..., User]
    make_credential: Callable[..., YubikeyCredential]

    def url(self, name: str, *args: object) -> str:
        return reverse(name, args=[*args])

    def key_url(self, name: str, key: YubikeyCredential | None = None) -> str:
        key = key or self.key
        return reverse(name, args=[key.user.pk, key.pk])


def settings_form(**changes: object) -> dict[str, object]:
    data: dict[str, object] = {
        "portal_name": "yk-portal",
        "login_notice": "",
        "idle_timeout_minutes": 20,
        "max_session_hours": 12,
        "temp_password_hours": 72,
        "failed_login_limit": 3,
        "max_yubikeys_per_user": 10,
        "step_up_before_reveal": "",
        "default_group": "",
        "default_theme": "browser",
    }
    return data | changes


def new_key(w: World) -> tuple[str, dict]:
    data = {
        "public_id": "vvccccbbcdef",
        "private_id": "4a6f8e2d1c3b",
        "aes_key": K1,
        "label": "VIP",
        "slot": "",
        "otp": "",
    }
    return w.url("admin-yubikey-add", w.alice.pk), data


def enable(w: World) -> tuple[str, dict]:
    bob = w.make_user("bob", state=AccountState.DISABLED)
    w.make_credential(bob, pin=PIN)
    return w.url("admin-user-enable", bob.pk), {}


def group(name: str) -> str:
    return reverse(name, args=[groups.create_group("noc", Actor.cli()).pk])


def member_removed(w: World) -> tuple[str, dict]:
    noc = groups.create_group("noc", Actor.cli())
    groups.add_member(noc, w.alice, Actor.cli())
    return reverse("admin-group-member-remove", args=[noc.pk, w.alice.pk]), {}


ACTIONS: dict[EventType, Callable[[World], tuple[str, dict]]] = {
    EventType.ACCOUNT_CREATED: lambda w: (w.url("admin-user-new"), {"username": "nina"}),
    EventType.USERNAME_CHANGED: lambda w: (
        w.url("admin-user-edit", w.alice.pk),
        {"username": "alicia"},
    ),
    EventType.ACCOUNT_UPDATED: lambda w: (
        w.url("admin-user-edit", w.alice.pk),
        {"username": "alice", "email": "alice@example.org"},
    ),
    EventType.ACCOUNT_DISABLED: lambda w: (w.url("admin-user-disable", w.alice.pk), {}),
    EventType.ACCOUNT_ENABLED: enable,
    EventType.ACCOUNT_UNLOCKED: lambda w: (
        w.url("admin-user-unlock", w.make_user("lee", state=AccountState.LOCKED).pk),
        {},
    ),
    EventType.ACCOUNT_RESET_TO_PROVISIONING: lambda w: (
        w.url("admin-user-reset", w.alice.pk),
        {},
    ),
    EventType.TEMPORARY_PASSWORD_SET: lambda w: (
        w.url(
            "admin-user-temporary-password",
            w.make_user("pat", state=AccountState.PROVISIONING).pk,
        ),
        {},
    ),
    EventType.ADMIN_ROLE_GRANTED: lambda w: (w.url("admin-user-grant-admin", w.alice.pk), {}),
    EventType.ADMIN_ROLE_REVOKED: lambda w: (
        w.url("admin-user-revoke-admin", w.make_user("sam", admin=True).pk),
        {},
    ),
    EventType.ACCOUNT_DELETED: lambda w: (
        w.url("admin-user-delete", w.alice.pk),
        {"username": "alice"},
    ),
    EventType.YUBIKEY_ADDED: new_key,
    EventType.YUBIKEY_UPDATED: lambda w: (
        w.key_url("admin-yubikey-edit"),
        {"label": "spare", "slot": "1"},
    ),
    EventType.PASSWORD_CHANGED: lambda w: (
        w.key_url("admin-yubikey-pin"),
        {"pin": PIN, "confirm": PIN},
    ),
    EventType.YUBIKEY_DISABLED: lambda w: (w.key_url("admin-yubikey-disable"), {}),
    EventType.YUBIKEY_ENABLED: lambda w: (
        w.key_url("admin-yubikey-enable", w.make_credential(w.alice, enabled=False)),
        {},
    ),
    EventType.YUBIKEY_REMOVED: lambda w: (w.key_url("admin-yubikey-remove"), {}),
    EventType.YUBIKEY_PRIVATE_ID_REVEALED: lambda w: (
        w.key_url("admin-yubikey-secrets"),
        {"secret": "both"},
    ),
    EventType.YUBIKEY_AES_SECRET_REVEALED: lambda w: (
        w.key_url("admin-yubikey-secrets"),
        {"secret": "both"},
    ),
    EventType.GROUP_CREATED: lambda w: (w.url("admin-group-new"), {"name": "ops"}),
    EventType.GROUP_UPDATED: lambda w: (
        group("admin-group-edit"),
        {"name": "noc-tx", "description": ""},
    ),
    EventType.GROUP_DELETED: lambda w: (group("admin-group-delete"), {}),
    EventType.GROUP_MEMBER_ADDED: lambda w: (
        group("admin-group-member-add"),
        {"username": "alice"},
    ),
    EventType.GROUP_MEMBER_REMOVED: member_removed,
    EventType.SETTING_CHANGED: lambda w: (
        w.url("admin-settings"),
        settings_form(portal_name="NOC"),
    ),
    EventType.LOGOUT: lambda w: (w.url("logout"), {}),
}


@pytest.fixture
def world(client, make_user, make_credential, actor) -> World:
    portal_settings.update({"step_up_before_reveal": False}, actor)
    root = make_user("root", admin=True)
    _, token = start_session(root, SessionClient("127.0.0.1", "pytest"))
    client.cookies[COOKIE] = token
    alice = make_user("alice", email="alice@example.com")
    key = make_credential(alice, public_id="vvccccbbcdeg")
    return World(root, alice, key, make_user, make_credential)


@pytest.mark.parametrize("event_type", ACTIONS, ids=str)
def test_the_page_records_the_admin_their_address_and_session(client, world, event_type):
    url, data = ACTIONS[event_type](world)
    before = list(AuditEvent.objects.values_list("pk", flat=True))
    session = Session.objects.get(user=world.root)
    response = client.post(url, data, REMOTE_ADDR="192.0.2.50")
    assert response.status_code in (200, 302), response.status_code
    events = AuditEvent.objects.exclude(pk__in=before).filter(event_type=event_type)
    assert events.exists(), list(AuditEvent.objects.exclude(pk__in=before))
    for event in events:
        assert event.result == Result.SUCCESS
        assert (event.actor_user_id, event.actor_username_snapshot) == (world.root.pk, "root")
        assert (event.source_ip, event.session_id) == ("192.0.2.50", session.pk)


def test_every_event_a_page_can_cause_is_covered():
    """Sign-in, onboarding, refusals and the commands are tested where they happen."""
    elsewhere = {
        EventType.LOGIN_SUCCESS,
        EventType.LOGIN_FAILURE,
        EventType.LOGIN_LOCKED,
        EventType.ACCOUNT_LOCKED,
        EventType.PROVISIONING_COMPLETED,
        EventType.ACCESS_DENIED,
        EventType.ADMIN_BOOTSTRAPPED,
        EventType.RADIATOR_EXPORT_CREATED,
        EventType.RADIATOR_IMPORT_COMPLETED,
        # Spec Phase 9 and later
        EventType.BACKUP_CREATED,
        EventType.BACKUP_RESTORED,
        EventType.MASTER_KEY_ROTATED,
    }
    assert set(EventType) - elsewhere == set(ACTIONS)
