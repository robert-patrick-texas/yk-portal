import ipaddress
from datetime import timedelta

import pytest
from django.test import RequestFactory
from django.utils import timezone

from yk_portal.accounts import services
from yk_portal.accounts.models import AccountState, User
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.audit.service import Actor
from yk_portal.authentication.models import Session
from yk_portal.authentication.sessions import (
    Client,
    client_ip,
    end_session,
    find_session,
    purge_ended_sessions,
    revoke_sessions,
    start_session,
)
from yk_portal.portal_settings.service import PortalSettings

pytestmark = pytest.mark.django_db

CLIENT = Client("192.0.2.10", "pytest")
DEFAULTS = PortalSettings()


def age(session: Session, idle: timedelta = timedelta(), old: timedelta = timedelta()) -> None:
    """Make SESSION idle for IDLE, and started OLD ago."""
    now = timezone.now()
    Session.objects.filter(pk=session.pk).update(last_activity_at=now - idle, created_at=now - old)


def test_start_session_stores_only_a_hash(make_user):
    user = make_user()
    session, token = start_session(user, CLIENT)
    assert len(token) >= 43
    assert session.token_hash != token
    assert not Session.objects.filter(token_hash=token).exists()
    assert find_session(token, DEFAULTS) == session


def test_every_login_gets_a_new_session(make_user):
    user = make_user()
    (one, token_one), (two, token_two) = start_session(user, CLIENT), start_session(user, CLIENT)
    assert one != two and token_one != token_two
    # Concurrent sessions are allowed (spec §19).
    assert find_session(token_one, DEFAULTS) == one
    assert find_session(token_two, DEFAULTS) == two


def test_unknown_token(db):
    assert find_session("no-such-token", DEFAULTS) is None


def test_idle_timeout(make_user):
    session, token = start_session(make_user(), CLIENT)
    age(session, idle=timedelta(minutes=19, seconds=50))
    assert find_session(token, DEFAULTS) is not None
    age(session, idle=timedelta(minutes=20))
    assert find_session(token, DEFAULTS) is None


def test_idle_timeout_follows_the_setting(make_user):
    session, token = start_session(make_user(), CLIENT)
    age(session, idle=timedelta(minutes=25))
    assert find_session(token, DEFAULTS) is None
    assert find_session(token, PortalSettings(idle_timeout_minutes=30)) is not None


def test_maximum_session_length(make_user):
    session, token = start_session(make_user(), CLIENT)
    age(session, old=timedelta(hours=11, minutes=59))
    assert find_session(token, DEFAULTS) is not None
    age(session, old=timedelta(hours=12))
    assert find_session(token, DEFAULTS) is None
    assert find_session(token, PortalSettings(max_session_hours=13)) is not None


def test_activity_is_recorded_at_most_once_a_minute(make_user):
    session, token = start_session(make_user(), CLIENT)
    age(session, idle=timedelta(seconds=30))
    before = Session.objects.get(pk=session.pk).last_activity_at
    find_session(token, DEFAULTS)
    assert Session.objects.get(pk=session.pk).last_activity_at == before
    age(session, idle=timedelta(minutes=2))
    find_session(token, DEFAULTS)
    assert timezone.now() - Session.objects.get(pk=session.pk).last_activity_at < timedelta(
        seconds=5
    )


def test_end_session_records_a_logout(make_user):
    user = make_user()
    session, token = start_session(user, CLIENT)
    actor = Actor(user, user.username, CLIENT.source_ip, session.pk)
    end_session(session, actor)
    end_session(session, actor)  # already ended: no second event
    assert find_session(token, DEFAULTS) is None
    event = AuditEvent.objects.get()
    assert (event.event_type, event.target_user_id, event.session_id) == (
        EventType.LOGOUT,
        user.pk,
        session.pk,
    )


@pytest.mark.parametrize("state", [AccountState.LOCKED, AccountState.DISABLED])
def test_sessions_of_locked_or_disabled_accounts_dont_count(make_user, state):
    user = make_user()
    _, token = start_session(user, CLIENT)
    User.objects.filter(pk=user.pk).update(state=state)
    assert find_session(token, DEFAULTS) is None


def test_provisioning_sessions_count(make_user):
    _, token = start_session(make_user(state=AccountState.PROVISIONING), CLIENT)
    assert find_session(token, DEFAULTS) is not None


def test_revoke_sessions(make_user):
    user, other = make_user(), make_user()
    tokens = [start_session(user, CLIENT)[1] for _ in range(2)]
    _, other_token = start_session(other, CLIENT)
    assert revoke_sessions(user) == 2
    assert all(find_session(token, DEFAULTS) is None for token in tokens)
    assert find_session(other_token, DEFAULTS) is not None


@pytest.mark.parametrize(
    "change",
    [services.disable, services.lock, services.reset_to_provisioning],
    ids=lambda f: f.__name__,
)
def test_admin_changes_end_sessions(make_user, actor, change):
    user = make_user()
    _, token = start_session(user, CLIENT)
    change(user, actor)
    assert Session.objects.filter(user=user, revoked_at__isnull=True).count() == 0
    assert find_session(token, DEFAULTS) is None


def test_purge_deletes_only_ended_sessions(make_user):
    alice, bob = make_user(), make_user()
    live = [start_session(alice, CLIENT)[0], start_session(bob, CLIENT)[0]]
    revoked, idle, old = (start_session(user, CLIENT)[0] for user in (alice, bob, bob))
    end_session(revoked, Actor.cli())
    age(idle, idle=timedelta(minutes=20))
    age(old, old=timedelta(hours=12))
    assert purge_ended_sessions(DEFAULTS) == 3
    assert set(Session.objects.all()) == set(live)


def test_purge_follows_the_settings(make_user):
    session, _ = start_session(make_user(), CLIENT)
    age(session, idle=timedelta(minutes=25))
    assert purge_ended_sessions(PortalSettings(idle_timeout_minutes=30)) == 0
    assert purge_ended_sessions(DEFAULTS) == 1


def test_deleting_a_user_deletes_its_sessions(make_user):
    user = make_user()
    start_session(user, CLIENT)
    user.delete()
    assert not Session.objects.exists()


# The client's address


@pytest.fixture
def proxies(settings):
    settings.YK_TRUSTED_PROXIES = (
        ipaddress.ip_network("127.0.0.1/32"),
        ipaddress.ip_network("10.0.0.0/8"),
    )


@pytest.mark.parametrize(
    ("remote", "forwarded", "expected"),
    [
        ("192.0.2.10", "", "192.0.2.10"),
        ("192.0.2.10", "198.51.100.7", "192.0.2.10"),  # not from a proxy: ignored
        ("127.0.0.1", "", "127.0.0.1"),
        ("127.0.0.1", "198.51.100.7", "198.51.100.7"),
        ("127.0.0.1", "203.0.113.9, 198.51.100.7", "198.51.100.7"),  # the left one is forged
        ("127.0.0.1", "198.51.100.7, 10.1.2.3", "198.51.100.7"),  # two proxies
        ("127.0.0.1", "10.1.2.3, 10.4.5.6", "10.1.2.3"),
        ("127.0.0.1", "garbage", "127.0.0.1"),
        ("127.0.0.1", "2001:db8::7", "2001:db8::7"),
        ("", "", None),
    ],
)
def test_client_ip(proxies, remote, forwarded, expected):
    request = RequestFactory().get("/", REMOTE_ADDR=remote, HTTP_X_FORWARDED_FOR=forwarded)
    assert client_ip(request) == expected


def test_client_of_a_request_truncates_the_user_agent():
    request = RequestFactory().get("/", REMOTE_ADDR="192.0.2.10", HTTP_USER_AGENT="x" * 300)
    assert Client.of(request) == Client("192.0.2.10", "x" * 255)
