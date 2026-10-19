"""The per-address limit on failed sign-ins (spec §18.2, §43 item 6; addendum §20.4)."""

import logging
from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from yk_portal.accounts.models import AccountState, User
from yk_portal.audit.models import AuditEvent, EventType, Result
from yk_portal.authentication import login, throttle
from yk_portal.authentication.login import LoginFailed, LoginThrottled, log_in
from yk_portal.authentication.passwords import hash_pin
from yk_portal.authentication.sessions import Client
from yk_portal.portal_settings import service as portal_settings

pytestmark = pytest.mark.django_db

PIN = "Passw0rd!"
PUBLIC_ID = "vvccccbbcdef"
PRIVATE_ID = "4a6f8e2d1c3b"
K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"
ATTACKER = Client("192.0.2.66", "pytest")
NEIGHBOUR = Client("192.0.2.67", "pytest")


@pytest.fixture(scope="session")
def hashes():
    return hash_pin(PIN)


@pytest.fixture
def alice(make_user, make_credential, hashes):
    user = make_user("alice")
    make_credential(
        user,
        public_id=PUBLIC_ID,
        private_id=PRIVATE_ID,
        aes_key=K1,
        pin_hash=hashes.web,
        radius_pin_hash=hashes.radius,
    )
    return user


@pytest.fixture
def passcode(make_otp):
    return lambda counter: PIN + make_otp(PUBLIC_ID, PRIVATE_ID, K1, counter)


@pytest.fixture
def limit(actor):
    """Two failed sign-ins from an address within 10 minutes, then it waits."""
    portal_settings.update({"address_failure_limit": 2, "address_wait_minutes": 10}, actor)


def fail(client: Client = ATTACKER, username: str = "nobody") -> None:
    with pytest.raises(LoginFailed) as excinfo:
        log_in(username, "wrong", client)
    assert not isinstance(excinfo.value, LoginThrottled)


def failure_at(minutes_ago: float, source_ip: str = ATTACKER.source_ip or "") -> None:
    AuditEvent.objects.create(
        timestamp=timezone.now() - timedelta(minutes=minutes_ago),
        event_type=EventType.LOGIN_FAILURE,
        source_ip=source_ip,
        result=Result.FAILURE,
        details={"reason": "unknown username nobody"},
    )


def waiting(client: Client = ATTACKER) -> timedelta | None:
    return throttle.wait(client.source_ip, portal_settings.current())


def throttled_events() -> list[AuditEvent]:
    return list(AuditEvent.objects.filter(event_type=EventType.LOGIN_THROTTLED))


def test_defaults():
    settings = portal_settings.current()
    assert (settings.address_failure_limit, settings.address_wait_minutes) == (10, 15)


def test_an_address_at_the_limit_waits_even_with_the_right_passcode(limit, alice, passcode):
    fail()
    fail()
    with pytest.raises(LoginThrottled) as excinfo:
        log_in("alice", passcode(1), ATTACKER)
    assert str(excinfo.value) == (
        "Too many failed sign-ins from your address. Try again in 10 minutes."
    )
    # Nothing was checked: the OTP wasn't used, so it signs in from elsewhere.
    log_in("alice", passcode(1), NEIGHBOUR)


def test_a_waiting_address_cant_lock_accounts(limit, alice, actor):
    """The lockout's denial of service (spec §43 item 6): the attempts aren't checked,
    so they don't count against the account or its YubiKeys."""
    portal_settings.update({"failed_login_limit": 3}, actor)
    fail(username="alice")
    fail(username="alice")
    for _ in range(5):
        with pytest.raises(LoginThrottled):
            log_in("alice", "wrong" + "c" * 44, ATTACKER)
    alice = User.objects.get(pk=alice.pk)
    assert alice.state == AccountState.ACTIVE
    assert alice.failed_login_count == 2


def test_it_is_recorded_once_per_wait(limit):
    fail()
    fail()
    for _ in range(3):
        with pytest.raises(LoginThrottled):
            log_in("nobody", "wrong", ATTACKER)
    (event,) = throttled_events()
    assert event.result == Result.FAILURE
    assert (event.source_ip, event.actor_user_id, event.target_user_id) == (
        ATTACKER.source_ip,
        None,
        None,
    )
    assert event.details == {
        "reason": "too many failed sign-ins from this address",
        "failed_logins": 2,
        "wait_minutes": 10,
        "seconds_left": event.details["seconds_left"],
    }
    assert 590 <= event.details["seconds_left"] <= 600
    # Not a failure itself: the wait doesn't grow while the address keeps trying.
    left = waiting()
    assert left is not None and left <= timedelta(minutes=10)


def test_the_wait_ends_when_enough_failures_are_old(limit):
    failure_at(9)
    failure_at(4)
    left = waiting()
    assert left is not None and timedelta(seconds=59) <= left <= timedelta(minutes=1)
    failure_at(2)  # the two latest now count: the wait is longer
    left = waiting()
    assert left is not None and timedelta(minutes=5, seconds=59) <= left <= timedelta(minutes=6)


def test_failures_older_than_the_wait_dont_count(limit):
    failure_at(11)
    failure_at(10.5)
    failure_at(3)
    assert waiting() is None
    fail()  # a second failure within the wait


def test_other_addresses_dont_wait(limit, alice, passcode):
    fail()
    fail()
    log_in("alice", passcode(1), NEIGHBOUR)
    assert waiting(NEIGHBOUR) is None


def test_attempts_on_locked_accounts_count(limit, make_user):
    make_user("lou", state=AccountState.LOCKED)
    fail(username="lou")
    fail(username="lou")
    assert AuditEvent.objects.filter(event_type=EventType.LOGIN_LOCKED).count() == 2
    with pytest.raises(LoginThrottled):
        log_in("lou", "wrong", ATTACKER)


def test_a_settings_change_applies_at_once(limit, actor):
    fail()
    fail()
    portal_settings.update({"address_failure_limit": 3}, actor)
    fail()
    with pytest.raises(LoginThrottled):
        log_in("nobody", "wrong", ATTACKER)


def test_the_wait_is_shown_in_whole_minutes():
    assert str(LoginThrottled(timedelta(seconds=5))).endswith("Try again in 1 minute.")
    assert str(LoginThrottled(timedelta(seconds=61))).endswith("Try again in 2 minutes.")
    assert isinstance(LoginThrottled(timedelta(0)), LoginFailed)


def test_a_trusted_proxys_own_address_is_never_counted(limit, caplog, monkeypatch):
    """The proxy didn't send the client's address: every client would share one count,
    and one of them could make everyone wait. It is logged once."""
    monkeypatch.setattr(throttle, "_warned", False)
    proxy = Client("127.0.0.1", "pytest")
    with caplog.at_level(logging.WARNING, logger="yk_portal.authentication"):
        for _ in range(4):
            fail(proxy)
    (message,) = caplog.messages
    assert "from 127.0.0.1, a trusted proxy, without the client's address" in message
    assert "X-Forwarded-For" in message


def test_no_address_is_never_counted(limit):
    nowhere = Client(None, "pytest")
    for _ in range(3):
        fail(nowhere)


def test_the_sign_in_page_answers_429(limit, client):
    for _ in range(2):
        response = client.post(
            reverse("login"), {"username": "nobody", "passcode": "wrong"}, REMOTE_ADDR="192.0.2.66"
        )
        assert response.status_code == 200
    response = client.post(
        reverse("login"), {"username": "nobody", "passcode": "wrong"}, REMOTE_ADDR="192.0.2.66"
    )
    assert response.status_code == 429
    assert "Too many failed sign-ins from your address." in response.content.decode()


def test_behind_the_proxy_the_clients_address_counts(limit, client):
    def post():
        return client.post(
            reverse("login"),
            {"username": "nobody", "passcode": "wrong"},
            REMOTE_ADDR="127.0.0.1",
            HTTP_X_FORWARDED_FOR="192.0.2.66",
        )

    post()
    post()
    assert post().status_code == 429
    assert throttled_events()[0].source_ip == "192.0.2.66"


def test_the_check_comes_before_any_password_check(limit, monkeypatch):
    fail()
    fail()
    monkeypatch.setattr(login, "check_web_password", pytest.fail)
    with pytest.raises(LoginThrottled):
        log_in("nobody", "wrong", ATTACKER)
