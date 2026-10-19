import threading
from datetime import timedelta

import pytest
from django.db import connections
from django.utils import timezone

from yk_portal.accounts import services
from yk_portal.accounts.models import AccountState, User
from yk_portal.audit.models import AuditEvent, EventType, Result
from yk_portal.audit.service import Actor
from yk_portal.authentication import login
from yk_portal.authentication.login import (
    MESSAGE,
    LoginFailed,
    confirm_identity,
    log_in,
    split_passcode,
)
from yk_portal.authentication.models import Session
from yk_portal.authentication.passwords import check_web_password, hash_pin
from yk_portal.authentication.sessions import Client, start_session
from yk_portal.core import sha512_crypt
from yk_portal.portal_settings import service as portal_settings
from yk_portal.yubikeys.models import YubikeyCredential

pytestmark = pytest.mark.django_db

PIN = "Passw0rd!"
PIN2 = "0ther-pin2"
PUBLIC_ID = "vvccccbbcdef"
PUBLIC_ID2 = "vvccccbbcdeg"
PRIVATE_ID = "4a6f8e2d1c3b"
PRIVATE_ID2 = "4a6f8e2d1c3c"
K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"
K2 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
CLIENT = Client("192.0.2.10", "pytest")
P, A, L, D = (
    AccountState.PROVISIONING,
    AccountState.ACTIVE,
    AccountState.LOCKED,
    AccountState.DISABLED,
)


@pytest.fixture(scope="session")
def hashes():
    return {pin: hash_pin(pin) for pin in (PIN, PIN2)}


@pytest.fixture
def alice(make_user, make_credential, hashes):
    """alice, whose YubiKey PUBLIC_ID has the PIN PIN."""
    user = make_user("alice")
    make_credential(
        user,
        public_id=PUBLIC_ID,
        private_id=PRIVATE_ID,
        aes_key=K1,
        pin_hash=hashes[PIN].web,
        radius_pin_hash=hashes[PIN].radius,
    )
    return user


@pytest.fixture
def second_key(alice, make_credential, hashes):
    """alice's second YubiKey, PUBLIC_ID2, with the PIN PIN2."""
    return make_credential(
        alice,
        public_id=PUBLIC_ID2,
        private_id=PRIVATE_ID2,
        aes_key=K1,
        pin_hash=hashes[PIN2].web,
        radius_pin_hash=hashes[PIN2].radius,
    )


@pytest.fixture
def otp(make_otp):
    """otp(counter, session=0, private_id=..., aes_key=..., public_id=...): an OTP."""

    def make(counter: int, session: int = 0, **kw: str) -> str:
        return make_otp(
            kw.get("public_id", PUBLIC_ID),
            kw.get("private_id", PRIVATE_ID),
            kw.get("aes_key", K1),
            counter,
            session,
        )

    return make


def refused(username: str, passcode: str) -> None:
    with pytest.raises(LoginFailed) as excinfo:
        log_in(username, passcode, CLIENT)
    assert str(excinfo.value) == MESSAGE


def last_event() -> AuditEvent:
    return AuditEvent.objects.order_by("-timestamp")[0]


def fresh(user: User) -> User:
    return User.objects.get(pk=user.pk)


def key_failures(public_id: str = PUBLIC_ID) -> int:
    return YubikeyCredential.objects.get(public_id=public_id).failed_login_count


@pytest.mark.parametrize(
    ("passcode", "expected"),
    [
        ("pw" + "c" * 44, ("pw", "c" * 44)),
        ("pw:" + "c" * 44, ("pw", "c" * 44)),  # Radiator's PIN:OTP (addendum §2.9)
        ("pw::" + "c" * 44, ("pw:", "c" * 44)),  # only one colon is dropped
        ("c" * 44, ("", "c" * 44)),
        ("short", ("short", None)),
        ("c" * 43, ("c" * 43, None)),
    ],
)
def test_split_passcode(passcode, expected):
    assert split_passcode(passcode) == expected


# ACTIVE accounts: a YubiKey's PIN + its OTP


def test_login(alice, otp):
    User.objects.filter(pk=alice.pk).update(failed_login_count=2)
    YubikeyCredential.objects.filter(public_id=PUBLIC_ID).update(failed_login_count=2)
    session, token = log_in("Alice", PIN + otp(3, 1), CLIENT)
    assert session.user == alice
    assert session.source_ip == "192.0.2.10"
    assert session.user_agent == "pytest"
    assert token not in session.token_hash
    user = fresh(alice)
    assert user.failed_login_count == 0
    assert user.last_login_at is not None
    credential = YubikeyCredential.objects.get(public_id=PUBLIC_ID)
    assert (credential.last_usage_counter, credential.last_session_counter) == (3, 1)
    assert credential.failed_login_count == 0
    event = last_event()
    assert event.event_type == EventType.LOGIN_SUCCESS
    assert event.details == {"state": A, "public_id": PUBLIC_ID}
    assert event.actor_user_id == event.target_user_id == alice.pk
    assert event.session_id == session.pk
    assert event.source_ip == "192.0.2.10"


def test_login_deletes_ended_sessions(alice, otp, make_user):
    old, _ = start_session(make_user(), CLIENT)
    Session.objects.filter(pk=old.pk).update(revoked_at=timezone.now())
    session, _ = log_in("alice", PIN + otp(3, 1), CLIENT)
    assert list(Session.objects.all()) == [session]


def test_login_with_a_colon_before_the_otp(alice, otp):
    log_in("alice", f"{PIN}:{otp(3, 1)}", CLIENT)


@pytest.mark.parametrize(
    ("passcode", "reason", "public_id"),
    [
        # Against the YubiKey: its PIN or OTP was wrong (addendum §2.14).
        ("wrong-pin1{otp}", "wrong PIN", PUBLIC_ID),
        ("{pin}{bad_crc}", "token does not decrypt (wrong AES key, or a mistyped OTP)", PUBLIC_ID),
        ("{pin}{bad_private_id}", "private ID mismatch", PUBLIC_ID),
        # Against the account: no YubiKey of it was named.
        ("{pin}", "malformed OTP", None),
        ("{pin}" + "x" * 44, "malformed OTP", None),
        ("{pin}{other_key}", "unknown public ID", None),
    ],
)
def test_failures_count(alice, otp, passcode, reason, public_id):
    passcode = passcode.format(
        pin=PIN,
        otp=otp(3, 1),
        other_key=otp(3, 1, public_id="vvccccbbcdeh"),
        bad_crc=otp(3, 1, aes_key=K2),
        bad_private_id=otp(3, 1, private_id="111111111111"),
    )
    refused("alice", passcode)
    assert (key_failures(), fresh(alice).failed_login_count) == ((1, 0) if public_id else (0, 1))
    event = last_event()
    assert event.event_type == EventType.LOGIN_FAILURE
    assert event.result == Result.FAILURE
    assert event.target_user_id == alice.pk
    expected = {"reason": reason, "failed_logins": 1}
    assert event.details == (expected | {"public_id": public_id} if public_id else expected)
    assert not Session.objects.exists()


def test_a_wrong_pin_leaves_the_otp_unused(alice, otp):
    refused("alice", "wrong-pin1" + otp(3, 1))
    credential = YubikeyCredential.objects.get(public_id=PUBLIC_ID)
    assert (credential.last_usage_counter, credential.last_session_counter) == (0, 0)
    log_in("alice", PIN + otp(3, 1), CLIENT)


def test_a_replayed_otp_counts_against_the_key(alice, otp):
    log_in("alice", PIN + otp(3, 1), CLIENT)
    refused("alice", PIN + otp(3, 1))
    assert last_event().details["reason"] == "replayed or stale OTP"
    assert key_failures() == 1


def test_another_users_key_and_a_disabled_key_count_against_the_account(
    alice, otp, make_user, make_credential
):
    make_credential(make_user("bob"), public_id="vvccccbbcdeh", aes_key=K1)
    refused("alice", PIN + otp(3, 1, public_id="vvccccbbcdeh"))
    assert last_event().details["reason"] == "public ID of another user's YubiKey"
    YubikeyCredential.objects.filter(public_id=PUBLIC_ID).update(enabled=False)
    refused("alice", PIN + otp(3, 1))
    assert last_event().details["reason"] == "disabled YubiKey"
    assert (fresh(alice).failed_login_count, key_failures()) == (2, 0)


def test_a_success_clears_the_keys_count_and_the_accounts(alice, otp):
    refused("alice", "wrong-pin1" + otp(3, 1))
    refused("alice", PIN + "x" * 44)
    log_in("alice", PIN + otp(3, 3), CLIENT)
    assert (key_failures(), fresh(alice).failed_login_count) == (0, 0)


def test_the_third_failure_locks_the_account(alice, otp):
    session, _ = start_session(alice, CLIENT)
    for session_counter in (1, 2, 3):
        refused("alice", "wrong-pin1" + otp(3, session_counter))
    user = fresh(alice)
    assert user.state == L
    assert key_failures() == 3
    locked = AuditEvent.objects.get(event_type=EventType.ACCOUNT_LOCKED)
    assert locked.details == {"old_state": A, "new_state": L}
    assert locked.source_ip == "192.0.2.10"
    # Its sessions end, and the right passcode no longer works (spec §18).
    assert Session.objects.get(pk=session.pk).revoked_at is not None
    refused("alice", PIN + otp(3, 4))
    assert last_event().event_type == EventType.LOGIN_LOCKED
    assert key_failures() == 3


def test_the_third_failure_naming_no_key_locks_the_account(alice):
    for _ in range(3):
        refused("alice", PIN + "x" * 44)
    assert fresh(alice).state == L


@pytest.mark.django_db(transaction=True)
def test_failures_at_once_are_each_counted(alice, otp, actor):
    """Simultaneous failed logins are each counted once, and lock the account once, on
    both backends (spec §48; addendum §18.4): PostgreSQL locks the rows, SQLite's
    IMMEDIATE transactions take turns."""
    limit = 10
    portal_settings.update({"failed_login_limit": limit}, actor)
    barrier = threading.Barrier(limit)
    errors: list[BaseException] = []

    def fail(session_counter: int) -> None:
        try:
            barrier.wait()
            refused("alice", "wrong-pin1" + otp(3, session_counter))
        except BaseException as e:  # noqa: BLE001 - reported below
            errors.append(e)
        finally:
            connections.close_all()

    workers = [threading.Thread(target=fail, args=(n,)) for n in range(1, limit + 1)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert errors == []
    assert key_failures() == limit
    assert fresh(alice).state == L
    assert AuditEvent.objects.filter(event_type=EventType.LOGIN_FAILURE).count() == limit
    assert AuditEvent.objects.filter(event_type=EventType.ACCOUNT_LOCKED).count() == 1


def test_the_limit_follows_the_setting(alice, otp, actor):
    portal_settings.update({"failed_login_limit": 5}, actor)
    for session_counter in range(1, 5):
        refused("alice", "wrong-pin1" + otp(3, session_counter))
    assert fresh(alice).state == A
    refused("alice", "wrong-pin1" + otp(3, 5))
    assert fresh(alice).state == L


# Several YubiKeys, each with its own PIN (addendum §2.2, §2.14)


def test_each_key_takes_its_own_pin(alice, second_key, otp):
    refused("alice", PIN2 + otp(3, 1))
    refused("alice", PIN + otp(3, 1, public_id=PUBLIC_ID2, private_id=PRIVATE_ID2))
    log_in("alice", PIN + otp(3, 1), CLIENT)
    log_in("alice", PIN2 + otp(3, 2, public_id=PUBLIC_ID2, private_id=PRIVATE_ID2), CLIENT)


def test_failures_with_different_keys_dont_add_up(alice, second_key, otp):
    for session_counter in (1, 2):
        refused("alice", "wrong-pin1" + otp(3, session_counter))
        refused(
            "alice",
            "wrong-pin1" + otp(3, session_counter, public_id=PUBLIC_ID2, private_id=PRIVATE_ID2),
        )
    assert fresh(alice).state == A
    assert (key_failures(PUBLIC_ID), key_failures(PUBLIC_ID2)) == (2, 2)


def test_a_success_with_one_key_leaves_anothers_count(alice, second_key, otp):
    """A stolen YubiKey gets no more PIN guesses while its owner signs in with another."""
    second = {"public_id": PUBLIC_ID2, "private_id": PRIVATE_ID2}
    refused("alice", "wrong-pin1" + otp(3, 1, **second))
    refused("alice", "wrong-pin1" + otp(3, 2, **second))
    log_in("alice", PIN + otp(3, 1), CLIENT)
    assert key_failures(PUBLIC_ID2) == 2
    refused("alice", "wrong-pin1" + otp(3, 3, **second))
    assert fresh(alice).state == L


def test_unlocking_clears_every_count(alice, second_key, otp, actor):
    refused("alice", "wrong-pin1" + otp(3, 1, public_id=PUBLIC_ID2, private_id=PRIVATE_ID2))
    for _ in range(3):
        refused("alice", PIN + "x" * 44)
    services.unlock(alice, actor)
    assert (fresh(alice).failed_login_count, key_failures(PUBLIC_ID2)) == (0, 0)


def test_an_account_disabled_during_the_check_is_refused(alice, otp, actor, monkeypatch):
    """The refusal is recorded, though the check's transaction ends in it."""
    accept = login.accept_otp

    def accept_then_disable(*args):
        accept(*args)
        services.disable(fresh(alice), actor)

    monkeypatch.setattr(login, "accept_otp", accept_then_disable)
    refused("alice", PIN + otp(3, 1))
    event = last_event()
    assert (event.event_type, event.details) == (
        EventType.LOGIN_FAILURE,
        {"reason": "state changed"},
    )
    assert not Session.objects.exists()


def test_a_disabled_account_is_refused_without_counting(alice, otp):
    User.objects.filter(pk=alice.pk).update(state=D)
    refused("alice", PIN + otp(3, 1))
    assert fresh(alice).failed_login_count == 0
    assert last_event().details == {"reason": "account disabled"}


def test_unknown_username(otp):
    refused("nobody", PIN + otp(3, 1))
    event = last_event()
    assert event.target_user_id is None
    assert event.details == {"reason": "unknown username nobody"}
    assert event.source_ip == "192.0.2.10"


def test_an_unknown_username_that_could_be_a_password_isnt_logged():
    refused("Secret Pass 1!", PIN)
    assert last_event().details == {"reason": "unknown username (not a valid username)"}


def test_a_temporary_password_in_the_username_box_isnt_logged(newcomer):
    """It is a valid username, but no account's name (spec §27)."""
    refused(newcomer.temporary_password, newcomer.temporary_password)
    assert last_event().details == {"reason": "unknown username (looks like a temporary password)"}


# YubiKeys imported from Radiator (addendum §2.8)


@pytest.fixture
def imported_key(make_user, make_credential):
    """erin's YubiKey, with only the SHA-512 crypt hash of its PIN, pin12345."""
    radius = sha512_crypt.make_hash("pin12345")
    return make_credential(
        make_user("erin"),
        public_id=PUBLIC_ID,
        private_id=PRIVATE_ID,
        aes_key=K1,
        pin_hash="",
        radius_pin_hash=radius,
    )


def test_first_web_login_with_an_imported_key(imported_key, otp):
    log_in("erin", "pin12345" + otp(3, 1), CLIENT)
    imported_key.refresh_from_db()
    assert check_web_password("pin12345", imported_key.pin_hash)
    log_in("erin", "pin12345" + otp(3, 2), CLIENT)


def test_an_imported_keys_wrong_pin_counts(imported_key, otp):
    refused("erin", "pin99999" + otp(3, 1))
    imported_key.refresh_from_db()
    assert (imported_key.failed_login_count, imported_key.pin_hash) == (1, "")


def test_a_key_without_a_pin_never_signs_in(alice, otp):
    YubikeyCredential.objects.filter(public_id=PUBLIC_ID).update(pin_hash="", radius_pin_hash="")
    for pin in ("", "anything1"):
        refused("alice", pin + otp(3, 1))
    assert last_event().details["reason"] == "wrong PIN"


# PROVISIONING accounts: the temporary password alone


@pytest.fixture
def newcomer(actor):
    return services.create_user("nina", actor)


def test_provisioning_login(newcomer):
    session, _ = log_in("nina", newcomer.temporary_password, CLIENT)
    assert session.user == newcomer.user
    assert last_event().details == {"state": P}


def test_a_wrong_temporary_password_counts_and_locks(newcomer):
    for _ in range(3):
        refused("nina", "wrong-temp-1")
    user = fresh(newcomer.user)
    assert user.state == L  # addendum §2.10
    assert user.failed_login_count == 3
    refused("nina", newcomer.temporary_password)


def test_unlocking_returns_a_provisioning_account_to_provisioning(newcomer, actor):
    for _ in range(3):
        refused("nina", "wrong-temp-1")
    services.unlock(newcomer.user, actor)
    assert newcomer.user.state == P
    log_in("nina", newcomer.temporary_password, CLIENT)


def test_an_expired_temporary_password_is_refused_without_counting(newcomer):
    User.objects.filter(pk=newcomer.user.pk).update(
        temporary_password_expires_at=timezone.now() - timedelta(seconds=1)
    )
    refused("nina", newcomer.temporary_password)
    assert fresh(newcomer.user).failed_login_count == 0
    assert last_event().details == {"reason": "temporary password expired"}


def test_the_temporary_password_doesnt_take_an_otp(newcomer, otp):
    refused("nina", newcomer.temporary_password + otp(3, 1))
    assert last_event().details["reason"] == "wrong temporary password"


# Step-up before revealing a secret (spec §20.2)


def as_actor(user: User, session: Session | None = None) -> Actor:
    return Actor(user, user.username, CLIENT.source_ip, session.pk if session else None)


def test_confirm_identity(alice, otp):
    confirm_identity(as_actor(alice), PIN + otp(3, 1))
    credential = YubikeyCredential.objects.get(public_id=PUBLIC_ID)
    assert (credential.last_usage_counter, credential.last_session_counter) == (3, 1)


def test_failed_step_ups_count_and_lock(alice, otp):
    session, _ = start_session(alice, CLIENT)
    for session_counter in (1, 2, 3):
        with pytest.raises(LoginFailed):
            confirm_identity(as_actor(alice, session), "wrong-pin1" + otp(3, session_counter))
    failures = AuditEvent.objects.filter(event_type=EventType.LOGIN_FAILURE)
    assert {e.details["reason"] for e in failures} == {"step-up: wrong PIN"}
    assert {(e.actor_user_id, e.session_id) for e in failures} == {(alice.pk, session.pk)}
    assert fresh(alice).state == L
