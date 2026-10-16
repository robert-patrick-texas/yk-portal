from datetime import timedelta

import pytest
from django.utils import timezone

from yk_portal.accounts import services
from yk_portal.accounts.models import AccountState, User
from yk_portal.audit.models import AuditEvent, EventType, Result
from yk_portal.authentication.login import MESSAGE, LoginFailed, log_in, split_passcode
from yk_portal.authentication.models import Session
from yk_portal.authentication.passwords import check_web_password, hash_password
from yk_portal.authentication.sessions import Client, start_session
from yk_portal.core import sha512_crypt
from yk_portal.portal_settings import service as portal_settings
from yk_portal.yubikeys.models import YubikeyCredential

pytestmark = pytest.mark.django_db

PASSWORD = "Passw0rd!"  # noqa: S105 - a test password
PUBLIC_ID = "vvccccbbcdef"
PRIVATE_ID = "4a6f8e2d1c3b"
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
    return hash_password(PASSWORD)


@pytest.fixture
def alice(make_user, make_credential, hashes):
    user = make_user("alice", password_hash=hashes.web, radius_password_hash=hashes.radius)
    make_credential(user, public_id=PUBLIC_ID, private_id=PRIVATE_ID, aes_key=K1)
    return user


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


# ACTIVE accounts: password + OTP


def test_login(alice, otp):
    User.objects.filter(pk=alice.pk).update(failed_login_count=2)
    session, token = log_in("Alice", PASSWORD + otp(3, 1), CLIENT)
    assert session.user == alice
    assert session.source_ip == "192.0.2.10"
    assert session.user_agent == "pytest"
    assert token not in session.token_hash
    user = fresh(alice)
    assert user.failed_login_count == 0
    assert user.last_login_at is not None
    credential = YubikeyCredential.objects.get(public_id=PUBLIC_ID)
    assert (credential.last_usage_counter, credential.last_session_counter) == (3, 1)
    event = last_event()
    assert event.event_type == EventType.LOGIN_SUCCESS
    assert event.actor_user_id == event.target_user_id == alice.pk
    assert event.session_id == session.pk
    assert event.source_ip == "192.0.2.10"


def test_login_with_a_colon_before_the_otp(alice, otp):
    log_in("alice", f"{PASSWORD}:{otp(3, 1)}", CLIENT)


@pytest.mark.parametrize(
    ("passcode", "reason"),
    [
        ("wrong-pw1" + "{otp}", "wrong password"),
        ("{pw}", "malformed OTP"),
        ("{pw}" + "x" * 44, "malformed OTP"),
        ("{pw}{other_key}", "unknown public ID"),
        ("{pw}{bad_crc}", "token does not decrypt (wrong AES key, or a mistyped OTP)"),
        ("{pw}{bad_private_id}", "private ID mismatch"),
    ],
)
def test_failures_count(alice, otp, passcode, reason):
    passcode = passcode.format(
        pw=PASSWORD,
        otp=otp(3, 1),
        other_key=otp(3, 1, public_id="vvccccbbcdeg"),
        bad_crc=otp(3, 1, aes_key=K2),
        bad_private_id=otp(3, 1, private_id="111111111111"),
    )
    refused("alice", passcode)
    assert fresh(alice).failed_login_count == 1
    event = last_event()
    assert event.event_type == EventType.LOGIN_FAILURE
    assert event.result == Result.FAILURE
    assert event.target_user_id == alice.pk
    assert event.details == {"reason": reason, "failed_logins": 1}
    assert not Session.objects.exists()


def test_a_wrong_password_leaves_the_otp_unused(alice, otp):
    refused("alice", "wrong-pw1" + otp(3, 1))
    credential = YubikeyCredential.objects.get(public_id=PUBLIC_ID)
    assert (credential.last_usage_counter, credential.last_session_counter) == (0, 0)
    log_in("alice", PASSWORD + otp(3, 1), CLIENT)


def test_a_replayed_otp_counts(alice, otp):
    log_in("alice", PASSWORD + otp(3, 1), CLIENT)
    refused("alice", PASSWORD + otp(3, 1))
    assert last_event().details["reason"] == "replayed or stale OTP"
    assert fresh(alice).failed_login_count == 1


def test_another_users_key_and_a_disabled_key_count(alice, otp, make_user, make_credential):
    make_credential(make_user("bob"), public_id="vvccccbbcdeg", aes_key=K1)
    refused("alice", PASSWORD + otp(3, 1, public_id="vvccccbbcdeg"))
    assert last_event().details["reason"] == "public ID of another user's YubiKey"
    YubikeyCredential.objects.filter(public_id=PUBLIC_ID).update(enabled=False)
    refused("alice", PASSWORD + otp(3, 1))
    assert last_event().details["reason"] == "disabled YubiKey"
    assert fresh(alice).failed_login_count == 2


def test_a_success_clears_the_count(alice, otp):
    refused("alice", "wrong-pw1" + otp(3, 1))
    refused("alice", "wrong-pw1" + otp(3, 2))
    log_in("alice", PASSWORD + otp(3, 3), CLIENT)
    assert fresh(alice).failed_login_count == 0


def test_the_third_failure_locks_the_account(alice, otp):
    session, _ = start_session(alice, CLIENT)
    for session_counter in (1, 2, 3):
        refused("alice", "wrong-pw1" + otp(3, session_counter))
    user = fresh(alice)
    assert user.state == L
    assert user.failed_login_count == 3
    locked = AuditEvent.objects.get(event_type=EventType.ACCOUNT_LOCKED)
    assert locked.details == {"old_state": A, "new_state": L}
    assert locked.source_ip == "192.0.2.10"
    # Its sessions end, and the right passcode no longer works (spec §18).
    assert Session.objects.get(pk=session.pk).revoked_at is not None
    refused("alice", PASSWORD + otp(3, 4))
    assert last_event().event_type == EventType.LOGIN_LOCKED
    assert fresh(alice).failed_login_count == 3


def test_the_limit_follows_the_setting(alice, otp, actor):
    portal_settings.update({"failed_login_limit": 5}, actor)
    for session_counter in range(1, 5):
        refused("alice", "wrong-pw1" + otp(3, session_counter))
    assert fresh(alice).state == A
    refused("alice", "wrong-pw1" + otp(3, 5))
    assert fresh(alice).state == L


def test_a_disabled_account_is_refused_without_counting(alice, otp):
    User.objects.filter(pk=alice.pk).update(state=D)
    refused("alice", PASSWORD + otp(3, 1))
    assert fresh(alice).failed_login_count == 0
    assert last_event().details == {"reason": "account disabled"}


def test_unknown_username(otp):
    refused("nobody", PASSWORD + otp(3, 1))
    event = last_event()
    assert event.target_user_id is None
    assert event.details == {"reason": "unknown username nobody"}
    assert event.source_ip == "192.0.2.10"


def test_an_unknown_username_that_could_be_a_password_isnt_logged():
    refused("Secret Pass 1!", PASSWORD)
    assert last_event().details == {"reason": "unknown username (not a valid username)"}


# Accounts imported from Radiator (addendum §2.8)


def test_first_web_login_of_an_imported_account(make_user, make_credential, otp):
    user = make_user(
        "erin", password_hash="", radius_password_hash=sha512_crypt.make_hash("pin12345")
    )
    make_credential(user, public_id=PUBLIC_ID, private_id=PRIVATE_ID, aes_key=K1)
    log_in("erin", "pin12345" + otp(3, 1), CLIENT)
    assert check_web_password("pin12345", fresh(user).password_hash)
    log_in("erin", "pin12345" + otp(3, 2), CLIENT)


def test_an_imported_accounts_wrong_password_counts(make_user, make_credential, otp):
    user = make_user(
        "erin", password_hash="", radius_password_hash=sha512_crypt.make_hash("pin12345")
    )
    make_credential(user, public_id=PUBLIC_ID, private_id=PRIVATE_ID, aes_key=K1)
    refused("erin", "pin99999" + otp(3, 1))
    assert fresh(user).failed_login_count == 1
    assert fresh(user).password_hash == ""


def test_an_account_without_any_password_never_signs_in(make_user, make_credential, otp):
    user = make_user("frank", password_hash="", radius_password_hash="")
    make_credential(user, public_id=PUBLIC_ID, private_id=PRIVATE_ID, aes_key=K1)
    for password in ("", "anything1"):
        refused("frank", password + otp(3, 1))
    assert last_event().details["reason"] == "wrong password"


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
