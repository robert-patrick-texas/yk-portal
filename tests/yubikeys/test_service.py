import os
import threading
from datetime import timedelta

import pytest
from django.db import connection, connections
from django.utils import timezone

from yk_portal.core.encryption import DecryptionError
from yk_portal.yubikeys.models import YubikeyCredential
from yk_portal.yubikeys.otp import OtpRejected, Rejection, parse_otp
from yk_portal.yubikeys.service import accept_otp, find_credential

pytestmark = pytest.mark.django_db

PRIVATE_ID = "4a6f8e2d1c3b"
K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"
K2 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"


@pytest.fixture
def credential(make_credential):
    return make_credential(public_id="vvccccbbcdef", private_id=PRIVATE_ID, aes_key=K1)


@pytest.fixture
def otp(make_otp):
    """otp(counter, session): an OTP of the credential fixture."""
    return lambda counter, session=0, **kw: parse_otp(
        make_otp(
            "vvccccbbcdef",
            kw.get("private_id", PRIVATE_ID),
            kw.get("aes_key", K1),
            counter,
            session,
        )
    )


def counters(credential: YubikeyCredential) -> tuple[int, int]:
    stored = YubikeyCredential.objects.get(pk=credential.pk)
    return stored.last_usage_counter, stored.last_session_counter


# Finding the credential


def test_find_credential(credential):
    assert find_credential(credential.user, "vvccccbbcdef") == credential


def test_unknown_public_id(credential, rejected):
    with rejected(Rejection.UNKNOWN_KEY):
        find_credential(credential.user, "vvccccbbcdeg")


def test_another_users_key(credential, make_user, rejected):
    with rejected(Rejection.OTHER_USERS_KEY):
        find_credential(make_user(), "vvccccbbcdef")


def test_disabled_key(make_credential, rejected):
    credential = make_credential(public_id="vvccccbbcdef", enabled=False)
    with rejected(Rejection.DISABLED_KEY):
        find_credential(credential.user, "vvccccbbcdef")


# Accepting an OTP


def test_accept_saves_the_counters(credential, otp):
    before = timezone.now()
    token = accept_otp(credential, otp(3, 1))
    assert (token.usage_counter, token.session_counter) == (3, 1)
    assert counters(credential) == (3, 1)
    assert (credential.last_usage_counter, credential.last_session_counter) == (3, 1)
    stored = YubikeyCredential.objects.get(pk=credential.pk)
    assert stored.last_used_at is not None
    assert before <= stored.last_used_at <= timezone.now() + timedelta(seconds=1)
    assert credential.last_used_at == stored.last_used_at


def test_the_same_otp_is_accepted_once(credential, otp, rejected):
    accept_otp(credential, otp(3, 1))
    with rejected(Rejection.REPLAYED):
        accept_otp(credential, otp(3, 1))
    with rejected(Rejection.REPLAYED):
        accept_otp(YubikeyCredential.objects.get(pk=credential.pk), otp(3, 1))


def test_counter_sequence(credential, otp, rejected):
    accept_otp(credential, otp(3, 1))
    with rejected(Rejection.REPLAYED):
        accept_otp(credential, otp(2, 9))  # an older session
    accept_otp(credential, otp(3, 2))  # next in the session
    accept_otp(credential, otp(0x8005, 0))  # 5: the top bit is ignored
    assert counters(credential) == (5, 0)


@pytest.mark.parametrize(
    ("kw", "reason"),
    [
        ({"aes_key": K2}, Rejection.BAD_CRC),
        ({"private_id": "111111111111"}, Rejection.PRIVATE_ID_MISMATCH),
    ],
)
def test_rejected_otps_leave_the_counters(credential, otp, rejected, kw, reason):
    with rejected(reason):
        accept_otp(credential, otp(9, 0, **kw))
    assert counters(credential) == (0, 0)
    assert YubikeyCredential.objects.get(pk=credential.pk).last_used_at is None


def test_a_newer_otp_saved_meanwhile_wins(credential, otp, rejected):
    stale = YubikeyCredential.objects.get(pk=credential.pk)
    accept_otp(credential, otp(3, 1))
    # stale still has counters 0/0, so its own check passes; the UPDATE doesn't.
    with rejected(Rejection.REPLAYED):
        accept_otp(stale, otp(3, 1))
    assert counters(credential) == (3, 1)


def test_a_key_disabled_meanwhile_is_refused(credential, otp, rejected):
    YubikeyCredential.objects.filter(pk=credential.pk).update(enabled=False)
    with rejected(Rejection.REPLAYED):
        accept_otp(credential, otp(3, 1))
    assert counters(credential) == (0, 0)


def test_the_otp_must_be_for_the_credential(credential, make_otp):
    with pytest.raises(ValueError, match="another credential"):
        accept_otp(credential, parse_otp(make_otp("vvccccbbcdeg", PRIVATE_ID, K1, 3)))


def test_a_damaged_stored_secret_is_a_server_fault(credential, otp):
    blob = bytearray(credential.encrypted_aes_secret)
    blob[-1] ^= 1
    credential.encrypted_aes_secret = bytes(blob)
    with pytest.raises(DecryptionError):
        accept_otp(credential, otp(3, 1))


@pytest.mark.skipif(
    os.environ.get("YK_PORTAL_TEST_DATABASE") != "postgresql",
    reason="concurrent writers need PostgreSQL (in-memory SQLite serializes them)",
)
@pytest.mark.django_db(transaction=True)
def test_the_same_otp_submitted_at_once_is_accepted_once(make_credential, make_otp):
    """Spec §48: exactly one of simultaneous logins with the same OTP succeeds."""
    credential = make_credential(public_id="vvccccbbcdef", private_id=PRIVATE_ID, aes_key=K1)
    text = make_otp("vvccccbbcdef", PRIVATE_ID, K1, 7, 3)
    threads = 8
    barrier = threading.Barrier(threads)
    results: list[str] = []

    def login() -> None:
        try:
            mine = YubikeyCredential.objects.get(pk=credential.pk)
            barrier.wait()
            accept_otp(mine, parse_otp(text))
            results.append("accepted")
        except OtpRejected as e:
            results.append(e.reason)
        finally:
            connections.close_all()

    workers = [threading.Thread(target=login) for _ in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert sorted(results) == ["accepted"] + [Rejection.REPLAYED] * (threads - 1)
    assert counters(credential) == (7, 3)
    assert connection.vendor == "postgresql"
