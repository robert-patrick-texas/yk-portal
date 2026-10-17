import pytest
from django.core.exceptions import ValidationError

from yk_portal.accounts import services
from yk_portal.accounts.models import AccountState, User
from yk_portal.accounts.onboarding import (
    finish_with_new_yubikey,
    finish_with_otp,
    needs_new_yubikey,
)
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.audit.service import Actor
from yk_portal.authentication.login import LoginFailed, log_in
from yk_portal.authentication.passwords import check_web_password
from yk_portal.authentication.sessions import Client
from yk_portal.core import sha512_crypt
from yk_portal.yubikeys.management import NewYubikey, add_yubikey
from yk_portal.yubikeys.models import ProvisioningMethod, YubikeyCredential
from yk_portal.yubikeys.otp import OtpRejected

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("master_key")]

PIN = "Passw0rd!"
PUBLIC_ID = "vvccccbbcdef"
PRIVATE_ID = "4a6f8e2d1c3b"
K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"
K2 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
KEY = NewYubikey(PUBLIC_ID, bytes.fromhex(PRIVATE_ID), bytes.fromhex(K1), "primary", 2)
CLIENT = Client("192.0.2.10", "pytest")


@pytest.fixture
def otp(make_otp):
    return lambda counter, session=0, aes_key=K1: make_otp(
        PUBLIC_ID, PRIVATE_ID, aes_key, counter, session
    )


@pytest.fixture
def newcomer(actor):
    """A new account with its email address set."""
    user = services.create_user("nina", actor).user
    services.set_email(user, "nina@example.com", Actor.for_user(user))
    return user


def code_of(excinfo: pytest.ExceptionInfo[ValidationError]) -> str | None:
    return excinfo.value.error_list[0].code


# Email (spec §24)


def test_set_email_audits_the_change_not_the_address(make_user, actor):
    user = make_user()
    services.set_email(user, " nina@example.com ", actor)
    assert user.email == "nina@example.com"
    services.set_email(user, "nina@example.com", actor)  # unchanged: no event
    event = AuditEvent.objects.get()
    assert event.event_type == EventType.ACCOUNT_UPDATED
    assert event.details == {"changed": ["email"]}


def test_set_email_checks_the_address(make_user, actor):
    with pytest.raises(ValidationError):
        services.set_email(make_user(), "not-an-address", actor)


# Self-provisioning (spec §13.2)


def test_self_provisioning(newcomer, otp):
    assert needs_new_yubikey(newcomer)
    finish_with_new_yubikey(newcomer, KEY, otp(1, 0), PIN, Actor.for_user(newcomer))
    user = User.objects.get(pk=newcomer.pk)
    assert user.state == AccountState.ACTIVE
    assert user.temporary_password_hash == ""
    assert user.temporary_password_expires_at is None
    credential = YubikeyCredential.objects.get(user=user)
    assert credential.provisioning_method == ProvisioningMethod.SELF_PROVISIONED
    assert (credential.last_usage_counter, credential.last_session_counter) == (1, 0)
    assert check_web_password(PIN, credential.pin_hash)
    assert sha512_crypt.check_hash(PIN, credential.radius_pin_hash)
    completed = AuditEvent.objects.get(event_type=EventType.PROVISIONING_COMPLETED)
    assert completed.details == {"old_state": "PROVISIONING", "new_state": "ACTIVE"}


def test_after_onboarding_the_pin_and_otp_sign_in(newcomer, actor, otp):
    temporary = services.set_temporary_password(newcomer, actor)
    # The temporary password works until onboarding completes (addendum §2.11).
    log_in("nina", temporary, CLIENT)
    finish_with_new_yubikey(newcomer, KEY, otp(1, 0), PIN, Actor.for_user(newcomer))
    with pytest.raises(LoginFailed):
        log_in("nina", temporary, CLIENT)
    log_in("nina", PIN + otp(1, 1), CLIENT)


def test_email_comes_first(newcomer, otp):
    User.objects.filter(pk=newcomer.pk).update(email="")
    newcomer.refresh_from_db()
    with pytest.raises(ValidationError) as excinfo:
        finish_with_new_yubikey(newcomer, KEY, otp(1, 0), PIN, Actor.for_user(newcomer))
    assert code_of(excinfo) == "no_email"
    assert not YubikeyCredential.objects.exists()
    assert User.objects.get(pk=newcomer.pk).state == AccountState.PROVISIONING


def test_a_pin_that_breaks_the_policy_adds_nothing(newcomer, otp):
    with pytest.raises(ValidationError):
        finish_with_new_yubikey(newcomer, KEY, otp(1, 0), "short1", Actor.for_user(newcomer))
    assert not YubikeyCredential.objects.exists()


def test_a_wrong_otp_adds_nothing_and_finishes_nothing(newcomer, otp):
    with pytest.raises(ValidationError):
        finish_with_new_yubikey(newcomer, KEY, otp(1, 0, aes_key=K2), PIN, Actor.for_user(newcomer))
    assert not YubikeyCredential.objects.exists()
    assert User.objects.get(pk=newcomer.pk).state == AccountState.PROVISIONING


# Admin-provisioned (VIP) accounts (spec §14; addendum §13 item 12)


@pytest.fixture
def vip(newcomer, make_user):
    admin = Actor.for_user(make_user("boss", admin=True))
    add_yubikey(newcomer, admin, KEY, ProvisioningMethod.ADMIN_PROVISIONED)
    return newcomer


def test_vip_tests_the_pre_provisioned_key_and_chooses_its_pin(vip, otp):
    assert not needs_new_yubikey(vip)
    assert not YubikeyCredential.objects.get(user=vip).has_pin
    credential = finish_with_otp(vip, otp(1, 0), PIN, Actor.for_user(vip))
    assert credential.public_id == PUBLIC_ID
    assert User.objects.get(pk=vip.pk).state == AccountState.ACTIVE
    credential.refresh_from_db()
    assert (credential.last_usage_counter, credential.last_session_counter) == (1, 0)
    assert check_web_password(PIN, credential.pin_hash)
    log_in("nina", PIN + otp(1, 1), CLIENT)


def test_vip_with_a_bad_otp_stays_provisioning(vip, otp):
    with pytest.raises(OtpRejected):
        finish_with_otp(vip, otp(1, 0, aes_key=K2), PIN, Actor.for_user(vip))
    user = User.objects.get(pk=vip.pk)
    assert user.state == AccountState.PROVISIONING
    assert user.failed_login_count == 0
    assert not YubikeyCredential.objects.get(user=vip).has_pin


def test_vip_with_a_bad_pin_leaves_the_otp_unused(vip, otp):
    with pytest.raises(ValidationError):
        finish_with_otp(vip, otp(1, 0), "short1", Actor.for_user(vip))
    finish_with_otp(vip, otp(1, 0), PIN, Actor.for_user(vip))


def test_complete_provisioning_only_from_provisioning(make_user, actor):
    with pytest.raises(ValidationError) as excinfo:
        services.complete_provisioning(make_user(email="a@example.com"), actor)
    assert code_of(excinfo) == "invalid_state"


def test_complete_provisioning_needs_an_enabled_key_with_a_pin(newcomer, actor, make_credential):
    with pytest.raises(ValidationError) as excinfo:
        services.complete_provisioning(newcomer, actor)
    assert code_of(excinfo) == "no_yubikey"
    make_credential(newcomer, pin_hash="", radius_pin_hash="")
    with pytest.raises(ValidationError) as excinfo:
        services.complete_provisioning(newcomer, actor)
    assert code_of(excinfo) == "no_yubikey"


# Reset to provisioning disables YubiKeys (spec §15)


def test_reset_disables_yubikeys(make_user, make_credential, actor):
    user = make_user("erin")
    keys = [make_credential(user), make_credential(user), make_credential(user, enabled=False)]
    services.reset_to_provisioning(user, actor)
    assert not YubikeyCredential.objects.filter(user=user, enabled=True).exists()
    assert YubikeyCredential.objects.filter(user=user).count() == 3  # kept, for admins to see
    event = AuditEvent.objects.get(event_type=EventType.YUBIKEY_DISABLED)
    assert event.details == {
        "public_ids": sorted(k.public_id for k in keys[:2]),
        "reason": "reset to provisioning",
    }
    assert needs_new_yubikey(user)
