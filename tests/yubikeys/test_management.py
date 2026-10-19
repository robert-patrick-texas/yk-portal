from datetime import UTC, datetime

import pytest
from django.core.exceptions import PermissionDenied, ValidationError

from yk_portal.accounts.models import AccountState
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.audit.service import Actor
from yk_portal.authentication.models import Session
from yk_portal.authentication.passwords import PinHashes, check_web_password
from yk_portal.authentication.sessions import Client, start_session
from yk_portal.core import sha512_crypt
from yk_portal.portal_settings import service as portal_settings
from yk_portal.yubikeys import management
from yk_portal.yubikeys.management import NewYubikey
from yk_portal.yubikeys.models import ProvisioningMethod, YubikeyCredential
from yk_portal.yubikeys.otp import OtpRejected, Rejection

pytestmark = pytest.mark.usefixtures("master_key")

PUBLIC_ID = "vvccccbbcdef"
PRIVATE_ID = "4a6f8e2d1c3b"
K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"
K2 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
SELF = ProvisioningMethod.SELF_PROVISIONED
ADMIN = ProvisioningMethod.ADMIN_PROVISIONED
PIN = "Passw0rd!"
PIN_HASHES = PinHashes(web="argon2$test", radius="{crypt}$6$test")
MIGRATED = ProvisioningMethod.MIGRATED


def new_key(
    public_id: str = PUBLIC_ID, private_id: str = PRIVATE_ID, label: str = "", slot: int | None = 2
) -> NewYubikey:
    return NewYubikey(
        public_id=public_id,
        private_id=bytes.fromhex(private_id),
        aes_key=bytes.fromhex(K1),
        label=label,
        slot=slot,
    )


def code_of(excinfo: pytest.ExceptionInfo[ValidationError]) -> str | None:
    return excinfo.value.error_list[0].code


@pytest.fixture
def user(make_user):
    return make_user("alice")


@pytest.fixture
def otp(make_otp):
    return lambda counter, session=0, **kw: make_otp(
        kw.get("public_id", PUBLIC_ID),
        kw.get("private_id", PRIVATE_ID),
        kw.get("aes_key", K1),
        counter,
        session,
    )


# Typed secrets


@pytest.mark.parametrize(
    "text", ["4a6f8e2d1c3b", "4A6F8E2D1C3B", "4a 6f 8e 2d 1c 3b", "4a:6f:8e:2d:1c:3b"]
)
def test_parse_private_id(text):
    assert management.parse_private_id(text) == bytes.fromhex("4a6f8e2d1c3b")


@pytest.mark.parametrize("text", ["", "4a6f8e2d1c", "4a6f8e2d1c3b00", "4a6f8e2d1c3g"])
def test_invalid_private_ids(text):
    with pytest.raises(ValidationError, match="12 hex characters"):
        management.parse_private_id(text)


def test_parse_aes_key():
    assert management.parse_aes_key(K1.upper()) == bytes.fromhex(K1)
    with pytest.raises(ValidationError, match="32 hex characters"):
        management.parse_aes_key(K1[:-1])


# Adding


def test_self_provisioned_key_is_proven_by_its_otp(user, actor, otp):
    credential = management.add_yubikey(
        user, actor, new_key(label="primary"), SELF, otp(7, 3), PIN_HASHES
    )
    assert credential.user == user
    assert credential.public_id == PUBLIC_ID
    assert credential.private_id() == bytes.fromhex(PRIVATE_ID)
    assert credential.aes_key() == bytes.fromhex(K1)
    assert (credential.last_usage_counter, credential.last_session_counter) == (7, 3)
    assert credential.last_used_at is not None
    assert credential.provisioning_method == SELF
    assert (credential.pin_hash, credential.radius_pin_hash) == ("argon2$test", "{crypt}$6$test")
    assert credential.slot_number == 2
    event = AuditEvent.objects.get()
    assert event.event_type == EventType.YUBIKEY_ADDED
    assert event.details == {
        "public_id": PUBLIC_ID,
        "label": "primary",
        "slot": 2,
        "method": SELF,
        "tested": True,
    }
    assert PRIVATE_ID not in str(event.details) and K1 not in str(event.details)


def test_the_same_otp_doesnt_work_again_after_adding(user, actor, otp):
    credential = management.add_yubikey(user, actor, new_key(), SELF, otp(7, 3), PIN_HASHES)
    with pytest.raises(OtpRejected) as excinfo:
        management.check_yubikey(user, otp(7, 3))
    assert excinfo.value.reason == Rejection.REPLAYED
    assert management.check_yubikey(user, otp(7, 4)) == credential


def test_admin_pre_provisioning_needs_no_otp(user, make_user):
    admin = make_user("boss", admin=True)
    credential = management.add_yubikey(user, Actor.for_user(admin), new_key(), ADMIN)
    assert (credential.last_usage_counter, credential.last_session_counter) == (0, 0)
    assert credential.last_used_at is None
    assert credential.created_by == admin
    assert not credential.has_pin  # its owner chooses it
    assert AuditEvent.objects.get().details["tested"] is False


def test_self_provisioning_needs_an_otp_and_a_pin(user, actor, otp):
    with pytest.raises(ValueError, match="a test OTP and a PIN"):
        management.add_yubikey(user, actor, new_key(), SELF, pin=PIN_HASHES)
    with pytest.raises(ValueError, match="a test OTP and a PIN"):
        management.add_yubikey(user, actor, new_key(), SELF, otp(1))


def test_migrated_key_keeps_its_state_counters_and_times(user, actor):
    created = datetime(2025, 1, 2, 3, 4, 5, tzinfo=UTC)
    used = datetime(2026, 5, 6, 7, 8, 9, tzinfo=UTC)
    migrated = management.Migrated("test", False, 12, 3, created, used)
    credential = management.add_yubikey(
        user, actor, new_key(slot=None), MIGRATED, migrated=migrated
    )
    stored = YubikeyCredential.objects.get(pk=credential.pk)
    assert stored.provisioning_method == MIGRATED
    assert stored.migration_source == "test"
    assert not stored.enabled
    assert (stored.last_usage_counter, stored.last_session_counter) == (12, 3)
    assert (stored.created_at, stored.last_used_at) == (created, used)
    assert stored.slot_number is None
    assert AuditEvent.objects.get().details == {
        "public_id": PUBLIC_ID,
        "label": "",
        "slot": None,
        "method": MIGRATED,
        "tested": False,
        "enabled": False,
        "source": "test",
    }


def test_migrated_key_without_times_gets_the_current_one(user, actor):
    migrated = management.Migrated("test", True, 0, 0)
    credential = management.add_yubikey(user, actor, new_key(), MIGRATED, migrated=migrated)
    assert credential.created_at is not None
    assert credential.last_used_at is None


def test_only_migrated_keys_take_a_migrated_state(user, actor):
    with pytest.raises(ValueError, match="migrated state"):
        management.add_yubikey(user, actor, new_key(), MIGRATED)
    with pytest.raises(ValueError, match="migrated state"):
        management.add_yubikey(
            user, actor, new_key(), ADMIN, migrated=management.Migrated("test", True, 0, 0)
        )


@pytest.mark.parametrize(
    ("make", "code"),
    [
        (lambda otp: "not an otp", "malformed_otp"),
        (lambda otp: otp(3, public_id="vvccccbbcdeg"), "wrong_public_id"),
        (lambda otp: otp(3, aes_key=K2), "wrong_aes_key"),
        (lambda otp: otp(3, private_id="111111111111"), "wrong_private_id"),
    ],
)
def test_an_otp_that_doesnt_fit_adds_nothing(user, actor, otp, make, code):
    with pytest.raises(ValidationError) as excinfo:
        management.add_yubikey(user, actor, new_key(), SELF, make(otp), PIN_HASHES)
    assert code_of(excinfo) == code
    assert not YubikeyCredential.objects.exists()
    assert not AuditEvent.objects.exists()


def test_public_id_is_normalized(user, actor, otp):
    credential = management.add_yubikey(
        user, actor, new_key(public_id=" VVCCCCBBCDEF "), SELF, otp(1), PIN_HASHES
    )
    assert credential.public_id == PUBLIC_ID


def test_public_ids_are_unique_across_users(user, actor, make_user, make_credential):
    make_credential(make_user("bob"), public_id=PUBLIC_ID)
    with pytest.raises(ValidationError) as excinfo:
        management.add_yubikey(user, actor, new_key(), ADMIN)
    assert code_of(excinfo) == "public_id_taken"


def test_private_ids_are_unique_across_users(user, actor, make_user, make_credential):
    make_credential(make_user("bob"), public_id="vvccccbbcdeg", private_id=PRIVATE_ID)
    with pytest.raises(ValidationError) as excinfo:
        management.add_yubikey(user, actor, new_key(), ADMIN)
    assert code_of(excinfo) == "private_id_taken"


def test_the_maximum_counts_disabled_keys(user, actor, make_credential):
    portal_settings.update({"max_yubikeys_per_user": 2}, actor)
    make_credential(user)
    make_credential(user, enabled=False)
    with pytest.raises(ValidationError) as excinfo:
        management.add_yubikey(user, actor, new_key(), ADMIN)
    assert code_of(excinfo) == "too_many_yubikeys"
    assert "at most 2" in excinfo.value.messages[0]


@pytest.mark.parametrize(
    ("key", "code"),
    [
        (new_key(public_id="vvccccbbcde"), "invalid_public_id"),
        (new_key(label="a\tb"), "invalid_label"),
        # SQLite would store it; PostgreSQL would refuse it (addendum §18.3).
        (new_key(label="x" * 256), "label_too_long"),
        (new_key(slot=3), "invalid_slot"),
    ],
)
def test_values_are_checked(user, actor, key, code):
    with pytest.raises(ValidationError) as excinfo:
        management.add_yubikey(user, actor, key, ADMIN)
    assert code_of(excinfo) == code


# PINs (addendum §2.2, §2.15)


def test_set_pin_gives_each_key_its_own_salts(user, actor, make_credential):
    keys = [make_credential(user), make_credential(user)]
    management.set_pin(user, keys, PIN, actor)
    for key in keys:
        key.refresh_from_db()
        assert check_web_password(PIN, key.pin_hash)
        assert sha512_crypt.check_hash(PIN, key.radius_pin_hash)
    assert keys[0].radius_pin_hash != keys[1].radius_pin_hash
    event = AuditEvent.objects.get()
    assert event.event_type == EventType.PASSWORD_CHANGED
    assert event.details == {"public_ids": sorted(k.public_id for k in keys)}


def test_set_pin_applies_the_policy(user, actor, make_credential):
    key = make_credential(user)
    with pytest.raises(ValidationError):
        management.set_pin(user, [key], "short1", actor)
    assert not AuditEvent.objects.exists()


def test_set_pin_only_on_the_users_keys(user, actor, make_user, make_credential):
    with pytest.raises(ValueError, match="not one of alice's YubiKeys"):
        management.set_pin(user, [make_credential(make_user("bob"))], PIN, actor)


@pytest.fixture
def two_keys(user, make_credential):
    return (
        make_credential(user, public_id=PUBLIC_ID, private_id=PRIVATE_ID, aes_key=K1),
        make_credential(user, pin_hash="", radius_pin_hash=""),
    )


def test_change_pin_with_an_otp_from_the_key(user, actor, otp, two_keys):
    first, second = two_keys
    management.change_pin(first, actor, PIN, otp(5))
    assert check_web_password(PIN, first.pin_hash)
    assert (first.last_usage_counter, first.last_session_counter) == (5, 0)
    second.refresh_from_db()
    assert not second.has_pin


def test_change_pin_everywhere(user, actor, otp, two_keys):
    first, second = two_keys
    management.change_pin(first, actor, PIN, otp(5), everywhere=True)
    second.refresh_from_db()
    assert check_web_password(PIN, second.pin_hash)
    assert AuditEvent.objects.get().details == {"public_ids": sorted(k.public_id for k in two_keys)}


def test_change_pin_needs_an_otp_from_that_key(user, actor, otp, two_keys, rejected):
    first, second = two_keys
    with pytest.raises(ValidationError) as excinfo:
        management.change_pin(second, actor, PIN, otp(5))
    assert code_of(excinfo) == "other_yubikey"
    with rejected(Rejection.BAD_CRC):
        management.change_pin(first, actor, PIN, otp(5, aes_key=K2))
    management.change_pin(first, actor, PIN, otp(5))
    with rejected(Rejection.REPLAYED):
        management.change_pin(first, actor, PIN, otp(5))
    assert not AuditEvent.objects.filter(event_type=EventType.LOGIN_FAILURE).exists()


def test_a_pin_that_breaks_the_policy_leaves_the_otp_unused(user, actor, otp, two_keys):
    first, _ = two_keys
    with pytest.raises(ValidationError):
        management.change_pin(first, actor, "short1", otp(5))
    management.change_pin(first, actor, PIN, otp(5))


# Testing, editing, disabling, removing


def test_check_yubikey_failures_dont_count(user, make_credential, otp):
    make_credential(user, public_id=PUBLIC_ID, private_id=PRIVATE_ID, aes_key=K1)
    with pytest.raises(OtpRejected):
        management.check_yubikey(user, otp(3, aes_key=K2))
    user.refresh_from_db()
    assert user.failed_login_count == 0


def test_update_yubikey(user, actor, make_credential):
    credential = make_credential(user, label="old", slot_number=1)
    management.update_yubikey(credential, actor, "new", 2)
    assert (credential.label, credential.slot_number) == ("new", 2)
    management.update_yubikey(credential, actor, "new", 2)  # unchanged: no event
    assert [e.details for e in AuditEvent.objects.all()] == [
        {
            "public_id": credential.public_id,
            "old_label": "old",
            "new_label": "new",
            "old_slot": 1,
            "new_slot": 2,
        }
    ]


def test_update_yubikey_checks_the_label(user, actor, make_credential):
    credential = make_credential(user)
    management.update_yubikey(credential, actor, "x" * 255, 2)
    with pytest.raises(ValidationError) as excinfo:
        management.update_yubikey(credential, actor, "x" * 256, 2)
    assert code_of(excinfo) == "label_too_long"


def test_disable_and_enable(user, actor, make_credential):
    make_credential(user)
    credential = make_credential(user)
    management.set_yubikey_enabled(credential, actor, False)
    assert not credential.enabled
    management.set_yubikey_enabled(credential, actor, False)  # already: no event
    management.set_yubikey_enabled(credential, actor, True)
    assert credential.enabled
    assert list(AuditEvent.objects.order_by("timestamp").values_list("event_type", flat=True)) == [
        EventType.YUBIKEY_DISABLED,
        EventType.YUBIKEY_ENABLED,
    ]


@pytest.mark.parametrize("change", ["disable", "remove"])
def test_users_keep_their_last_enabled_key(user, actor, make_credential, change):
    make_credential(user, enabled=False)
    credential = make_credential(user)
    with pytest.raises(ValidationError) as excinfo:
        if change == "disable":
            management.set_yubikey_enabled(credential, actor, False)
        else:
            management.remove_yubikey(credential, actor)
    assert code_of(excinfo) == "last_yubikey"
    credential.refresh_from_db()
    assert credential.enabled


def test_admins_may_take_the_last_key(user, actor, make_credential):
    credential = make_credential(user)
    management.set_yubikey_enabled(credential, actor, False, allow_last=True)
    management.remove_yubikey(credential, actor, allow_last=True)
    assert not YubikeyCredential.objects.exists()


def test_a_provisioning_accounts_keys_can_go(make_user, actor, make_credential):
    credential = make_credential(make_user(state=AccountState.PROVISIONING))
    management.remove_yubikey(credential, actor)
    assert not YubikeyCredential.objects.exists()


def test_a_disabled_key_can_be_removed(user, actor, make_credential):
    make_credential(user)
    credential = make_credential(user, enabled=False, label="lost")
    management.remove_yubikey(credential, actor)
    event = AuditEvent.objects.get()
    assert event.event_type == EventType.YUBIKEY_REMOVED
    assert event.details == {"public_id": credential.public_id, "label": "lost"}


# Revealing secrets (spec §20.2)


def test_admins_reveal_secrets_with_an_audit_event(user, make_user, make_credential):
    credential = make_credential(user, private_id=PRIVATE_ID, aes_key=K1)
    admin = Actor.for_user(make_user("boss", admin=True))
    assert management.reveal_private_id(credential, admin, step_up=True) == PRIVATE_ID
    assert management.reveal_aes_key(credential, admin, step_up=False) == K1
    events = AuditEvent.objects.order_by("timestamp")
    public_id = credential.public_id
    assert [(e.event_type, e.details) for e in events] == [
        (EventType.YUBIKEY_PRIVATE_ID_REVEALED, {"public_id": public_id, "step_up": True}),
        (EventType.YUBIKEY_AES_SECRET_REVEALED, {"public_id": public_id, "step_up": False}),
    ]


@pytest.mark.parametrize("who", ["user", "cli"])
def test_only_admins_reveal_secrets(user, actor, make_credential, who):
    credential = make_credential(user)
    reveal_as = Actor.for_user(user) if who == "user" else actor
    with pytest.raises(PermissionDenied):
        management.reveal_private_id(credential, reveal_as, step_up=True)
    with pytest.raises(PermissionDenied):
        management.reveal_aes_key(credential, reveal_as, step_up=True)
    assert not AuditEvent.objects.exists()


# Admins set PINs without an OTP (addendum §2.16)


def test_admin_set_pin(user, make_user, two_keys):
    admin = make_user("boss", admin=True)
    first, second = two_keys
    users_sessions = [start_session(user, Client("127.0.0.1", "pytest"))[0] for _ in range(2)]
    admins_session, _ = start_session(admin, Client("127.0.0.1", "pytest"))
    management.admin_set_pin(second, Actor.for_user(admin), PIN, keep=admins_session)
    assert check_web_password(PIN, second.pin_hash)
    assert sha512_crypt.check_hash(PIN, second.radius_pin_hash)
    first.refresh_from_db()
    assert first.pin_hash == "argon2$dummy"  # unchanged
    audit = AuditEvent.objects.get()
    assert (audit.event_type, audit.actor_username_snapshot) == (EventType.PASSWORD_CHANGED, "boss")
    assert (audit.target_user_id, audit.details) == (user.pk, {"public_ids": [second.public_id]})
    # Every session of the owner ends; the owner isn't asked to change the PIN.
    assert all(Session.objects.get(pk=s.pk).revoked_at for s in users_sessions)
    assert Session.objects.get(pk=admins_session.pk).revoked_at is None


def test_admin_set_pin_everywhere(user, actor, two_keys):
    management.admin_set_pin(two_keys[0], actor, PIN, everywhere=True)
    for key in YubikeyCredential.objects.filter(user=user):
        assert check_web_password(PIN, key.pin_hash)


def test_admins_set_their_own_pin_keeping_their_session(user, two_keys):
    current, _ = start_session(user, Client("127.0.0.1", "pytest"))
    other, _ = start_session(user, Client("127.0.0.1", "pytest"))
    management.admin_set_pin(two_keys[0], Actor.for_user(user), PIN, keep=current)
    assert Session.objects.get(pk=current.pk).revoked_at is None
    assert Session.objects.get(pk=other.pk).revoked_at is not None


def test_admin_set_pin_applies_the_policy(user, actor, two_keys):
    session, _ = start_session(user, Client("127.0.0.1", "pytest"))
    with pytest.raises(ValidationError):
        management.admin_set_pin(two_keys[1], actor, "short")
    assert not YubikeyCredential.objects.get(pk=two_keys[1].pk).has_pin
    assert Session.objects.get(pk=session.pk).revoked_at is None
    assert not AuditEvent.objects.exists()
