"""The admin pages for any account's YubiKeys (spec §14, §20, §34; addendum §2.16, §6.6)."""

import re

import pytest
from django.urls import reverse

from yk_portal.accounts.models import AccountState, User
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.authentication.models import Session
from yk_portal.authentication.passwords import check_web_password
from yk_portal.authentication.sessions import COOKIE, start_session
from yk_portal.authentication.sessions import Client as SessionClient
from yk_portal.portal_settings import service as portal_settings
from yk_portal.yubikeys.models import ProvisioningMethod, YubikeyCredential

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("master_key")]

PIN = "Passw0rd!"
K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"
K2 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
# root's own YubiKey, for the step-up.
ROOT_PUBLIC_ID = "vvccccbbcdeh"
ROOT_PRIVATE_ID = "0a0b0c0d0e0f"
# A YubiKey the admin pre-provisions for alice.
PUBLIC_ID = "vvccccbbcdef"
PRIVATE_ID = "4a6f8e2d1c3b"


def signed_in(client, user: User) -> Session:
    session, token = start_session(user, SessionClient("127.0.0.1", "pytest"))
    client.cookies[COOKIE] = token
    return session


def page(response) -> str:
    assert response.status_code == 200, response.status_code
    return response.content.decode()


@pytest.fixture
def root(client, make_user, make_credential):
    """An ACTIVE admin with a YubiKey and its PIN, signed in."""
    user = make_user("root", admin=True)
    make_credential(user, public_id=ROOT_PUBLIC_ID, private_id=ROOT_PRIVATE_ID, pin=PIN)
    signed_in(client, user)
    return user


@pytest.fixture
def step_up(make_otp):
    """step_up(counter): root's PIN and a fresh OTP from root's YubiKey."""
    return lambda counter: PIN + make_otp(ROOT_PUBLIC_ID, ROOT_PRIVATE_ID, K1, counter)


@pytest.fixture
def alice(make_user, make_credential):
    user = make_user("alice")
    make_credential(user, public_id="vvccccbbcdeg", private_id="0102030405a6", label="keyring")
    return user


@pytest.fixture
def key(alice):
    return YubikeyCredential.objects.get(user=alice)


def url(name: str, credential: YubikeyCredential) -> str:
    return reverse(name, args=[credential.user.pk, credential.pk])


# Pre-provisioning (spec §14)


def key_form(**overrides: str) -> dict[str, str]:
    data = {
        "public_id": PUBLIC_ID,
        "private_id": PRIVATE_ID,
        "aes_key": K1,
        "label": "VIP",
        "slot": "",
        "otp": "",
    }
    return data | overrides


def test_pre_provision_without_the_yubikey(client, root, alice):
    add = reverse("admin-yubikey-add", args=[alice.pk])
    html = page(client.get(add))
    assert "chooses its PIN" in html and 'name="pin"' not in html
    response = client.post(add, key_form())
    assert response.headers["Location"] == reverse("admin-user", args=[alice.pk])
    credential = YubikeyCredential.objects.get(public_id=PUBLIC_ID)
    assert credential.user == alice and credential.created_by == root
    assert credential.provisioning_method == ProvisioningMethod.ADMIN_PROVISIONED
    assert credential.slot_number is None and not credential.has_pin
    assert credential.private_id().hex() == PRIVATE_ID
    audit = AuditEvent.objects.get(event_type=EventType.YUBIKEY_ADDED)
    assert audit.details["tested"] is False


def test_pre_provision_with_a_test_otp(client, root, alice, make_otp):
    add = reverse("admin-yubikey-add", args=[alice.pk])
    html = page(client.post(add, key_form(otp=make_otp(PUBLIC_ID, PRIVATE_ID, K2, 7))))
    assert "doesn&#x27;t decrypt with this AES key" in html
    assert PRIVATE_ID not in html and K1 not in html  # secrets are never sent back
    client.post(add, key_form(slot="2", otp=make_otp(PUBLIC_ID, PRIVATE_ID, K1, 7, 3)))
    credential = YubikeyCredential.objects.get(public_id=PUBLIC_ID)
    assert (credential.last_usage_counter, credential.last_session_counter) == (7, 3)
    assert credential.slot_number == 2


def test_pre_provision_stops_at_the_maximum(client, root, alice, actor):
    portal_settings.update({"max_yubikeys_per_user": 1}, actor)
    html = page(client.get(reverse("admin-user", args=[alice.pk])))
    assert "Add a YubiKey" not in html and "the most YubiKeys" in html
    html = page(client.post(reverse("admin-yubikey-add", args=[alice.pk]), key_form()))
    assert "An account can have at most 1 YubiKeys." in html


# Edit, PIN, disable, remove (spec §20; addendum §2.16, §14.3)


def test_edit(client, root, key):
    response = client.post(url("admin-yubikey-edit", key), {"label": "spare", "slot": "1"})
    assert response.headers["Location"] == reverse("admin-user", args=[key.user.pk])
    key.refresh_from_db()
    assert (key.label, key.slot_number) == ("spare", 1)


def test_set_a_pin_without_an_otp(client, root, alice, key):
    sessions = [start_session(alice, SessionClient("127.0.0.1", "x"))[0] for _ in range(2)]
    html = page(client.get(url("admin-yubikey-pin", key)))
    assert "Use this PIN on all of alice’s YubiKeys" in html and 'name="otp"' not in html
    response = client.post(url("admin-yubikey-pin", key), {"pin": PIN, "confirm": PIN})
    assert response.headers["Location"] == reverse("admin-user", args=[alice.pk])
    key.refresh_from_db()
    assert check_web_password(PIN, key.pin_hash)
    # All of alice's sessions end (addendum §2.16); root stays signed in.
    assert all(Session.objects.get(pk=s.pk).revoked_at for s in sessions)
    assert client.get(reverse("admin-users")).status_code == 200
    audit = AuditEvent.objects.get(event_type=EventType.PASSWORD_CHANGED)
    assert audit.actor_username_snapshot == "root" and audit.target_username_snapshot == "alice"


def test_a_pin_on_all_the_owners_keys(client, root, alice, key, make_credential):
    other = make_credential(alice, pin_hash="", radius_pin_hash="")
    client.post(url("admin-yubikey-pin", key), {"pin": PIN, "confirm": PIN, "everywhere": "on"})
    other.refresh_from_db()
    assert check_web_password(PIN, other.pin_hash)


def test_the_pin_policy_applies(client, root, key):
    html = page(client.post(url("admin-yubikey-pin", key), {"pin": "short", "confirm": "short"}))
    assert "Use at least 8 characters." in html and "short" not in html.split("</h1>")[1]
    key.refresh_from_db()
    assert key.pin_hash == "argon2$dummy"


def test_admins_may_disable_the_last_key(client, root, key):
    assert client.get(url("admin-yubikey-disable", key)).status_code == 405
    client.post(url("admin-yubikey-disable", key))
    key.refresh_from_db()
    assert not key.enabled
    client.post(url("admin-yubikey-enable", key))
    key.refresh_from_db()
    assert key.enabled


def test_remove_reminds_of_radiator(client, root, key):
    html = page(client.get(url("admin-yubikey-remove", key)))
    assert "yubikey-db.sh delete alice vvccccbbcdeg</code>" in html
    assert "It is alice’s only enabled YubiKey" in html
    response = client.post(url("admin-yubikey-remove", key))
    assert response.headers["Location"] == reverse("admin-user", args=[key.user.pk])
    assert not YubikeyCredential.objects.filter(pk=key.pk).exists()


@pytest.mark.parametrize(
    ("name", "method"),
    [
        ("admin-yubikey-edit", "get"),
        ("admin-yubikey-pin", "post"),
        ("admin-yubikey-disable", "post"),
        ("admin-yubikey-remove", "post"),
        ("admin-yubikey-secrets", "get"),
    ],
)
def test_a_yubikey_belongs_to_the_account_in_the_address(
    client, root, alice, make_user, make_credential, name, method
):
    bobs = make_credential(make_user("bob"))
    response = getattr(client, method)(reverse(name, args=[alice.pk, bobs.pk]))
    assert response.status_code == 404
    assert YubikeyCredential.objects.get(pk=bobs.pk).enabled


def test_users_cant_reach_admin_yubikey_pages(client, alice, key):
    signed_in(client, alice)
    assert client.get(url("admin-yubikey-secrets", key)).status_code == 403
    assert client.post(url("admin-yubikey-disable", key)).status_code == 403


# Revealing secrets (spec §20.2, §34; addendum §3.2)


def revealed(html: str) -> dict[str, str]:
    return dict(
        re.findall(r'<code class="revealed"[^>]*data-mask="(\*+)">([0-9a-f]+)</code>', html)
    )


def reveal_events() -> list[str]:
    return list(
        AuditEvent.objects.filter(
            event_type__in=[
                EventType.YUBIKEY_PRIVATE_ID_REVEALED,
                EventType.YUBIKEY_AES_SECRET_REVEALED,
            ]
        )
        .order_by("timestamp")
        .values_list("event_type", flat=True)
    )


def test_secrets_are_masked_by_default(client, root, key):
    html = page(client.get(url("admin-yubikey-secrets", key)))
    assert "0102030405a6" not in html and K1 not in html
    assert "<code>************</code>" in html
    assert 'name="passcode"' in html
    assert '<script src="/static/web/expire.js" defer></script>' in html


def test_reveal_after_the_step_up(client, root, key, step_up):
    response = client.post(
        url("admin-yubikey-secrets", key), {"secret": "private_id", "passcode": step_up(1)}
    )
    html = page(response)
    assert revealed(html) == {"************": "0102030405a6"}
    assert K1 not in html
    assert "no-store" in response.headers["Cache-Control"]
    assert "Shown for 60 seconds" in html
    assert reveal_events() == [EventType.YUBIKEY_PRIVATE_ID_REVEALED]
    audit = AuditEvent.objects.get(event_type=EventType.YUBIKEY_PRIVATE_ID_REVEALED)
    assert audit.details == {"public_id": "vvccccbbcdeg", "step_up": True}  # never the value
    assert audit.actor_username_snapshot == "root" and audit.target_username_snapshot == "alice"

    html = page(
        client.post(url("admin-yubikey-secrets", key), {"secret": "both", "passcode": step_up(2)})
    )
    assert revealed(html) == {"************": "0102030405a6", "*" * 32: K1}
    assert len(reveal_events()) == 3


def test_a_wrong_step_up_reveals_nothing_and_counts(client, root, key, step_up):
    wrong = "Wr0ngPIN!" + step_up(1)[len(PIN) :]
    html = page(
        client.post(url("admin-yubikey-secrets", key), {"secret": "aes_key", "passcode": wrong})
    )
    assert "Your PIN and OTP weren’t accepted." in html
    assert not revealed(html) and K1 not in html and "Wr0ngPIN!" not in html
    assert not reveal_events()
    failure = AuditEvent.objects.get(event_type=EventType.LOGIN_FAILURE)
    assert failure.details["reason"] == "step-up: wrong PIN"
    assert (failure.actor_user_id, failure.session_id) == (
        root.pk,
        Session.objects.get(user=root).pk,
    )
    assert YubikeyCredential.objects.get(public_id=ROOT_PUBLIC_ID).failed_login_count == 1


def test_a_replayed_step_up_otp_is_refused(client, root, key, step_up):
    client.post(url("admin-yubikey-secrets", key), {"secret": "aes_key", "passcode": step_up(1)})
    html = page(
        client.post(
            url("admin-yubikey-secrets", key), {"secret": "aes_key", "passcode": step_up(1)}
        )
    )
    assert "weren’t accepted" in html and not revealed(html)


def test_the_step_up_needs_a_passcode(client, root, key):
    html = page(client.post(url("admin-yubikey-secrets", key), {"secret": "private_id"}))
    assert "This field is required." in html and not revealed(html)
    assert not reveal_events()


def test_step_up_failures_can_lock_the_admin(client, root, key, step_up, make_user):
    make_user("other", admin=True)
    for counter in range(1, 4):
        wrong = "Wr0ngPIN!" + step_up(counter)[len(PIN) :]
        response = client.post(
            url("admin-yubikey-secrets", key), {"secret": "aes_key", "passcode": wrong}
        )
    assert response.headers["Location"] == reverse("login")
    assert User.objects.get(pk=root.pk).state == AccountState.LOCKED
    assert not reveal_events()


def test_reveal_without_the_step_up_when_the_setting_is_off(client, root, key, actor):
    portal_settings.update({"step_up_before_reveal": False}, actor)
    html = page(client.get(url("admin-yubikey-secrets", key)))
    assert 'name="passcode"' not in html
    html = page(client.post(url("admin-yubikey-secrets", key), {"secret": "aes_key"}))
    assert revealed(html) == {"*" * 32: K1}
    assert reveal_events() == [EventType.YUBIKEY_AES_SECRET_REVEALED]
    audit = AuditEvent.objects.get(event_type=EventType.YUBIKEY_AES_SECRET_REVEALED)
    assert audit.details["step_up"] is False


def test_an_unknown_secret_is_a_bad_request(client, root, key, actor):
    portal_settings.update({"step_up_before_reveal": False}, actor)
    response = client.post(url("admin-yubikey-secrets", key), {"secret": "pin"})
    assert response.status_code == 400
    assert not reveal_events()
