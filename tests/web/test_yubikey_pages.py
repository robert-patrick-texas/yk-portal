import re

import pytest
from django.urls import reverse

from yk_portal.accounts import services
from yk_portal.accounts.models import AccountState, User
from yk_portal.audit.service import Actor
from yk_portal.authentication.passwords import hash_password
from yk_portal.authentication.sessions import COOKIE, start_session
from yk_portal.authentication.sessions import Client as SessionClient
from yk_portal.portal_settings import service as portal_settings
from yk_portal.yubikeys.management import NewYubikey, add_yubikey
from yk_portal.yubikeys.models import ProvisioningMethod, YubikeyCredential

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("master_key")]

PASSWORD = "Passw0rd!"  # noqa: S105 - a test password
PUBLIC_ID = "vvccccbbcdef"
PRIVATE_ID = "4a6f8e2d1c3b"
K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"
K2 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"


@pytest.fixture(scope="session")
def hashes():
    return hash_password(PASSWORD)


def signed_in(client, user: User) -> None:
    """Give CLIENT a session for USER, without the sign-in page."""
    _, token = start_session(user, SessionClient("127.0.0.1", "pytest"))
    client.cookies[COOKIE] = token


def key_form(otp_text: str, **overrides: str) -> dict[str, str]:
    data = {
        "public_id": PUBLIC_ID,
        "private_id": PRIVATE_ID,
        "aes_key": K1,
        "label": "primary",
        "slot": "2",
        "otp": otp_text,
    }
    return data | overrides


@pytest.fixture
def otp(make_otp):
    return lambda counter, session=0, aes_key=K1: make_otp(
        PUBLIC_ID, PRIVATE_ID, aes_key, counter, session
    )


@pytest.fixture
def nina(client, actor):
    """A new account, signed in with its temporary password."""
    account = services.create_user("nina", actor)
    client.post(reverse("login"), {"username": "nina", "passcode": account.temporary_password})
    return account.user


@pytest.fixture
def alice(client, make_user, make_credential, hashes):
    """An ACTIVE account with one YubiKey, signed in."""
    user = make_user("alice", password_hash=hashes.web, radius_password_hash=hashes.radius)
    make_credential(user, public_id="vvccccbbcdeg", label="old one")
    signed_in(client, user)
    return user


# Onboarding (spec §13)


def test_onboarding_through_the_pages(client, nina, otp):
    page = client.get(reverse("provision")).content.decode()
    assert "Your email address" in page and "To do" in page
    # The YubiKey step waits for the email address and password.
    assert client.get(reverse("provision-yubikey")).headers["Location"] == reverse("provision")

    response = client.post(reverse("provision-email"), {"email": "nina@example.com"})
    assert response.headers["Location"] == reverse("provision")

    response = client.post(reverse("provision-password"), {"password": "short", "confirm": "x"})
    page = response.content.decode()
    assert "Use at least 8 characters." in page and "The two passwords differ." in page
    response = client.post(
        reverse("provision-password"), {"password": PASSWORD, "confirm": PASSWORD}
    )
    assert response.headers["Location"] == reverse("provision")

    page = client.get(reverse("provision-yubikey")).content.decode()
    assert "Add your YubiKey" in page and "ykman otp yubico 2" in page
    response = client.post(reverse("provision-yubikey"), key_form(otp(1)))
    assert response.headers["Location"] == reverse("home")
    assert User.objects.get(pk=nina.pk).state == AccountState.ACTIVE
    assert "<h1>nina</h1>" in client.get(reverse("home")).content.decode()


def test_secrets_are_never_sent_back(client, nina, otp, actor):
    services.set_email(nina, "nina@example.com", actor)
    services.set_password(nina, PASSWORD, actor)
    response = client.post(reverse("provision-yubikey"), key_form(otp(1, aes_key=K2)))
    page = response.content.decode()
    assert "doesn&#x27;t decrypt with this AES key" in page
    assert PRIVATE_ID not in page and K1 not in page
    assert not YubikeyCredential.objects.exists()


def test_vip_onboarding_tests_the_pre_provisioned_key(client, nina, otp, actor, make_user):
    services.set_email(nina, "nina@example.com", actor)
    services.set_password(nina, PASSWORD, actor)
    admin = Actor.for_user(make_user("boss", admin=True))
    key = NewYubikey(PUBLIC_ID, bytes.fromhex(PRIVATE_ID), bytes.fromhex(K1))
    add_yubikey(nina, admin, key, ProvisioningMethod.ADMIN_PROVISIONED)
    page = client.get(reverse("provision-yubikey")).content.decode()
    assert "Test your YubiKey" in page and 'name="public_id"' not in page
    response = client.post(reverse("provision-yubikey"), {"otp": otp(1, aes_key=K2)})
    assert "That OTP wasn&#x27;t accepted" in response.content.decode()
    response = client.post(reverse("provision-yubikey"), {"otp": otp(1)})
    assert response.headers["Location"] == reverse("home")


def masked_fields(html: str) -> set[str]:
    """Names of the inputs shown masked, with a show/hide button."""
    names = set()
    for tag in re.findall(r"<input [^>]*>", html):
        name = re.search(r'name="(\w+)"', tag)
        if name and 'type="password"' in tag and "data-reveal" in tag:
            names.add(name.group(1))
    return names


def test_passwords_and_secrets_are_masked_with_a_show_button(client, nina, actor):
    page = client.get(reverse("provision-password")).content.decode()
    assert masked_fields(page) == {"password", "confirm"}
    services.set_email(nina, "nina@example.com", actor)
    services.set_password(nina, PASSWORD, actor)
    page = client.get(reverse("provision-yubikey")).content.decode()
    # The public ID, label and OTP aren't secret.
    assert masked_fields(page) == {"private_id", "aes_key"}


def test_provisioning_sessions_cant_reach_yubikeys(client, nina):
    assert client.get(reverse("yubikeys")).headers["Location"] == reverse("provision")


def test_active_accounts_cant_reach_onboarding(client, alice):
    for name in ("provision", "provision-email", "provision-password", "provision-yubikey"):
        assert client.get(reverse(name)).headers["Location"] == reverse("home")


# Your YubiKeys (spec §20)


def test_list(client, alice):
    page = client.get(reverse("yubikeys")).content.decode()
    assert "old one" in page and "vvccccbbcdeg" in page and "Add a YubiKey" in page


def test_add(client, alice, otp):
    response = client.post(reverse("yubikey-add"), key_form(otp(5, 1)))
    assert response.headers["Location"] == reverse("yubikeys")
    credential = YubikeyCredential.objects.get(public_id=PUBLIC_ID)
    assert credential.user == alice
    assert credential.provisioning_method == ProvisioningMethod.SELF_PROVISIONED


def test_add_shows_errors_beside_the_field(client, alice, make_otp):
    taken = "vvccccbbcdeg"  # alice's other YubiKey
    otp_text = make_otp(taken, PRIVATE_ID, K1, 5)
    page = client.post(reverse("yubikey-add"), key_form(otp_text, public_id=taken)).content
    assert "A YubiKey with this public ID is registered already." in page.decode()


def test_the_add_link_goes_at_the_maximum(client, alice, actor):
    portal_settings.update({"max_yubikeys_per_user": 1}, actor)
    page = client.get(reverse("yubikeys")).content.decode()
    assert "Add a YubiKey" not in page and "the most YubiKeys" in page


def test_test_page(client, alice, make_credential, otp):
    make_credential(alice, public_id=PUBLIC_ID, private_id=PRIVATE_ID, label="spare")
    page = client.post(reverse("yubikey-test"), {"otp": otp(3)}).content.decode()
    assert "It works: spare." in page
    page = client.post(reverse("yubikey-test"), {"otp": otp(3)}).content.decode()
    assert "That OTP was used before." in page


def test_edit(client, alice):
    credential = YubikeyCredential.objects.get(user=alice)
    response = client.post(
        reverse("yubikey-edit", args=[credential.pk]), {"label": "keyring", "slot": "1"}
    )
    assert response.headers["Location"] == reverse("yubikeys")
    credential.refresh_from_db()
    assert (credential.label, credential.slot_number) == ("keyring", 1)


def test_disable_and_enable(client, alice, make_credential):
    credential = make_credential(alice)
    assert client.get(reverse("yubikey-disable", args=[credential.pk])).status_code == 405
    client.post(reverse("yubikey-disable", args=[credential.pk]))
    credential.refresh_from_db()
    assert not credential.enabled
    client.post(reverse("yubikey-enable", args=[credential.pk]))
    credential.refresh_from_db()
    assert credential.enabled


def test_the_last_enabled_key_stays(client, alice):
    credential = YubikeyCredential.objects.get(user=alice)
    page = client.post(reverse("yubikey-disable", args=[credential.pk])).content.decode()
    assert "This is your only enabled YubiKey" in page
    page = client.post(reverse("yubikey-remove", args=[credential.pk])).content.decode()
    assert "This is your only enabled YubiKey" in page
    assert YubikeyCredential.objects.get(pk=credential.pk).enabled


def test_remove(client, alice, make_credential):
    credential = make_credential(alice, enabled=False, label="lost")
    page = client.get(reverse("yubikey-remove", args=[credential.pk])).content.decode()
    assert "keeps working with Radiator" in page
    response = client.post(reverse("yubikey-remove", args=[credential.pk]))
    assert response.headers["Location"] == reverse("yubikeys")
    assert not YubikeyCredential.objects.filter(pk=credential.pk).exists()


@pytest.mark.parametrize(
    ("name", "method"),
    [
        ("yubikey-edit", "get"),
        ("yubikey-edit", "post"),
        ("yubikey-disable", "post"),
        ("yubikey-enable", "post"),
        ("yubikey-remove", "get"),
        ("yubikey-remove", "post"),
    ],
)
def test_another_users_yubikey_is_not_found(
    client, alice, make_user, make_credential, name, method
):
    theirs = make_credential(make_user("bob"))
    response = getattr(client, method)(reverse(name, args=[theirs.pk]))
    assert response.status_code == 404
    theirs.refresh_from_db()
    assert theirs.enabled
