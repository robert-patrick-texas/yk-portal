"""No secret reaches the audit log, in the database or the journal (spec §26, §27): an
account's whole life through the pages, with every secret it uses."""

import json
import logging
import re

import pytest
from django.test import Client
from django.urls import reverse

from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.authentication.sessions import COOKIE

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("master_key")]

ROOT_PIN = "R00t-pin!"
ROOT_PUBLIC_ID = "vvccccbbcdeh"
ROOT_PRIVATE_ID = "0a0b0c0d0e0f"
K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"
PIN = "N1na-pin!"
NEW_PIN = "N1na-new-pin!"
ADMIN_PIN = "Adm1n-set-pin!"
EMAIL = "nina@example.com"
PUBLIC_ID = "vvccccbbcdef"
PRIVATE_ID = "4a6f8e2d1c3b"
AES_KEY = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
TEMPORARY = re.compile(r'<p class="secret"><code>([a-z0-9-]{19})</code>')


def test_an_accounts_life_leaves_no_secret_in_the_audit_log(
    client, make_user, make_credential, make_otp, caplog, django_capture_on_commit_callbacks
):
    secrets: list[str] = [PIN, NEW_PIN, ADMIN_PIN, EMAIL, PRIVATE_ID, AES_KEY, ROOT_PIN]
    counters = {PUBLIC_ID: 0, ROOT_PUBLIC_ID: 0}

    def otp(public_id: str = PUBLIC_ID) -> str:
        counters[public_id] += 1
        private_id, aes_key = (
            (PRIVATE_ID, AES_KEY) if public_id == PUBLIC_ID else (ROOT_PRIVATE_ID, K1)
        )
        text = make_otp(public_id, private_id, aes_key, counters[public_id])
        secrets.append(text[12:])  # the token: all of an OTP but its public ID
        return text

    def sign_in(browser: Client, username: str, passcode: str) -> None:
        browser.post(reverse("login"), {"username": username, "passcode": passcode})
        if COOKIE in browser.cookies and browser.cookies[COOKIE].value:
            secrets.append(browser.cookies[COOKIE].value)

    root = make_user("root", admin=True)
    make_credential(root, public_id=ROOT_PUBLIC_ID, private_id=ROOT_PRIVATE_ID, pin=ROOT_PIN)
    nina = Client()
    with (
        caplog.at_level(logging.INFO, logger="yk_portal.audit"),
        django_capture_on_commit_callbacks(execute=True),
    ):
        sign_in(client, "root", ROOT_PIN + otp(ROOT_PUBLIC_ID))
        response = client.post(reverse("admin-user-new"), {"username": "nina", "email": EMAIL})
        temporary = TEMPORARY.search(response.content.decode())
        assert temporary
        secrets.append(temporary.group(1))

        # Onboarding, with a mistyped temporary password and a passcode in the username box
        sign_in(nina, "nina", temporary.group(1) + "x")
        sign_in(nina, temporary.group(1), temporary.group(1))
        sign_in(nina, "nina", temporary.group(1))
        key = {"public_id": PUBLIC_ID, "private_id": PRIVATE_ID, "aes_key": AES_KEY}
        key |= {"label": "primary", "slot": "2", "pin": PIN, "confirm": PIN, "otp": otp()}
        nina.post(reverse("provision-yubikey"), key)
        nina.post(reverse("logout"))

        # Signing in, refused and accepted; the PIN changed, once with a replayed OTP
        sign_in(nina, "nina", "wrong-pin1" + otp())
        sign_in(nina, "nina", PIN + ":" + otp())
        listing = nina.get(reverse("yubikeys")).content.decode()
        key_id = re.search(r"/account/yubikeys/([0-9a-f-]{36})/pin/", listing)
        assert key_id
        pin_url = reverse("yubikey-pin", args=[key_id.group(1)])
        replayed = otp()
        nina.post(pin_url, {"pin": NEW_PIN, "confirm": NEW_PIN, "otp": replayed})
        nina.post(pin_url, {"pin": NEW_PIN, "confirm": NEW_PIN, "otp": replayed})

        # The admin: a failed step-up, a reveal, a PIN, a reset, the delete
        user_id = AuditEvent.objects.get(event_type=EventType.ACCOUNT_CREATED).target_user_id
        key_args = [user_id, key_id.group(1)]
        secrets_url = reverse("admin-yubikey-secrets", args=key_args)
        client.post(secrets_url, {"secret": "both", "passcode": "Wr0ng-pin" + otp(ROOT_PUBLIC_ID)})
        passcode = ROOT_PIN + otp(ROOT_PUBLIC_ID)
        response = client.post(secrets_url, {"secret": "both", "passcode": passcode})
        assert PRIVATE_ID in response.content.decode()  # shown on the page, and only there
        pin = {"pin": ADMIN_PIN, "confirm": ADMIN_PIN}
        client.post(reverse("admin-yubikey-pin", args=key_args), pin)
        response = client.post(reverse("admin-user-reset", args=[user_id]))
        temporary = TEMPORARY.search(response.content.decode())
        assert temporary
        secrets.append(temporary.group(1))
        client.post(reverse("admin-user-delete", args=[user_id]), {"username": "nina"})

    recorded = [e.event_type for e in AuditEvent.objects.order_by("timestamp")]
    for expected in (
        EventType.PROVISIONING_COMPLETED,
        EventType.LOGOUT,
        EventType.YUBIKEY_AES_SECRET_REVEALED,
        EventType.ACCOUNT_RESET_TO_PROVISIONING,
        EventType.ACCOUNT_DELETED,
    ):
        assert expected in recorded
    assert len(caplog.messages) == len(recorded)
    stored = [json.dumps([str(value) for value in row]) for row in AuditEvent.objects.values_list()]
    for text in (*stored, *caplog.messages):
        for secret in secrets:
            assert secret.lower() not in text.lower(), (secret, text)
