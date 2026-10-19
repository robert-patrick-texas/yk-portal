"""Signing in: username + passcode (spec §16, §18; addendum §2.8-§2.10, §2.14).

An ACTIVE account signs in with the PIN of one of its YubiKeys followed by an
OTP from that YubiKey. A PROVISIONING account signs in with its temporary
password alone (spec §13). Every refusal raises the same LoginFailed, whatever
the cause (spec §16); the cause goes to the audit log. Each attempt checks one
hash, even for an unknown username, so timing doesn't tell which usernames
exist.

A failed login counts against the YubiKey whose PIN or OTP was wrong, or
against the account when no YubiKey of it was named. Any one count reaching
the failed-login limit locks the account (addendum §2.14).
"""

import functools
import secrets
from typing import NoReturn

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from yk_portal.accounts import services
from yk_portal.accounts.models import AccountState, User
from yk_portal.accounts.validators import validate_username
from yk_portal.audit.models import EventType, Result
from yk_portal.audit.service import Actor, record
from yk_portal.authentication.passwords import (
    check_web_password,
    hash_web_password,
    looks_like_temporary_password,
)
from yk_portal.core import sha512_crypt
from yk_portal.portal_settings.service import current as current_settings
from yk_portal.yubikeys.models import YubikeyCredential
from yk_portal.yubikeys.otp import OTP_LENGTH, OtpRejected, Rejection, parse_otp
from yk_portal.yubikeys.service import accept_otp, find_credential

from .models import Session
from .sessions import Client, purge_ended_sessions, start_session

MESSAGE = "Sign-in failed. Check your username, PIN and YubiKey."


class LoginFailed(Exception):
    """A refused login. Its message is the same for every cause."""

    def __init__(self) -> None:
        super().__init__(MESSAGE)


def split_passcode(passcode: str) -> tuple[str, str | None]:
    """The PIN and the OTP: the last 44 characters (spec §5.3).

    One ":" right before the OTP is dropped, as Radiator does (addendum §2.9);
    a PIN can't end with ":". A passcode too short to hold an OTP has none.
    """
    if len(passcode) < OTP_LENGTH:
        return passcode, None
    pin, otp = passcode[:-OTP_LENGTH], passcode[-OTP_LENGTH:]
    return pin.removesuffix(":"), otp


def log_in(username: str, passcode: str, client: Client) -> tuple[Session, str]:
    """Check a login and start a session.

    Returns:
        The new session and the token for its cookie.

    Raises:
        LoginFailed: For any refusal. Refusals that count (spec §18.1) may lock the
            account (addendum §2.10).
    """
    username = services.normalize_username(username)
    anonymous = Actor(user=None, name="", source_ip=client.source_ip)
    user = User.objects.filter(username=username).first()
    if user is None:
        _check_nothing(passcode)
        _refuse(anonymous, None, _unknown(username))
    if user.state == AccountState.LOCKED:
        _check_nothing(passcode)
        _refuse(anonymous, user, "account locked", EventType.LOGIN_LOCKED)
    if user.state == AccountState.DISABLED:
        _check_nothing(passcode)
        _refuse(anonymous, user, "account disabled")
    if user.state == AccountState.PROVISIONING:
        _check_temporary_password(user, passcode, anonymous)
        return _succeed(user, client, AccountState.PROVISIONING)
    credential, new_pin_hash = _check_pin_and_otp(user, passcode, anonymous)
    return _succeed(user, client, AccountState.ACTIVE, credential, new_pin_hash)


def _check_temporary_password(user: User, passcode: str, actor: Actor) -> None:
    if not check_web_password(passcode, user.temporary_password_hash):
        _count_failure(user, actor, "wrong temporary password")
    expires = user.temporary_password_expires_at
    if expires is None or expires <= timezone.now():
        # The right password, too late: not a guess, so it doesn't count.
        _refuse(actor, user, "temporary password expired")


def confirm_identity(actor: Actor, passcode: str) -> None:
    """Step-up: the signed-in user's PIN and a fresh OTP again, before revealing a
    YubiKey secret (spec §20.2, addendum §3.2). A failure counts like a failed login.

    Args:
        actor: The signed-in user, with the request's address and session.

    Raises:
        LoginFailed: The passcode isn't good.
    """
    if actor.user is None:
        raise ValueError("step-up needs a signed-in user")
    _check_pin_and_otp(actor.user, passcode, actor, "step-up: ")


def _check_pin_and_otp(
    user: User, passcode: str, actor: Actor, context: str = ""
) -> tuple[YubikeyCredential, str]:
    """Check the PIN of the YubiKey whose OTP ends PASSCODE, then the OTP (spec §16).

    Args:
        context: Prefixes the audited reason of a failure.

    Returns:
        The YubiKey, and the Argon2id hash to store for the first web login with a key
        that has only the SHA-512 hash of its PIN (addendum §2.8), else "".
    """
    pin, otp_text = split_passcode(passcode)
    try:
        if otp_text is None:
            raise OtpRejected(Rejection.MALFORMED)
        otp = parse_otp(otp_text)
        credential = find_credential(user, otp.public_id)
    except OtpRejected as e:
        _check_nothing(pin)
        _count_failure(user, actor, context + e.reason.value)
    if not _check_pin(credential, pin):
        # Checked before the OTP, so a wrong PIN doesn't use the OTP up.
        _count_failure(user, actor, context + "wrong PIN", credential)
    try:
        accept_otp(credential, otp)
    except OtpRejected as e:
        _count_failure(user, actor, context + e.reason.value, credential)
    return credential, "" if credential.pin_hash else hash_web_password(pin)


def _check_pin(credential: YubikeyCredential, pin: str) -> bool:
    """The Argon2id hash, or for a key imported from Radiator without one, the SHA-512
    crypt hash (addendum §2.8). A key with neither never matches."""
    if credential.pin_hash:
        return check_web_password(pin, credential.pin_hash)
    if credential.radius_pin_hash:
        return sha512_crypt.check_hash(pin, credential.radius_pin_hash)
    _check_nothing(pin)
    return False


def _check_nothing(passcode: str) -> None:
    """Spend the time of one password check, as for a real account. Its result is unused."""
    check_web_password(passcode, _dummy_hash())


@functools.cache
def _dummy_hash() -> str:
    return hash_web_password(secrets.token_urlsafe(32))


def _unknown(username: str) -> str:
    """The audit reason for an unknown username, naming it only if it could be one,
    so a password typed into the username box isn't logged. A temporary password could
    be a username, but isn't named either (spec §27)."""
    try:
        validate_username(username)
    except ValidationError:
        return "unknown username (not a valid username)"
    if looks_like_temporary_password(username):
        return "unknown username (looks like a temporary password)"
    return f"unknown username {username}"


def _count_failure(
    user: User, actor: Actor, reason: str, credential: YubikeyCredential | None = None
) -> NoReturn:
    """Record a failed login that counts (spec §18): against CREDENTIAL, the YubiKey whose
    PIN or OTP was wrong, or else against the account. The account locks when the count
    reaches the limit (addendum §2.14)."""
    with transaction.atomic():
        account = User.objects.select_for_update().get(pk=user.pk)
        counts = account.state in (AccountState.ACTIVE, AccountState.PROVISIONING)
        key = None
        if credential is not None:
            key = YubikeyCredential.objects.select_for_update().filter(pk=credential.pk).first()
        details: dict[str, str | int] = {"reason": reason}
        if key is not None:
            if counts:
                key.failed_login_count += 1
                key.save(update_fields=["failed_login_count"])
            failures = key.failed_login_count
            details["public_id"] = key.public_id
        else:
            if counts:
                account.failed_login_count += 1
                account.save(update_fields=["failed_login_count", "updated_at"])
            failures = account.failed_login_count
        details["failed_logins"] = failures
        record(EventType.LOGIN_FAILURE, actor, account, details=details, result=Result.FAILURE)
        if counts and failures >= current_settings().failed_login_limit:
            services.lock(account, actor)
    raise LoginFailed


def _refuse(
    actor: Actor, user: User | None, reason: str, event: EventType = EventType.LOGIN_FAILURE
) -> NoReturn:
    """Record a failed login that doesn't count."""
    record(event, actor, user, details={"reason": reason}, result=Result.FAILURE)
    raise LoginFailed


def _succeed(
    user: User,
    client: Client,
    state: AccountState,
    credential: YubikeyCredential | None = None,
    new_pin_hash: str = "",
) -> tuple[Session, str]:
    """Start a session. Clears the failed-login count of the account and of CREDENTIAL,
    the YubiKey used; the other YubiKeys' counts stay (addendum §2.14)."""
    with transaction.atomic():
        account = User.objects.select_for_update().get(pk=user.pk)
        if account.state != state:  # changed by an admin during the check
            _refuse(Actor(user=None, name="", source_ip=client.source_ip), account, "state changed")
        account.failed_login_count = 0
        account.last_login_at = timezone.now()
        account.save(update_fields=["failed_login_count", "last_login_at", "updated_at"])
        details: dict[str, str] = {"state": state}
        if credential is not None:
            keys = YubikeyCredential.objects.filter(pk=credential.pk)
            keys.update(failed_login_count=0)
            if new_pin_hash:
                keys.filter(pin_hash="").update(pin_hash=new_pin_hash)
            details["public_id"] = credential.public_id
        session, token = start_session(account, client)
        actor = Actor(
            user=account, name=account.username, source_ip=client.source_ip, session_id=session.pk
        )
        record(EventType.LOGIN_SUCCESS, actor, account, details=details)
    purge_ended_sessions(current_settings())
    return session, token
