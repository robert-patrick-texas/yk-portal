"""Signing in: username + passcode (spec §16, §18; addendum §2.8-§2.10).

An ACTIVE account signs in with its password followed by a YubiKey OTP. A
PROVISIONING account signs in with its temporary password alone (spec §13).
Every refusal raises the same LoginFailed, whatever the cause (spec §16); the
cause goes to the audit log. Each attempt checks one password hash, even for
an unknown username, so timing doesn't tell which usernames exist.
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
from yk_portal.authentication.passwords import check_web_password, hash_web_password
from yk_portal.core import sha512_crypt
from yk_portal.portal_settings.service import current as current_settings
from yk_portal.yubikeys.otp import OTP_LENGTH, OtpRejected, Rejection, parse_otp
from yk_portal.yubikeys.service import accept_otp, find_credential

from .models import Session
from .sessions import Client, purge_ended_sessions, start_session

MESSAGE = "Sign-in failed. Check your username, password and YubiKey."


class LoginFailed(Exception):
    """A refused login. Its message is the same for every cause."""

    def __init__(self) -> None:
        super().__init__(MESSAGE)


def split_passcode(passcode: str) -> tuple[str, str | None]:
    """The password and the OTP: the last 44 characters (spec §5.3).

    One ":" right before the OTP is dropped, as Radiator does (addendum §2.9);
    a password can't end with ":". A passcode too short to hold an OTP has none.
    """
    if len(passcode) < OTP_LENGTH:
        return passcode, None
    password, otp = passcode[:-OTP_LENGTH], passcode[-OTP_LENGTH:]
    return password.removesuffix(":"), otp


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
    new_password_hash = _check_password_and_otp(user, passcode, anonymous)
    return _succeed(user, client, AccountState.ACTIVE, new_password_hash)


def _check_temporary_password(user: User, passcode: str, actor: Actor) -> None:
    if not check_web_password(passcode, user.temporary_password_hash):
        _count_failure(user, actor, "wrong temporary password")
    expires = user.temporary_password_expires_at
    if expires is None or expires <= timezone.now():
        # The right password, too late: not a guess, so it doesn't count.
        _refuse(actor, user, "temporary password expired")


def confirm_identity(user: User, passcode: str, client: Client) -> None:
    """Step-up: the signed-in user's password and a fresh OTP again, before revealing a
    YubiKey secret (spec §20.2, addendum §3.2). A failure counts like a failed login.

    Raises:
        LoginFailed: The passcode isn't good.
    """
    actor = Actor(user=user, name=user.username, source_ip=client.source_ip)
    _check_password_and_otp(user, passcode, actor, "step-up: ")


def _check_password_and_otp(user: User, passcode: str, actor: Actor, context: str = "") -> str:
    """Returns the Argon2id hash to store for an imported account's first web login
    (addendum §2.8), else "". CONTEXT prefixes the audited reason of a failure."""
    password, otp_text = split_passcode(passcode)
    password_ok = _check_password(user, password)
    try:
        if otp_text is None:
            raise OtpRejected(Rejection.MALFORMED)
        otp = parse_otp(otp_text)
        credential = find_credential(user, otp.public_id)
        if not password_ok:
            # Checked before the OTP, so a wrong password doesn't use the OTP up.
            _count_failure(user, actor, context + "wrong password")
        accept_otp(credential, otp)
    except OtpRejected as e:
        _count_failure(user, actor, context + e.reason.value)
    return "" if user.password_hash else hash_web_password(password)


def _check_password(user: User, password: str) -> bool:
    """The Argon2id hash, or for an account imported from Radiator without one, the
    SHA-512 crypt hash (addendum §2.8). An account with neither never matches."""
    if user.password_hash:
        return check_web_password(password, user.password_hash)
    if user.radius_password_hash:
        return sha512_crypt.check_hash(password, user.radius_password_hash)
    _check_nothing(password)
    return False


def _check_nothing(passcode: str) -> None:
    """Spend the time of one password check, as for a real account. Its result is unused."""
    check_web_password(passcode, _dummy_hash())


@functools.cache
def _dummy_hash() -> str:
    return hash_web_password(secrets.token_urlsafe(32))


def _unknown(username: str) -> str:
    """The audit reason for an unknown username, naming it only if it could be one,
    so a password typed into the username box isn't logged."""
    try:
        validate_username(username)
    except ValidationError:
        return "unknown username (not a valid username)"
    return f"unknown username {username}"


def _count_failure(user: User, actor: Actor, reason: str) -> NoReturn:
    """Record a failed login that counts, locking the account at the limit (spec §18)."""
    with transaction.atomic():
        account = User.objects.select_for_update().get(pk=user.pk)
        if account.state in (AccountState.ACTIVE, AccountState.PROVISIONING):
            account.failed_login_count += 1
            account.save(update_fields=["failed_login_count", "updated_at"])
        details = {"reason": reason, "failed_logins": account.failed_login_count}
        record(EventType.LOGIN_FAILURE, actor, account, details=details, result=Result.FAILURE)
        if account.failed_login_count >= current_settings().failed_login_limit and (
            account.state in (AccountState.ACTIVE, AccountState.PROVISIONING)
        ):
            services.lock(account, actor)
    raise LoginFailed


def _refuse(
    actor: Actor, user: User | None, reason: str, event: EventType = EventType.LOGIN_FAILURE
) -> NoReturn:
    """Record a failed login that doesn't count."""
    record(event, actor, user, details={"reason": reason}, result=Result.FAILURE)
    raise LoginFailed


def _succeed(
    user: User, client: Client, state: AccountState, new_password_hash: str = ""
) -> tuple[Session, str]:
    with transaction.atomic():
        account = User.objects.select_for_update().get(pk=user.pk)
        if account.state != state:  # changed by an admin during the check
            _refuse(Actor(user=None, name="", source_ip=client.source_ip), account, "state changed")
        account.failed_login_count = 0
        account.last_login_at = timezone.now()
        if new_password_hash and not account.password_hash:
            account.password_hash = new_password_hash
        account.save(
            update_fields=["failed_login_count", "last_login_at", "password_hash", "updated_at"]
        )
        session, token = start_session(account, client)
        actor = Actor(
            user=account, name=account.username, source_ip=client.source_ip, session_id=session.pk
        )
        record(EventType.LOGIN_SUCCESS, actor, account, details={"state": state})
    purge_ended_sessions(current_settings())
    return session, token
