"""Account lifecycle: creation, states, temporary passwords, roles (spec §6-§11, §15).

Each function checks its rules, changes the account in one transaction and
records an audit event. A broken rule raises ValidationError with a code, and
a message the web pages and the CLI show as it is. Functions that change an
account refresh the User passed in.
"""

from collections.abc import Collection, Generator, Iterable
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.db.models import QuerySet
from django.utils import timezone

from yk_portal.audit.models import EventType
from yk_portal.audit.service import Actor, record
from yk_portal.authentication.passwords import generate_temporary_password, hash_web_password
from yk_portal.authentication.sessions import revoke_sessions
from yk_portal.portal_settings.service import current as current_settings
from yk_portal.yubikeys.models import YubikeyCredential

from .models import AccountState, Group, Role, User
from .validators import validate_username

PROVISIONING = AccountState.PROVISIONING
ACTIVE = AccountState.ACTIVE
LOCKED = AccountState.LOCKED
DISABLED = AccountState.DISABLED


@dataclass(frozen=True)
class NewAccount:
    """A created account and its temporary password, shown once to the admin."""

    user: User
    temporary_password: str = field(repr=False)


def normalize_username(value: str) -> str:
    """Usernames are lowercase (spec §10, §23)."""
    return value.strip().lower()


def create_user(
    username: str,
    actor: Actor,
    email: str = "",
    admin: bool = False,
    groups: Iterable[Group] | None = None,
) -> NewAccount:
    """Create an account in PROVISIONING with a temporary password (spec §10).

    Args:
        username: The username; it is lowercased.
        actor: Who creates the account.
        email: An optional email address.
        admin: Whether to add the admin role to the user role.
        groups: The account's groups; None gives the default group, if one is set
            (addendum §5.4).

    Returns:
        The account and its temporary password.

    Raises:
        ValidationError: The username or email address is invalid, or the username is taken.
    """
    return _create(username, actor, email, admin, groups, EventType.ACCOUNT_CREATED)


def bootstrap_admin(username: str, actor: Actor) -> NewAccount:
    """Create the first admin account (spec §8): PROVISIONING, roles user and admin.

    Raises:
        ValidationError: An admin account already exists, or the username is invalid.
    """
    if User.objects.filter(user_roles__role__name=Role.ADMIN).exists():
        raise ValidationError(
            "An admin account already exists; use create-admin to add another.",
            code="admin_exists",
        )
    return _create(username, actor, "", True, None, EventType.ADMIN_BOOTSTRAPPED)


def create_migrated_user(username: str, actor: Actor, source: str) -> User:
    """Create an ACTIVE account for a user migrated from another system (addendum §7.2).

    It gets the user role, the default group if one is set, no email address and
    no temporary password. Its YubiKeys, added next, bring their PINs.

    Args:
        username: The username, used as it is: it isn't lowercased.
        actor: Who creates the account.
        source: Where it comes from, for the audit event.

    Raises:
        ValidationError: The username is invalid or taken.
    """
    validate_username(username)
    with transaction.atomic():
        return _insert(
            username,
            actor,
            [Role.USER],
            None,
            EventType.ACCOUNT_CREATED,
            {"source": source},
            state=ACTIVE,
        )


def _create(
    username: str,
    actor: Actor,
    email: str,
    admin: bool,
    groups: Iterable[Group] | None,
    event: EventType,
) -> NewAccount:
    username = normalize_username(username)
    validate_username(username)
    email = email.strip()
    if email:
        validate_email(email)
    temporary = generate_temporary_password()
    temporary_hash = hash_web_password(temporary)
    roles = [Role.USER, Role.ADMIN] if admin else [Role.USER]
    with transaction.atomic():
        user = _insert(
            username,
            actor,
            roles,
            groups,
            event,
            {},
            email=email,
            temporary_password_hash=temporary_hash,
            temporary_password_expires_at=_temporary_expiry(),
        )
    return NewAccount(user, temporary)


def _insert(
    username: str,
    actor: Actor,
    roles: list[str],
    groups: Iterable[Group] | None,
    event: EventType,
    details: dict[str, str],
    **fields: object,
) -> User:
    """Insert an account with its roles and groups (None: the default group), and record
    EVENT. Call it in a transaction."""
    if User.objects.filter(username=username).exists():
        raise ValidationError("That username is taken.", code="username_taken")
    if groups is None:
        groups = Group.objects.filter(pk=current_settings().default_group)
    groups = list(groups)
    user = User.objects.create(username=username, **fields)
    user.roles.add(*Role.objects.filter(name__in=roles))
    user.groups.add(*groups)
    record(
        event,
        actor,
        user,
        details={"roles": roles, "groups": sorted(g.name for g in groups), **details},
    )
    return user


def disable(user: User, actor: Actor) -> None:
    """PROVISIONING, ACTIVE or LOCKED -> DISABLED (spec §7.1), unless it is the last admin.

    Ends the account's sessions.
    """
    with _account(user, {PROVISIONING, ACTIVE, LOCKED}, keep_an_admin=True) as account:
        _set_state(account, actor, DISABLED, EventType.ACCOUNT_DISABLED)
        revoke_sessions(account)


def enable(user: User, actor: Actor) -> None:
    """DISABLED -> ACTIVE (spec §7.1), for an account with a YubiKey that has a PIN
    (addendum §2.12).

    An account disabled before it finished provisioning has none: reset it to
    provisioning instead.
    """
    with _account(user, {DISABLED}) as account:
        if not _keys(account).exclude(pin_hash="", radius_pin_hash="").exists():
            raise ValidationError(
                "This account has no YubiKey with a PIN; reset it to provisioning instead.",
                code="no_pin",
            )
        _set_state(account, actor, ACTIVE, EventType.ACCOUNT_ENABLED)
        _clear_failures(account)


def lock(user: User, actor: Actor) -> None:
    """ACTIVE or PROVISIONING -> LOCKED, ending the account's sessions (spec §7.1, §18;
    addendum §2.10)."""
    with _account(user, {ACTIVE, PROVISIONING}) as account:
        _set_state(account, actor, LOCKED, EventType.ACCOUNT_LOCKED)
        revoke_sessions(account)


def unlock(user: User, actor: Actor) -> None:
    """LOCKED -> ACTIVE, clearing the failed-login count (spec §7.1, §18).

    An account that still has a temporary password never finished provisioning,
    so it returns to PROVISIONING instead (addendum §2.10).
    """
    with _account(user, {LOCKED}) as account:
        state = PROVISIONING if account.temporary_password_hash else ACTIVE
        _set_state(account, actor, state, EventType.ACCOUNT_UNLOCKED)
        _clear_failures(account)


def reset_to_provisioning(user: User, actor: Actor) -> str:
    """ACTIVE, LOCKED or DISABLED -> PROVISIONING with a new temporary password (spec §15).

    Ends the account's sessions and disables its YubiKeys.

    Returns:
        The new temporary password, shown once to the admin.
    """
    temporary = generate_temporary_password()
    temporary_hash = hash_web_password(temporary)
    with _account(user, {ACTIVE, LOCKED, DISABLED}) as account:
        _set_state(
            account,
            actor,
            PROVISIONING,
            EventType.ACCOUNT_RESET_TO_PROVISIONING,
            temporary_password_hash=temporary_hash,
            temporary_password_expires_at=_temporary_expiry(),
        )
        _clear_failures(account)
        revoke_sessions(account)
        # Disabled, not deleted: a lost YubiKey can't be used, and admins still see it.
        enabled = _keys(account).filter(enabled=True)
        public_ids = sorted(enabled.values_list("public_id", flat=True))
        if public_ids:
            enabled.update(enabled=False, updated_at=timezone.now())
            details = {"public_ids": public_ids, "reason": "reset to provisioning"}
            record(EventType.YUBIKEY_DISABLED, actor, account, details=details)
    return temporary


def set_temporary_password(user: User, actor: Actor) -> str:
    """Issue a new temporary password to a PROVISIONING account (spec §11).

    For an account in another state, use reset_to_provisioning.

    Returns:
        The new temporary password, shown once to the admin.
    """
    temporary = generate_temporary_password()
    temporary_hash = hash_web_password(temporary)
    with _account(user, {PROVISIONING}) as account:
        account.temporary_password_hash = temporary_hash
        account.temporary_password_expires_at = _temporary_expiry()
        account.save()
        _clear_failures(account)
        record(
            EventType.TEMPORARY_PASSWORD_SET,
            actor,
            account,
            details={"expires_at": account.temporary_password_expires_at.isoformat()},
        )
    return temporary


def set_email(user: User, email: str, actor: Actor) -> None:
    """Set the account's email address, informational only (spec §24).

    The audit event names the change, not the address (spec §26).

    Raises:
        ValidationError: Not an email address.
    """
    email = email.strip()
    if email:
        validate_email(email)
    with _account(user) as account:
        if account.email == email:
            return
        account.email = email
        account.save()
        record(EventType.ACCOUNT_UPDATED, actor, account, details={"changed": ["email"]})


def complete_provisioning(user: User, actor: Actor) -> None:
    """PROVISIONING -> ACTIVE: onboarding is done (spec §13.2). The temporary password
    stops working (addendum §2.11).

    Call it only after the user tested an enabled YubiKey and set its PIN in the same
    transaction, as yk_portal.accounts.onboarding does.

    Raises:
        ValidationError: The account has no email address, or no enabled YubiKey with
            a PIN.
    """
    with _account(user, {PROVISIONING}) as account:
        check_ready_to_finish(account)
        if (
            not _keys(account)
            .filter(enabled=True)
            .exclude(pin_hash="", radius_pin_hash="")
            .exists()
        ):
            raise ValidationError("Add a YubiKey first.", code="no_yubikey")
        _set_state(
            account,
            actor,
            ACTIVE,
            EventType.PROVISIONING_COMPLETED,
            temporary_password_hash="",
            temporary_password_expires_at=None,
        )
        _clear_failures(account)


def check_ready_to_finish(user: User) -> None:
    """Whether onboarding has the email address it needs before the YubiKey step
    (addendum §14.2).

    Raises:
        ValidationError: It is missing.
    """
    if not user.email:
        raise ValidationError("Set your email address first.", code="no_email")


def grant_admin(user: User, actor: Actor) -> None:
    """Add the admin role (spec §6). Nothing happens if the user has it already."""
    with _account(user) as account:
        if account.is_admin:
            return
        account.roles.add(Role.objects.get(name=Role.ADMIN))
        record(EventType.ADMIN_ROLE_GRANTED, actor, account)


def revoke_admin(user: User, actor: Actor) -> None:
    """Remove the admin role, unless it is the last enabled admin (spec §6, §9.1).

    Nothing happens if the user isn't an admin.
    """
    with _account(user, keep_an_admin=True) as account:
        if not account.is_admin:
            return
        account.roles.remove(Role.objects.get(name=Role.ADMIN))
        record(EventType.ADMIN_ROLE_REVOKED, actor, account)


def enabled_admins() -> QuerySet[User]:
    """Admin accounts that aren't DISABLED: those spec §9.1 keeps at least one of."""
    return User.objects.filter(user_roles__role__name=Role.ADMIN).exclude(state=DISABLED)


@contextmanager
def _account(
    user: User, states: Collection[str] = (), keep_an_admin: bool = False
) -> Generator[User]:
    """A transaction holding USER's row locked, after checking its state.

    Args:
        user: The account to change.
        states: The states the change is allowed from; empty for any.
        keep_an_admin: Refuse if USER is the last enabled admin (spec §9.1). Every
            enabled admin is locked first, in ID order, so two admins changing each
            other at once queue instead of both passing the check or deadlocking.

    Yields:
        A fresh copy of the account to change; USER is refreshed afterwards.
    """
    with transaction.atomic():
        if keep_an_admin:
            admins = list(
                enabled_admins()
                .select_for_update(of=("self",))
                .order_by("pk")
                .values_list("pk", flat=True)
            )
            if admins == [user.pk]:
                raise ValidationError(
                    "This is the last enabled admin account; make another admin first.",
                    code="last_admin",
                )
        account = User.objects.select_for_update().get(pk=user.pk)
        if states and account.state not in states:
            raise ValidationError(
                f"Not allowed while the account is {account.state}.", code="invalid_state"
            )
        yield account
    user.refresh_from_db()


def _keys(account: User) -> QuerySet[YubikeyCredential]:
    return YubikeyCredential.objects.filter(user=account)


def _clear_failures(account: User) -> None:
    """Clear the failed-login counts of the account and of each of its YubiKeys
    (addendum §2.14)."""
    User.objects.filter(pk=account.pk).update(failed_login_count=0)
    account.failed_login_count = 0
    _keys(account).update(failed_login_count=0)


def _set_state(
    account: User, actor: Actor, state: AccountState, event: EventType, **fields: object
) -> None:
    old = account.state
    account.state = state
    for name, value in fields.items():
        setattr(account, name, value)
    account.save()
    record(event, actor, account, details={"old_state": old, "new_state": state})


def _temporary_expiry(hours: int | None = None) -> datetime:
    """When a temporary password issued now expires (addendum §3.2, §3.3)."""
    if hours is None:
        hours = current_settings().temp_password_hours
    return timezone.now() + timedelta(hours=hours)
