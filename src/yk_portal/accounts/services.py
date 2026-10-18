"""Account lifecycle: creation, states, temporary passwords, roles (spec §6-§11, §15).

Each function checks its rules, changes the account in one transaction and
records an audit event. A broken rule raises ValidationError with a code, and
a message the web pages and the CLI show as it is. Functions that change an
account refresh the User passed in.
"""

import unicodedata
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

# The admin-only fields (addendum §16.9).
DISPLAY_NAME_LENGTH = 255
COMMENT_LENGTH = 1000

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
    display_name: str = "",
    comment: str = "",
) -> NewAccount:
    """Create an account in PROVISIONING with a temporary password (spec §10).

    Args:
        username: The username; it is lowercased.
        actor: Who creates the account.
        email: An optional email address.
        admin: Whether to add the admin role to the user role.
        groups: The account's groups; None gives the default group, if one is set
            (addendum §5.4).
        display_name: An optional name, for admins (addendum §16.9).
        comment: Optional notes, for admins.

    Returns:
        The account and its temporary password.

    Raises:
        ValidationError: The username, email address, display name or comment is
            invalid, or the username is taken.
    """
    return _create(
        username,
        actor,
        email,
        admin,
        groups,
        EventType.ACCOUNT_CREATED,
        display_name=display_name,
        comment=comment,
    )


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
    display_name: str = "",
    comment: str = "",
) -> NewAccount:
    username = normalize_username(username)
    validate_username(username)
    email = _clean_email(email)
    display_name = _clean_display_name(display_name)
    comment = _clean_comment(comment)
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
            display_name=display_name,
            comment=comment,
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

    Raises:
        ValidationError: Not an email address.
    """
    update_account(user, actor, email=email)


def update_account(
    user: User,
    actor: Actor,
    *,
    email: str | None = None,
    display_name: str | None = None,
    comment: str | None = None,
) -> None:
    """Change an account's email address, display name or comment; None leaves one as it
    is. Display name and comment are for admins (addendum §16.9).

    One ACCOUNT_UPDATED event names the fields changed, never their values, which are
    personal data (spec §26).

    Raises:
        ValidationError: A value is invalid.
    """
    cleaners = {
        "email": (email, _clean_email),
        "display_name": (display_name, _clean_display_name),
        "comment": (comment, _clean_comment),
    }
    changes = {name: clean(value) for name, (value, clean) in cleaners.items() if value is not None}
    with _account(user) as account:
        changed = [name for name, value in changes.items() if getattr(account, name) != value]
        if not changed:
            return
        for name in changed:
            setattr(account, name, changes[name])
        account.save()
        record(EventType.ACCOUNT_UPDATED, actor, account, details={"changed": changed})


def change_username(user: User, username: str, actor: Actor) -> None:
    """Rename an account (spec §9, §23). Its ID, which everything refers to, stays.

    Radiator gets the new name with the next export, which replaces each of the
    account's YubiKeys by public ID (addendum §6.4).

    Raises:
        ValidationError: The username is invalid or taken.
    """
    username = normalize_username(username)
    validate_username(username)
    with _account(user) as account:
        if account.username == username:
            return
        if User.objects.filter(username=username).exists():
            raise ValidationError("That username is taken.", code="username_taken")
        old = account.username
        account.username = username
        account.save()
        record(
            EventType.USERNAME_CHANGED,
            actor,
            account,
            details={"old_username": old, "new_username": username},
        )


def delete_user(user: User, actor: Actor) -> list[str]:
    """Hard delete an account (spec §26), unless it is the last enabled admin (spec §9.1).

    Its YubiKeys and their secrets, roles, group memberships and sessions go with it.
    The audit log keeps its former ID and username. The deletion doesn't reach Radiator
    (addendum §6.6): an admin runs `yubikey-db.sh delete` there.

    Returns:
        The public IDs of the YubiKeys deleted.
    """
    with transaction.atomic():
        _keep_an_admin(user)
        account = User.objects.select_for_update().get(pk=user.pk)
        public_ids = sorted(_keys(account).values_list("public_id", flat=True))
        details = {"state": account.state, "public_ids": public_ids}
        record(EventType.ACCOUNT_DELETED, actor, account, details=details)
        account.delete()
    return public_ids


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
        keep_an_admin: Refuse if USER is the last enabled admin (_keep_an_admin).

    Yields:
        A fresh copy of the account to change; USER is refreshed afterwards.
    """
    with transaction.atomic():
        if keep_an_admin:
            _keep_an_admin(user)
        account = User.objects.select_for_update().get(pk=user.pk)
        if states and account.state not in states:
            raise ValidationError(
                f"Not allowed while the account is {account.state}.", code="invalid_state"
            )
        yield account
    user.refresh_from_db()


def _clean_email(email: str) -> str:
    email = email.strip()
    if email:
        validate_email(email)
    return email


def _clean_display_name(display_name: str) -> str:
    """One line of plain text, up to 255 characters."""
    display_name = display_name.strip()
    if len(display_name) > DISPLAY_NAME_LENGTH:
        raise ValidationError(
            f"Use at most {DISPLAY_NAME_LENGTH} characters.", code="display_name_too_long"
        )
    if any(unicodedata.category(c) == "Cc" for c in display_name):
        raise ValidationError(
            "Use one line, without control characters.", code="display_name_control_character"
        )
    return display_name


def _clean_comment(comment: str) -> str:
    """Plain text, line breaks allowed, up to 1,000 characters."""
    comment = comment.replace("\r\n", "\n").strip()
    if len(comment) > COMMENT_LENGTH:
        raise ValidationError(
            f"Use at most {COMMENT_LENGTH:,} characters.", code="comment_too_long"
        )
    if any(unicodedata.category(c) == "Cc" and c not in "\n\t" for c in comment):
        raise ValidationError(
            "Don't use control characters other than line breaks and tabs.",
            code="comment_control_character",
        )
    return comment


def _keep_an_admin(user: User) -> None:
    """Refuse if USER is the last enabled admin (spec §9.1). Call it in a transaction.

    Every enabled admin is locked first, in ID order, so two admins changing each
    other at once queue instead of both passing the check or deadlocking.
    """
    admins = list(
        enabled_admins().select_for_update(of=("self",)).order_by("pk").values_list("pk", flat=True)
    )
    if admins == [user.pk]:
        raise ValidationError(
            "This is the last enabled admin account; make another admin first.",
            code="last_admin",
        )


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
