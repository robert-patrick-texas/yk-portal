"""Shared by the account management commands."""

from django.core.exceptions import ValidationError
from django.core.management.base import CommandError, OutputWrapper

from yk_portal.accounts.models import User


def command_error(error: ValidationError) -> CommandError:
    """A CommandError with the messages of a broken rule."""
    return CommandError(" ".join(error.messages))


def show_temporary_password(stdout: OutputWrapper, user: User, temporary_password: str) -> None:
    """Print an account's new temporary password, the one time it is shown."""
    expires = user.temporary_password_expires_at
    assert expires is not None  # noqa: S101 - every temporary password has an expiry
    stdout.write(f"Temporary password: {temporary_password}")
    stdout.write(
        f"It expires {expires:%Y-%m-%d %H:%M} UTC. Give it to {user.username} privately: "
        "they sign in with it, then set a permanent password and add a YubiKey."
    )
