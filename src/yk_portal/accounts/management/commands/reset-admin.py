from argparse import ArgumentParser

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from yk_portal.accounts.cli import command_error, show_temporary_password
from yk_portal.accounts.models import AccountState, User
from yk_portal.accounts.services import (
    normalize_username,
    reset_to_provisioning,
    set_temporary_password,
)
from yk_portal.audit.service import Actor


class Command(BaseCommand):
    help = (
        "Give an admin account a new temporary password, resetting it to PROVISIONING "
        "(spec §15, §36): for when no admin can sign in."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("username")

    def handle(self, *args: object, **options: str) -> None:
        username = normalize_username(options["username"])
        user = User.objects.filter(username=username).first()
        if user is None or not user.is_admin:
            raise CommandError(f"{username} is not an admin account.")
        try:
            if user.state == AccountState.PROVISIONING:
                temporary_password = set_temporary_password(user, Actor.cli())
                done = "Issued a new temporary password to"
            else:
                temporary_password = reset_to_provisioning(user, Actor.cli())
                done = "Reset to PROVISIONING"
        except ValidationError as e:
            raise command_error(e) from None
        self.stdout.write(f"{done} the admin account {user.username}.")
        show_temporary_password(self.stdout, user, temporary_password)
