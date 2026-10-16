from argparse import ArgumentParser

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand

from yk_portal.accounts.cli import command_error, show_temporary_password
from yk_portal.accounts.services import bootstrap_admin
from yk_portal.audit.service import Actor


class Command(BaseCommand):
    help = (
        "Create the first admin account, in PROVISIONING with a temporary password (spec §8). "
        "Refused once any admin account exists: use create-admin then."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("username", nargs="?", help="the username (prompted for if left out)")

    def handle(self, *args: object, **options: str | None) -> None:
        username = options["username"] or input("Username: ")
        try:
            account = bootstrap_admin(username, Actor.cli())
        except ValidationError as e:
            raise command_error(e) from None
        self.stdout.write(f"Created the admin account {account.user.username}.")
        show_temporary_password(self.stdout, account.user, account.temporary_password)
