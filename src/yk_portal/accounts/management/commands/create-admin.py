from argparse import ArgumentParser

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand

from yk_portal.accounts.cli import command_error, show_temporary_password
from yk_portal.accounts.services import create_user
from yk_portal.audit.service import Actor


class Command(BaseCommand):
    help = (
        "Create another admin account, in PROVISIONING with a temporary password (spec §36). "
        "It gets the default group, if one is set."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("username")
        parser.add_argument("--email", default="", help="the account's email address")

    def handle(self, *args: object, **options: str) -> None:
        try:
            account = create_user(
                options["username"], Actor.cli(), email=options["email"], admin=True
            )
        except ValidationError as e:
            raise command_error(e) from None
        self.stdout.write(f"Created the admin account {account.user.username}.")
        show_temporary_password(self.stdout, account.user, account.temporary_password)
