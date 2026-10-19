from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from yk_portal.core.database_status import database_status


class Command(BaseCommand):
    help = (
        "Show which database yk-portal uses and whether it is ready: reachable, migrated, "
        "its audit log protected, and set up as addendum §18 recommends. Exits with "
        "status 1 if there is a problem; warnings don't change the status."
    )

    requires_system_checks = []  # reports on the database even when checks would fail

    def handle(self, *args: object, **options: object) -> None:
        status = database_status(connection)
        width = max((len(label) for label, _ in status.lines), default=0) + 2
        for label, text in status.lines:
            self.stdout.write(f"{label + ':':<{width}}{text}")
        for warning in status.warnings:
            self.stdout.write(f"Warning: {warning}")
        if status.problems:
            for problem in status.problems:
                self.stderr.write(f"Problem: {problem}")
            count = len(status.problems)
            raise CommandError(f"the database isn't ready ({count} problem{'s' * (count > 1)})")
