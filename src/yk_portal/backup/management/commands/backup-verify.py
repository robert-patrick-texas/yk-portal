import sys
from argparse import ArgumentParser
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from yk_portal.backup import service
from yk_portal.backup.cli import show_backup
from yk_portal.backup.encrypted import BackupError
from yk_portal.core.master_key import MasterKeyError


class Command(BaseCommand):
    help = (
        "Check a backup completely, as backup-restore does before changing anything (spec "
        "§29; addendum §19): its format, the authentication of every part, every row, and "
        "that this installation can restore it (the same master key and schema). Changes "
        "nothing. Exits with status 1 if the backup can't be restored here."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("file", metavar="FILE", help="the backup, or - to read standard input")

    def handle(self, *args: object, **options: object) -> None:
        file = str(options["file"])
        try:
            if file == "-":
                summary = service.verify(sys.stdin.buffer)
            else:
                with Path(file).open("rb") as backup:
                    summary = service.verify(backup)
        except OSError as e:
            raise CommandError(f"cannot read {file}: {e.strerror}") from None
        except (BackupError, MasterKeyError) as e:
            raise CommandError(f"{file}: {e}") from None
        show_backup(self.stdout, summary)
        self.stdout.write(
            "Verified: authentic and complete, and this installation can restore it "
            "(the same master key and schema)."
        )
