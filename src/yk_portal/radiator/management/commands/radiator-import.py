import os
import sys
from argparse import ArgumentParser
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from yk_portal.audit.service import Actor
from yk_portal.core.encryption import DecryptionError
from yk_portal.core.master_key import MasterKeyError
from yk_portal.radiator import csvfile, importer
from yk_portal.radiator.importer import Kind


class Command(BaseCommand):
    help = (
        "Import a file written by `yubikey-db.sh export` (addendum §7): create the accounts and "
        "add the YubiKeys yk-portal doesn't have, and move counters forward for those it has. "
        "Every row is checked first; nothing is imported if one is invalid."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "file", metavar="FILE", help="the export file, or - to read standard input"
        )
        parser.add_argument(
            "--dry-run", action="store_true", help="report what would happen, and change nothing"
        )
        parser.add_argument(
            "--skip-invalid",
            action="store_true",
            help="import the valid rows even if some are invalid",
        )
        parser.add_argument(
            "--counters-only",
            action="store_true",
            help="only move counters forward, for the YubiKeys yk-portal has (for cron)",
        )

    def handle(self, *args: object, **options: object) -> None:
        file = str(options["file"])
        try:
            if file == "-":
                source, data = "standard input", sys.stdin.buffer.read()
            else:
                source, data = os.path.abspath(file), Path(file).read_bytes()
        except OSError as e:
            raise CommandError(f"cannot read {file}: {e.strerror}") from None
        try:
            report = importer.run(
                data,
                Actor.cli(),
                source,
                counters_only=bool(options["counters_only"]),
                dry_run=bool(options["dry_run"]),
                skip_invalid=bool(options["skip_invalid"]),
            )
        except csvfile.CsvError as e:
            raise CommandError(f"{file}: {e}") from None
        except (importer.ImportFailed, DecryptionError, MasterKeyError) as e:
            raise CommandError(str(e)) from None
        for row in report.rows:
            self.stdout.write(str(row))
        self.stdout.write(report.summary())
        invalid = report.count(Kind.INVALID)
        if invalid and not options["skip_invalid"]:
            rows = "row" if invalid == 1 else "rows"
            raise CommandError(
                f"nothing imported: {invalid} invalid {rows} (or use --skip-invalid)"
            )
        if options["dry_run"]:
            self.stdout.write("Dry run: nothing changed.")
