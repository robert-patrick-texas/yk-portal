import os
from argparse import ArgumentParser
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from yk_portal.audit.service import Actor
from yk_portal.core.master_key import MasterKeyError
from yk_portal.radiator import export


class Command(BaseCommand):
    help = (
        "Write every YubiKey credential in radiator-yubikey's export format (addendum §6), "
        "for `yubikey-db.sh import --from-export --replace`. The file holds every AES key "
        "and private ID in clear text."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("file", metavar="FILE", help="the file to write (mode 0600), or -")
        parser.add_argument("-f", "--force", action="store_true", help="replace FILE if it exists")

    def handle(self, *args: object, **options: object) -> None:
        self.stderr.style_func = None  # a summary, not an error
        file, force = str(options["file"]), bool(options["force"])
        try:
            result = export.build()
            if file == "-":
                destination = "standard output"
                self.stdout.write(result.text, ending="")
            else:
                destination = os.path.abspath(file)
                export.write_file(Path(file), result.text, force)
        except (export.ExportError, MasterKeyError) as e:
            raise CommandError(f"{e}; nothing exported") from None
        export.record_export(Actor.cli(), result, destination)
        where = destination if file == "-" else f"{file} (mode 0600)"
        keys = "YubiKey" if result.rows == 1 else "YubiKeys"
        inactive = f", {len(result.inactive)} inactive:" if result.inactive else "."
        self.stderr.write(f"Exported {result.rows} {keys} to {where}{inactive}")
        for key in result.inactive:
            self.stderr.write(f"  {key.username} {key.public_id}: {', '.join(key.reasons)}")
        if file != "-":
            self.stderr.write(f"It holds AES keys and private IDs in clear text: shred -u {file}")
