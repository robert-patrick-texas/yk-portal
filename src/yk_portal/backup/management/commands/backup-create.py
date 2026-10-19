import sys
from argparse import ArgumentParser
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError
from django.utils import timezone

from yk_portal.audit.service import Actor
from yk_portal.backup import service
from yk_portal.backup.encrypted import BackupError
from yk_portal.core.db import short_message
from yk_portal.core.files import FileWriteError, new_file
from yk_portal.core.master_key import MasterKeyError


class Command(BaseCommand):
    help = (
        "Back up the database to an encrypted file (spec §28; addendum §19): every account, "
        "YubiKey, group, setting and audit event, as of one moment, encrypted with "
        "AES-256-GCM under a key derived from the master key. It can run while yk-portal "
        "runs. Restoring it needs the same master key, which isn't in the backup."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "file",
            metavar="FILE",
            help="the file to write (mode 0600); a directory, to write "
            "yk-portal-YYYYMMDDTHHMMSSZ.backup in it; or - for standard output",
        )
        parser.add_argument("-f", "--force", action="store_true", help="replace FILE if it exists")

    def handle(self, *args: object, **options: object) -> None:
        self.stderr.style_func = None  # a summary, not an error
        file, force = str(options["file"]), bool(options["force"])
        try:
            if file == "-":
                if sys.stdout.isatty():
                    raise CommandError("won't write a backup to a terminal; give a FILE")
                destination = "standard output"
                try:
                    summary, size = service.create(sys.stdout.buffer)
                    sys.stdout.buffer.flush()
                except OSError as e:
                    raise CommandError(
                        f"cannot write to standard output: {e.strerror}; no backup made"
                    ) from None
            else:
                path = Path(file)
                if path.is_dir():
                    path /= f"yk-portal-{timezone.now():%Y%m%dT%H%M%SZ}.backup"
                elif file.endswith("/"):
                    raise CommandError(f"{file}: no such directory; no backup made")
                destination = str(path.absolute())
                with new_file(path, force) as out:
                    summary, size = service.create(out)
        except (BackupError, FileWriteError, MasterKeyError) as e:
            raise CommandError(f"{e}; no backup made") from None
        except DatabaseError as e:
            raise CommandError(
                f"the database can't be read: {short_message(e)}; no backup made"
            ) from None
        where = destination if file == "-" else f"{path} (mode 0600, {size:,} bytes)"
        try:
            service.record_created(Actor.cli(), summary, destination, size)
        except DatabaseError as e:
            raise CommandError(
                f"backed up to {where}, but its BACKUP_CREATED audit event couldn't be "
                f"recorded: {short_message(e)}"
            ) from None
        if options["verbosity"] == 0:  # for cron: nothing to say when all went well
            return
        self.stderr.write(f"Backed up {summary.contents()} to {where}.")
        self.stderr.write(
            f"Backup ID {summary.header.id}. Restoring it needs this master key (ID "
            f"{summary.header.key_id.hex()}): keep a copy of the key apart from the backups."
        )
