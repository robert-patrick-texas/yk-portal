from argparse import ArgumentParser
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError

from yk_portal.audit.service import Actor
from yk_portal.backup import service
from yk_portal.backup.cli import show_backup
from yk_portal.backup.encrypted import BackupError
from yk_portal.core.db import short_message
from yk_portal.core.master_key import MasterKeyError

CONFIRMATION = "restore"


class Command(BaseCommand):
    help = (
        "Restore a backup (spec §29; addendum §19): check it completely, then replace every "
        "account, YubiKey, group and setting with the backup's in one transaction, which "
        "changes nothing if anything fails. OTP counters never move back, the audit events "
        "recorded since the backup are kept, and every session ends."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("file", metavar="FILE", help="the backup")
        parser.add_argument(
            "--replace",
            action="store_true",
            help="replace the database's accounts, YubiKeys, groups and settings; without "
            "it, the database must hold none",
        )
        parser.add_argument(
            "--noinput",
            "--no-input",
            action="store_false",
            dest="interactive",
            help=f'don\'t ask to type "{CONFIRMATION}" first',
        )

    def handle(self, *args: object, **options: object) -> None:
        path, replace = Path(str(options["file"])), bool(options["replace"])
        try:
            with path.open("rb") as file:
                summary = service.verify(file)
            show_backup(self.stdout, summary)
            self.stdout.write("Verified: authentic and complete.")
            contents = service.database_contents()
            if service.holds_data(contents) and not replace:
                raise BackupError(
                    f"the database isn't empty: it holds {service.describe(contents)}; "
                    "to replace them, use --replace"
                )
            if options["interactive"]:
                self._confirm(contents)
            with path.open("rb") as file:
                restored = service.restore(
                    file, Actor.cli(), replace=replace, backup_id=summary.header.id
                )
        except OSError as e:
            raise CommandError(f"cannot read {path}: {e.strerror}") from None
        except (BackupError, MasterKeyError) as e:
            raise CommandError(f"{path}: {e}; nothing was restored") from None
        except DatabaseError as e:
            raise CommandError(
                f"the database refused the restore, so nothing changed: {short_message(e)}"
            ) from None
        self._report(restored)

    def _confirm(self, contents: dict[str, int]) -> None:
        self.stdout.write(
            f"The database holds {service.describe(contents)}: the restore replaces them "
            "with the backup's. Its audit events are kept, and the backup's added."
        )
        self.stdout.write("Every session ends: everyone signs in again.")
        try:
            answer = input(f'Type "{CONFIRMATION}" to restore this backup: ')
        except EOFError:
            raise CommandError(
                f'not confirmed: type "{CONFIRMATION}", or use --no-input; nothing was restored'
            ) from None
        if answer.strip() != CONFIRMATION:
            raise CommandError("not confirmed; nothing was restored")

    def _report(self, restored: service.Restored) -> None:
        summary = restored.summary
        self.stdout.write(f"Restored backup {summary.header.id}: {summary.contents()}.")
        if restored.counters_kept:
            keys = service.count(restored.counters_kept, "YubiKey", "YubiKeys")
            self.stdout.write(
                f"Kept the database's OTP counters for {keys}, which were ahead of the backup's."
            )
        if restored.audit_events_kept:
            events = service.count(restored.audit_events_kept, "audit event", "audit events")
            self.stdout.write(f"Kept {events} that the backup doesn't have.")
        if restored.audit_events_restored:
            events = service.count(restored.audit_events_restored, "audit event", "audit events")
            self.stderr.write(
                f"Warning: put back {events} as the backup has them: the database's differed, "
                "so the audit log was changed outside yk-portal."
            )
        if summary.counts["yubikey_credentials"]:
            self.stdout.write(
                "A YubiKey used since the backup was made can have OTP counters behind its "
                "last OTP. If radiator-yubikey has newer ones, move them forward:\n"
                "  yubikey-db.sh export - | yk-portal radiator-import --counters-only -"
            )
