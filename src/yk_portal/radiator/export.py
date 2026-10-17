"""The export for radiator-yubikey: one CSV row per YubiKey credential (addendum §6).

It is loaded with `yubikey-db.sh import --from-export --replace`: the password
column holds the SHA-512 crypt hash of each YubiKey's PIN, which a plain
`import` would hash again.
"""

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from yk_portal.accounts.models import AccountState
from yk_portal.audit.models import EventType
from yk_portal.audit.service import Actor, record
from yk_portal.core.encryption import DecryptionError
from yk_portal.yubikeys.models import YubikeyCredential

from . import csvfile


class ExportError(Exception):
    """The export can't be written. Nothing was written."""


@dataclass(frozen=True)
class InactiveKey:
    """A YubiKey exported with active=0, and why."""

    username: str
    public_id: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class Export:
    text: str = field(repr=False)
    rows: int
    inactive: list[InactiveKey]


def build() -> Export:
    """The export of every YubiKey credential, ordered by username and public ID.

    A key is active only if its account is ACTIVE and the key is enabled (addendum
    §6.3), so the next load turns the others off in Radiator too.

    Raises:
        ExportError: A stored secret can't be decrypted.
    """
    credentials = sorted(
        YubikeyCredential.objects.select_related("user"),
        key=lambda c: (c.user.username, c.public_id),
    )
    lines = [csvfile.HEADER + "\n"]
    inactive = []
    for credential in credentials:
        user = credential.user
        reasons = []
        if user.state != AccountState.ACTIVE:
            reasons.append(f"account {user.state}")
        if not credential.enabled:
            reasons.append("YubiKey disabled")
        if reasons:
            inactive.append(InactiveKey(user.username, credential.public_id, tuple(reasons)))
        try:
            private_id, aes_key = credential.private_id(), credential.aes_key()
        except DecryptionError as e:
            raise ExportError(
                f"{user.username} {credential.public_id}: secrets can't be decrypted ({e})"
            ) from None
        lines.append(
            csvfile.format_row(
                [
                    user.username,
                    credential.public_id,
                    private_id.hex(),
                    aes_key.hex(),
                    credential.radius_pin_hash,
                    "0" if reasons else "1",
                    csvfile.format_time(credential.created_at),
                    csvfile.format_time(credential.last_used_at),
                    str(credential.last_usage_counter),
                    str(credential.last_session_counter),
                    "0",
                    credential.label,
                ]
            )
        )
    return Export("".join(lines), len(credentials), inactive)


def write_file(path: Path, text: str, force: bool) -> None:
    """Write TEXT to PATH with mode 0600, replacing an existing file only if FORCE.

    The file is written under a temporary name in the same directory, then
    renamed, so a failed export leaves no partial file behind.

    Raises:
        ExportError: PATH exists (without FORCE), is a directory, or can't be written.
    """
    if path.is_dir():
        raise ExportError(f"{path} is a directory")
    if not force and (path.exists() or path.is_symlink()):
        raise ExportError(f"{path} already exists (use --force to replace it)")
    try:
        # mkstemp creates the file with mode 0600.
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".yk-portal-export.")
    except OSError as e:
        raise ExportError(f"cannot write to the directory {path.parent}: {e.strerror}") from None
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as file:
            file.write(text)
            file.flush()
            os.fsync(file.fileno())
        if force:
            os.replace(temporary, path)
        else:
            # A link fails if PATH appeared meanwhile, where a rename would replace it.
            os.link(temporary, path)
    except FileExistsError:
        raise ExportError(f"{path} already exists (use --force to replace it)") from None
    except OSError as e:
        raise ExportError(f"cannot write {path}: {e.strerror}") from None
    finally:
        Path(temporary).unlink(missing_ok=True)


def record_export(actor: Actor, export: Export, destination: str) -> None:
    """The RADIATOR_EXPORT_CREATED audit event: counts and destination, no secret."""
    record(
        EventType.RADIATOR_EXPORT_CREATED,
        actor,
        details={
            "rows": export.rows,
            "inactive": len(export.inactive),
            "destination": destination,
        },
    )
