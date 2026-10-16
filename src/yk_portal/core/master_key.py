"""The master key: 256 random bits in a file outside the database (spec §22.4).

The file holds the key as 64 hex characters and a line break, at mode 0600,
owned by the yk-portal service account. Nothing is encrypted with the master
key itself: each purpose gets its own key, derived with HKDF-SHA256 (spec
§22.5), and an 8-byte key ID marks which master key encrypted a value, for
rotation (spec §37).
"""

import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_BYTES = 32
_KEY_TEXT = re.compile(r"[0-9a-f]{64}\n?")


class MasterKeyError(Exception):
    """The master key file is missing, unreadable, too widely readable or malformed."""


@dataclass(frozen=True)
class DerivedKeys:
    """The keys derived from one master key. repr() never shows a key."""

    key_id: bytes
    secrets: bytes = field(repr=False)
    backup: bytes = field(repr=False)
    # For keyed digests that let a unique index cover an encrypted value.
    lookup: bytes = field(repr=False)
    django_secret_key: str = field(repr=False)


def create_master_key(path: Path) -> None:
    """Write a new random master key to PATH, mode 0600. An existing file is never replaced."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise MasterKeyError(f"{path}: already exists; it was not changed") from None
    except OSError as e:
        raise MasterKeyError(f"{path}: cannot create: {e.strerror}") from None
    with os.fdopen(fd, "w", encoding="ascii") as f:
        os.fchmod(fd, 0o600)  # whatever the umask
        f.write(secrets.token_bytes(KEY_BYTES).hex() + "\n")
        f.flush()
        os.fsync(fd)


def load_master_key(path: Path) -> bytes:
    """Read the master key, refusing a file that group or others may read or write."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except FileNotFoundError:
        raise MasterKeyError(
            f"{path}: not found; create it with 'yk-portal master-key-create'"
        ) from None
    except PermissionError:
        raise MasterKeyError(
            f"{path}: permission denied; run as the yk-portal service account or root"
        ) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise MasterKeyError(f"{path}: not a regular file")
        if info.st_mode & 0o077:
            mode = stat.S_IMODE(info.st_mode)
            raise MasterKeyError(
                f"{path}: group or others have access (mode {mode:04o}); run: chmod 600 {path}"
            )
        text = os.read(fd, 200)
    finally:
        os.close(fd)
    # The message never includes the file's contents.
    if not _KEY_TEXT.fullmatch(text.decode("ascii", errors="replace")):
        raise MasterKeyError(f"{path}: not a master key (expected 64 lowercase hex characters)")
    return bytes.fromhex(text.decode("ascii").strip())


def derive_keys(master_key: bytes) -> DerivedKeys:
    """Derive one key per purpose from the master key."""
    if len(master_key) != KEY_BYTES:
        raise ValueError("the master key must be 32 bytes")

    def derive(purpose: str, length: int = KEY_BYTES) -> bytes:
        info = f"yk-portal/v1/{purpose}".encode()
        return HKDF(algorithm=SHA256(), length=length, salt=None, info=info).derive(master_key)

    return DerivedKeys(
        key_id=derive("key-id", 8),
        secrets=derive("stored-secrets"),
        backup=derive("backup"),
        lookup=derive("lookup-digest"),
        django_secret_key=derive("django-secret-key").hex(),
    )
