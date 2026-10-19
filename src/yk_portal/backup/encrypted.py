"""The encrypted backup file (spec §28.1; addendum §19): a header anyone can read,
then the payload in AES-256-GCM segments.

    yk-portal-backup 1                    magic and format version
    {"application_version": ...}          the header: one line of JSON
    segment 0, segment 1, ... last        each AES-256-GCM ciphertext and its 16-byte tag

`head -n 2 FILE` shows which backup a file is, when it was made, by which
version and with which master key, without the key. The header holds no
secret, but it is authenticated: it is the associated data of every segment,
so a changed header fails as a changed segment does.

The payload is encrypted in segments, as Tink's streaming AEAD
(AES256_GCM_HKDF) does it, so a backup of any size is encrypted and checked
without holding it in memory or writing it anywhere unencrypted:

- each backup has its own key, derived with HKDF-SHA256 from the backup key
  (itself derived from the master key) and the header's random salt, so no
  two backups share a key and nonces can't repeat;
- segment N's nonce is the header's random 7-byte prefix, N as 4 bytes, and
  one byte that is 1 for the last segment, else 0: a segment moved, dropped
  or repeated fails its check, and so does a file cut short, whose last
  segment wasn't encrypted as the last;
- each segment holds segment_bytes of payload, except the last, which holds
  the rest, possibly nothing.
"""

import dataclasses
import json
import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FORMAT_VERSION = 1
MAGIC = b"yk-portal-backup "
CIPHER = "AES-256-GCM"
SEGMENT_BYTES = 64 * 1024
TAG_BYTES = 16
SALT_BYTES = 32
NONCE_PREFIX_BYTES = 7
KEY_ID_BYTES = 8
_MAX_SEGMENTS = 2**32
_MAX_HEADER_BYTES = 64 * 1024


class BackupError(Exception):
    """A backup can't be made, read or restored: a file that isn't a backup this
    version can read or that fails its checks, or a database not ready for it. The
    database is unchanged."""


@dataclass(frozen=True)
class Header:
    """What the header says about a backup: everything but the contents."""

    id: uuid.UUID
    created_at: datetime
    application_version: str
    # The database it was made from: sqlite or postgresql.
    database: str
    # Each app's last migration, which a restore's database must have too.
    schema: dict[str, str]
    # The ID of the master key whose backup key encrypted it.
    key_id: bytes
    salt: bytes = field(repr=False)
    nonce_prefix: bytes = field(repr=False)
    segment_bytes: int = SEGMENT_BYTES
    cipher: str = CIPHER
    # The two lines as read from a file, which its segments authenticate; empty for a
    # new header, whose lines are to_bytes().
    lines: bytes = field(default=b"", repr=False, compare=False)

    @classmethod
    def new(
        cls,
        application_version: str,
        database: str,
        schema: dict[str, str],
        key_id: bytes,
        created_at: datetime,
    ) -> Header:
        """The header of a new backup, with its own ID, salt and nonce prefix."""
        return cls(
            id=uuid.uuid4(),
            created_at=created_at,
            application_version=application_version,
            database=database,
            schema=schema,
            key_id=key_id,
            salt=os.urandom(SALT_BYTES),
            nonce_prefix=os.urandom(NONCE_PREFIX_BYTES),
        )

    def associated_data(self) -> bytes:
        """What every segment authenticates: the two header lines, byte for byte."""
        return self.lines or self.to_bytes()

    def to_bytes(self) -> bytes:
        """The two header lines of a new backup."""
        fields = {
            "id": str(self.id),
            "created_at": self.created_at.isoformat(),
            "application_version": self.application_version,
            "database": self.database,
            "schema": self.schema,
            "cipher": self.cipher,
            "key_id": self.key_id.hex(),
            "salt": self.salt.hex(),
            "nonce_prefix": self.nonce_prefix.hex(),
            "segment_bytes": self.segment_bytes,
        }
        text = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        return MAGIC + f"{FORMAT_VERSION}\n{text}\n".encode()


def _file_key(backup_key: bytes, header: Header) -> AESGCM:
    hkdf = HKDF(algorithm=SHA256(), length=32, salt=header.salt, info=b"yk-portal/v1/backup-file")
    return AESGCM(hkdf.derive(backup_key))


def _nonce(header: Header, index: int, last: bool) -> bytes:
    if index >= _MAX_SEGMENTS:
        raise BackupError("too large: a backup has at most 2^32 segments")
    return header.nonce_prefix + index.to_bytes(4, "big") + bytes([last])


class EncryptingWriter:
    """Writes a backup to OUT: the header at once, then the payload given to write(),
    encrypted a segment at a time. close() writes the last segment; without it, the
    backup is incomplete and fails its check."""

    def __init__(self, out: BinaryIO, header: Header, backup_key: bytes) -> None:
        self._out = out
        self._header = header
        self._associated_data = header.associated_data()
        self._aead = _file_key(backup_key, header)
        self._pending = bytearray()
        self._index = 0
        self.size = 0  # bytes written so far
        self._emit(self._associated_data)

    def write(self, data: bytes) -> None:
        self._pending += data
        segment = self._header.segment_bytes
        # Keep what may be the last segment until close(): it must be marked last.
        while len(self._pending) > segment:
            self._encrypt(bytes(self._pending[:segment]), last=False)
            del self._pending[:segment]

    def close(self) -> None:
        self._encrypt(bytes(self._pending), last=True)
        self._pending.clear()

    def _encrypt(self, plaintext: bytes, last: bool) -> None:
        nonce = _nonce(self._header, self._index, last)
        self._emit(self._aead.encrypt(nonce, plaintext, self._associated_data))
        self._index += 1

    def _emit(self, data: bytes) -> None:
        self._out.write(data)
        self.size += len(data)


def read_header(file: BinaryIO) -> Header:
    """Read and check the header, leaving FILE at the first segment.

    The header is authenticated, byte for byte, only once the first segment is checked,
    by decrypt_segments().

    Raises:
        BackupError: Not a backup, a format this version doesn't read, or a damaged header.
    """
    first = file.readline(64)
    if not first.startswith(MAGIC):
        raise BackupError("not a yk-portal backup")
    version = first.removeprefix(MAGIC).rstrip(b"\n")
    if version != str(FORMAT_VERSION).encode():
        shown = version.decode("ascii", errors="replace")
        raise BackupError(
            f"backup format {shown}: this version of yk-portal reads format {FORMAT_VERSION}"
        )
    line = file.readline(_MAX_HEADER_BYTES)
    if not line.endswith(b"\n"):
        raise BackupError("the header is damaged (no complete second line)")
    try:
        header = _parse_header(json.loads(line))
    except (ValueError, TypeError, KeyError) as e:
        raise BackupError(f"the header is damaged ({e})") from None
    return dataclasses.replace(header, lines=first + line)


def _parse_header(data: Any) -> Header:
    if not isinstance(data, dict):
        raise TypeError("not a JSON object")

    def text(key: str) -> str:
        value = data[key]
        if not isinstance(value, str):
            raise TypeError(f"{key} isn't text")
        return value

    def hex_bytes(key: str, length: int) -> bytes:
        value = bytes.fromhex(text(key))
        if len(value) != length:
            raise ValueError(f"{key} isn't {length} bytes")
        return value

    if text("cipher") != CIPHER:
        raise ValueError(f"cipher {data['cipher']}: only {CIPHER} is known")
    schema = data["schema"]
    if not isinstance(schema, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in schema.items()
    ):
        raise TypeError("schema isn't a list of migrations")
    segment_bytes = data["segment_bytes"]
    if type(segment_bytes) is not int or not 1024 <= segment_bytes <= 16 * 1024 * 1024:
        raise ValueError("segment_bytes is out of range")
    created_at = datetime.fromisoformat(text("created_at"))
    if created_at.tzinfo is None:
        raise ValueError("created_at has no time zone")
    return Header(
        id=uuid.UUID(text("id")),
        created_at=created_at,
        application_version=text("application_version"),
        database=text("database"),
        schema=schema,
        key_id=hex_bytes("key_id", KEY_ID_BYTES),
        salt=hex_bytes("salt", SALT_BYTES),
        nonce_prefix=hex_bytes("nonce_prefix", NONCE_PREFIX_BYTES),
        segment_bytes=segment_bytes,
    )


def decrypt_segments(file: BinaryIO, header: Header, backup_key: bytes) -> Iterator[bytes]:
    """Each segment's payload, in order, once it has passed its check.

    Raises:
        BackupError: A segment fails its check: changed, moved or missing, the file cut
            short or longer than written, or encrypted with another master key's key.
    """
    aead = _file_key(backup_key, header)
    associated_data = header.associated_data()
    size = header.segment_bytes + TAG_BYTES
    current = _read(file, size)
    if len(current) < TAG_BYTES:
        raise BackupError("damaged: the encrypted data is missing or cut short")
    index = 0
    while True:
        # Only a full segment is followed by more: _read() returns less only at the end.
        following = _read(file, size)
        last = not following
        try:
            plaintext = aead.decrypt(_nonce(header, index, last), current, associated_data)
        except InvalidTag:
            raise BackupError(
                f"authentication failed at segment {index}: the backup was changed, "
                "damaged or cut short"
            ) from None
        yield plaintext
        if last:
            return
        current, index = following, index + 1


def _read(file: BinaryIO, size: int) -> bytes:
    """SIZE bytes, or fewer at the end of the file: a pipe may return less at a time."""
    data = bytearray()
    while len(data) < size:
        chunk = file.read(size - len(data))
        if not chunk:
            break
        data += chunk
    return bytes(data)
