import dataclasses
import io
import json
import os
from datetime import UTC, datetime

import pytest

from yk_portal.backup.encrypted import (
    TAG_BYTES,
    BackupError,
    EncryptingWriter,
    Header,
    decrypt_segments,
    read_header,
)

KEY = bytes(range(32))
SEGMENT = 1024  # small, so a few kilobytes make several segments
OTHER_TIME = "2020-01-01T00:00:00+00:00"
SCHEMA = {"accounts": "0006_user_display_name_comment", "audit": "0005_details_unicode"}


def header(**changes: object) -> Header:
    made = Header.new("0.1.0", "sqlite", SCHEMA, b"\x01" * 8, datetime(2026, 10, 18, tzinfo=UTC))
    return dataclasses.replace(made, segment_bytes=SEGMENT, **changes)


def encrypt(payload: bytes, made: Header | None = None, key: bytes = KEY) -> bytes:
    out = io.BytesIO()
    writer = EncryptingWriter(out, made or header(), key)
    for start in range(0, len(payload), 300):  # in pieces, as rows are written
        writer.write(payload[start : start + 300])
    writer.close()
    assert writer.size == len(out.getvalue())
    return out.getvalue()


def decrypt(data: bytes, key: bytes = KEY) -> bytes:
    file = io.BytesIO(data)
    return b"".join(decrypt_segments(file, read_header(file), key))


def segments(data: bytes) -> tuple[bytes, list[bytes]]:
    """The header lines and each encrypted segment of a backup."""
    first, second, rest = data.split(b"\n", 2)
    size = SEGMENT + TAG_BYTES
    return first + b"\n" + second + b"\n", [rest[n : n + size] for n in range(0, len(rest), size)]


@pytest.mark.parametrize("size", [0, 1, SEGMENT - 1, SEGMENT, SEGMENT + 1, 3 * SEGMENT, 5000])
def test_round_trip(size):
    payload = os.urandom(size)
    data = encrypt(payload)
    assert decrypt(data) == payload
    _, parts = segments(data)
    # Full segments, then the last with the rest: possibly nothing, never more than one.
    assert len(parts) == max(1, -(-size // SEGMENT))
    assert all(len(part) == SEGMENT + TAG_BYTES for part in parts[:-1])


def test_the_header_is_readable_and_holds_no_secret():
    made = header()
    data = encrypt(b"alice,secret\n" * 10, made)
    first, second, _ = data.split(b"\n", 2)
    assert first == b"yk-portal-backup 1"
    fields = json.loads(second)
    assert fields == {
        "id": str(made.id),
        "created_at": "2026-10-18T00:00:00+00:00",
        "application_version": "0.1.0",
        "database": "sqlite",
        "schema": SCHEMA,
        "cipher": "AES-256-GCM",
        "key_id": "0101010101010101",
        "salt": made.salt.hex(),
        "nonce_prefix": made.nonce_prefix.hex(),
        "segment_bytes": SEGMENT,
    }
    assert KEY not in data and b"alice" not in data
    assert read_header(io.BytesIO(data)) == made


def test_each_backup_has_its_own_key_and_nonces():
    a, b = header(), header()
    assert a.id != b.id and a.salt != b.salt and a.nonce_prefix != b.nonce_prefix
    payload = b"x" * 100
    assert segments(encrypt(payload, a))[1] != segments(encrypt(payload, b))[1]


def flip(data: bytes, position: int) -> bytes:
    return data[:position] + bytes([data[position] ^ 1]) + data[position + 1 :]


def test_a_changed_header_fails_authentication():
    data = encrypt(b"payload " * 500)
    head, _ = segments(data)
    # "2026-10-18" made "2026-10-19": still a valid header, but not this backup's.
    changed = data.replace(b'"created_at":"2026-10-18', b'"created_at":"2026-10-19', 1)
    assert changed != data and len(changed) == len(data)
    with pytest.raises(BackupError, match="authentication failed at segment 0"):
        decrypt(changed)
    with pytest.raises(BackupError, match="authentication failed at segment 0"):
        decrypt(head.replace(b'"0.1.0"', b'"0.1.1"') + data[len(head) :])


@pytest.mark.parametrize("where", ["first segment", "middle", "last tag"])
def test_a_changed_segment_fails_authentication(where):
    data = encrypt(os.urandom(3 * SEGMENT + 10))
    head, parts = segments(data)
    position = {
        "first segment": len(head),
        "middle": len(head) + len(parts[0]) + 500,
        "last tag": len(data) - 1,
    }[where]
    with pytest.raises(BackupError, match="authentication failed"):
        decrypt(flip(data, position))


def test_segments_moved_dropped_or_repeated_fail():
    head, parts = segments(encrypt(os.urandom(3 * SEGMENT + 10)))
    for changed in (
        [parts[1], parts[0], parts[2], parts[3]],  # swapped
        [parts[0], parts[2], parts[3]],  # one missing
        [parts[0], parts[0], parts[1], parts[2], parts[3]],  # one repeated
    ):
        with pytest.raises(BackupError, match="authentication failed"):
            decrypt(head + b"".join(changed))


def test_a_file_cut_short_fails():
    data = encrypt(os.urandom(3 * SEGMENT + 10))
    head, parts = segments(data)
    # At a segment's end: what is now last wasn't encrypted as the last.
    with pytest.raises(BackupError, match="authentication failed at segment 2"):
        decrypt(head + b"".join(parts[:3]))
    with pytest.raises(BackupError, match="authentication failed at segment 3"):
        decrypt(data[:-1])
    with pytest.raises(BackupError, match="encrypted data is missing"):
        decrypt(head)
    with pytest.raises(BackupError, match="encrypted data is missing"):
        decrypt(head + parts[0][: TAG_BYTES - 1])


def test_data_after_the_end_fails():
    data = encrypt(os.urandom(2 * SEGMENT + 10))
    with pytest.raises(BackupError, match="authentication failed at segment 2"):
        decrypt(data + b"more")
    full = encrypt(os.urandom(2 * SEGMENT))  # its last segment is a full one
    with pytest.raises(BackupError, match="authentication failed at segment 1"):
        decrypt(full + b"more")


def test_another_key_fails():
    with pytest.raises(BackupError, match="authentication failed at segment 0"):
        decrypt(encrypt(b"payload"), key=bytes(32))


def test_a_header_from_another_backup_fails():
    a, b = encrypt(b"payload a"), encrypt(b"payload b")
    head_a, _ = segments(a)
    head_b, _ = segments(b)
    with pytest.raises(BackupError, match="authentication failed"):
        decrypt(head_b + a[len(head_a) :])


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "not a yk-portal backup"),
        (b"username,public_id\n", "not a yk-portal backup"),
        (b"yk-portal-backup 2\n{}\n", "backup format 2: this version of yk-portal reads format 1"),
        (b"yk-portal-backup 1\n", "the header is damaged \\(no complete second line\\)"),
        (b"yk-portal-backup 1\n{\n", "the header is damaged"),
        (b"yk-portal-backup 1\n[]\n", "the header is damaged \\(not a JSON object\\)"),
        (b"yk-portal-backup 1\n{}\n", "the header is damaged \\('cipher'\\)"),
    ],
)
def test_not_a_backup(data, message):
    with pytest.raises(BackupError, match=message):
        read_header(io.BytesIO(data))


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"cipher": "AES-128-CBC"}, "cipher AES-128-CBC: only AES-256-GCM is known"),
        ({"salt": "00"}, "salt isn't 32 bytes"),
        ({"key_id": "zz"}, "non-hexadecimal"),
        ({"segment_bytes": 10}, "segment_bytes is out of range"),
        ({"segment_bytes": True}, "segment_bytes is out of range"),
        ({"created_at": "2026-10-18T00:00:00"}, "created_at has no time zone"),
        ({"schema": ["accounts"]}, "schema isn't a list of migrations"),
        ({"id": 7}, "id isn't text"),
    ],
)
def test_a_damaged_header(change, message):
    first, second, rest = encrypt(b"payload").split(b"\n", 2)
    fields = json.loads(second) | change
    data = first + b"\n" + json.dumps(fields).encode() + b"\n" + rest
    with pytest.raises(BackupError, match=message):
        read_header(io.BytesIO(data))


class Trickle(io.RawIOBase):
    """A pipe that returns at most 100 bytes a read."""

    def __init__(self, data: bytes) -> None:
        self._data = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        chunk = self._data.read(min(len(buffer), 100))
        buffer[: len(chunk)] = chunk
        return len(chunk)


def test_short_reads_from_a_pipe():
    payload = os.urandom(3 * SEGMENT + 10)
    file = io.BufferedReader(Trickle(encrypt(payload)), buffer_size=64)
    assert b"".join(decrypt_segments(file, read_header(file), KEY)) == payload


@pytest.mark.parametrize(
    "rewrite",
    [
        lambda h: json.dumps(h),  # spaces after separators
        lambda h: json.dumps(dict(reversed(h.items())), separators=(",", ":")),  # key order
        lambda h: json.dumps(h | {"salt": h["salt"].upper()}, separators=(",", ":")),
        lambda h: json.dumps(h | {"note": "harmless?"}, separators=(",", ":")),
        # A duplicate key: a reader of `head -n 2` sees one time, the parser the other.
        lambda h: json.dumps(h, separators=(",", ":"))[:-1] + f',"created_at":"{OTHER_TIME}"}}',
    ],
)
def test_the_header_is_authenticated_byte_for_byte(rewrite):
    first, second, rest = encrypt(b"payload").split(b"\n", 2)
    changed = rewrite(json.loads(second)).encode()
    assert changed != second
    with pytest.raises(BackupError, match="authentication failed at segment 0"):
        decrypt(first + b"\n" + changed + b"\n" + rest)
