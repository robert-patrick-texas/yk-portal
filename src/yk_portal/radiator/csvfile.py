"""radiator-yubikey's export format, which yubikey-db.sh export writes and
`import --from-export` reads (addendum §1.2, §6.2).

The header is required. Fields with a comma, quote or line break are quoted,
with quotes doubled; lines end with LF (CRLF is read too). Times are UTC,
`YYYY-MM-DD HH:MM:SS`. Files are read the way yubikey-db.sh reads them, so
both accept the same files.
"""

import re
from datetime import UTC, datetime

COLUMNS = (
    "username",
    "public_id",
    "private_id",
    "aes_key",
    "password",
    "active",
    "created",
    "accessed",
    "counter",
    "low",
    "high",
    "label",
)
HEADER = ",".join(COLUMNS)
# radiator-yubikey before 1.8.0 had no label column.
OLD_HEADER = ",".join(COLUMNS[:-1])

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
_TIME = re.compile(
    r"[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01]) ([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
)

_NEEDS_QUOTES = re.compile(r'[",\r\n]')
_QUOTED = re.compile(rb'"((?:[^"]|"")*)"')
_UNQUOTED = re.compile(rb'[^",\r\n]*')
_LINE_END = re.compile(rb"\r?\n")


class CsvError(Exception):
    """The file isn't an export file, or isn't CSV. Nothing in it can be used."""


def format_row(values: list[str]) -> str:
    """One CSV line, with its LF."""
    return ",".join(_field(v) for v in values) + "\n"


def _field(value: str) -> str:
    if _NEEDS_QUOTES.search(value):
        return '"' + value.replace('"', '""') + '"'
    return value


def format_time(value: datetime | None) -> str:
    """VALUE in UTC as YYYY-MM-DD HH:MM:SS, or empty for None."""
    return value.astimezone(UTC).strftime(TIME_FORMAT) if value else ""


def parse_time(text: str) -> datetime | None:
    """A UTC time written as YYYY-MM-DD HH:MM:SS, or None if TEXT isn't one."""
    if not _TIME.fullmatch(text):
        return None
    try:
        return datetime.strptime(text, TIME_FORMAT).replace(tzinfo=UTC)
    except ValueError:  # a day the month doesn't have
        return None


def read(data: bytes) -> tuple[int, list[tuple[int, list[bytes]]]]:
    """Split an export file into rows of fields, as yubikey-db.sh does.

    Blank lines are skipped. Fields are bytes; a quoted one may hold commas,
    doubled quotes and line breaks.

    Returns:
        The number of columns of the header (12, or 11 for a file made before
        radiator-yubikey 1.8.0), and each row's line number and fields.

    Raises:
        CsvError: The file is empty, isn't CSV, or doesn't start with the header.
    """
    columns = 0
    rows: list[tuple[int, list[bytes]]] = []
    position, line = 0, 1
    while position < len(data):
        start, fields = line, []
        while True:
            if quoted := _QUOTED.match(data, position):
                value = quoted.group(1)
                line += value.count(b"\n")
                fields.append(value.replace(b'""', b'"'))
                position = quoted.end()
            else:
                unquoted = _UNQUOTED.match(data, position)
                assert unquoted is not None  # noqa: S101 - it matches the empty string
                fields.append(unquoted.group())
                position = unquoted.end()
            if data.startswith(b",", position):
                position += 1
                continue
            if end := _LINE_END.match(data, position):
                position = end.end()
                line += 1
                break
            if position >= len(data):
                break
            raise CsvError(
                f"line {start}: malformed CSV (a quote inside an unquoted field, or an "
                "unterminated quoted field)"
            )
        if fields == [b""]:
            continue
        if not columns:
            if b",".join(fields) not in (HEADER.encode(), OLD_HEADER.encode()):
                raise CsvError(f"not an export file; its first line must be:\n  {HEADER}")
            columns = len(fields)
            continue
        rows.append((start, fields))
    if not columns:
        raise CsvError("the file is empty")
    return columns, rows
