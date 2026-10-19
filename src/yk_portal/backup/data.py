"""The backup's contents: a logical export of every table, as JSON Lines (spec §28;
addendum §19.2).

    {"table":"users","columns":["id","username",...]}
    ["7d0e3c5a-...","alice",...]
    ...

Each table starts with a line naming its columns; then one line per row lists
its values in that order. Tables come parents first, rows in primary-key order,
so the same database always gives the same text, and either backend gives the
same text for the same values, but for the order of keys in a JSON column's
objects, which PostgreSQL chooses. Values are JSON: text, whole numbers, true
and false, null; times in ISO 8601 with microseconds (Django's JSON serializer
keeps only milliseconds, addendum §17.1); UUIDs with hyphens; IP addresses as
Django writes them; binary values (the encrypted YubiKey secrets) in Base64;
JSON columns as they are.

Every row written is read back as a restore would read it, so a backup that
was made can be restored.

Sessions aren't backed up: a restore ends every session.
"""

import base64
import binascii
import functools
import json
import uuid
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime
from typing import Any

from django.core.exceptions import ValidationError
from django.db import models

from yk_portal.accounts.models import Group, Role, User, UserGroup, UserRole
from yk_portal.audit.models import AuditEvent
from yk_portal.core.db import CodePoint
from yk_portal.portal_settings.models import Setting
from yk_portal.yubikeys.models import YubikeyCredential

from .encrypted import BackupError

# Parents before the tables that refer to them.
TABLES: tuple[type[models.Model], ...] = (
    Role,
    User,
    UserRole,
    Group,
    UserGroup,
    YubikeyCredential,
    Setting,
    AuditEvent,
)

_MAX_LINE_BYTES = 16 * 1024 * 1024
_CHUNK_ROWS = 2000

type Row = list[Any]


def table(model: type[models.Model]) -> str:
    return model._meta.db_table


def fields(model: type[models.Model]) -> list[models.Field]:
    """The model's columns, in the model's order."""
    return list(model._meta.concrete_fields)


def dump(write: Callable[[bytes], None]) -> dict[str, int]:
    """Write every table to WRITE as JSON Lines. Run it in a snapshot.

    Returns:
        The number of rows of each table.
    """
    counts = {}
    for model in TABLES:
        columns = fields(model)
        write(_line({"table": table(model), "columns": [f.column for f in columns]}))
        pk = model._meta.pk
        assert pk is not None  # noqa: S101 - every model has one
        # Text keys in code-point order on both backends; UUIDs sort alike on both.
        order = CodePoint("pk") if isinstance(pk, models.CharField) else "pk"
        rows = (
            model._base_manager.order_by(order)
            .values_list(*(f.attname for f in columns))
            .iterator(chunk_size=_CHUNK_ROWS)
        )
        count = 0
        codecs = _codecs(model)
        for row in rows:
            values = [c.encode(v) for c, v in zip(codecs, row, strict=True)]
            for codec, value in zip(codecs, values, strict=True):
                try:
                    codec.decode(value)
                except (ValidationError, ValueError, TypeError) as e:
                    raise BackupError(
                        f"{table(model)} {row[_pk_index(model)]}: {codec.column}: "
                        f"{_problem(e)}: a restore would refuse this row"
                    ) from None
            write(_line(values))
            count += 1
        counts[table(model)] = count
    return counts


def canonical(model: type[models.Model], values: Iterable[Any]) -> Row:
    """A row as Django reads it, made what parse() would give for it after a backup."""
    return [c.decode(c.encode(v)) for c, v in zip(_codecs(model), values, strict=True)]


def _line(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n"


def parse(chunks: Iterable[bytes]) -> Iterator[tuple[type[models.Model], Row]]:
    """Each row of a backup's payload, with its model, in order. Each is checked as it
    is read: the tables and columns are this version's, each value has its column's
    type, and each reference is to a row the backup holds.

    Raises:
        BackupError: The payload isn't what dump() writes.
    """
    tables = iter(TABLES)
    current: _Table | None = None
    # The primary keys of the tables that others refer to, read so far.
    keys: dict[type[models.Model], set[Any]] = {
        _parent(f): set()
        for model in TABLES
        for f in fields(model)
        if isinstance(f, models.ForeignKey)
    }
    for line in _lines(chunks):
        if line.startswith(b"{"):
            model = next(tables, None)
            if model is None:
                raise BackupError("the data goes on after the last table")
            current = _Table(model, line, keys)
        elif current is None:
            raise BackupError("the data doesn't start with a table")
        else:
            yield current.model, current.decode(line)
    missing = next(tables, None)
    if missing is not None:
        raise BackupError(f"the data ends before the table {table(missing)}")


def _lines(chunks: Iterable[bytes]) -> Iterator[bytes]:
    rest = b""
    for chunk in chunks:
        *complete, rest = (rest + chunk).split(b"\n")
        if len(rest) > _MAX_LINE_BYTES:
            raise BackupError("the data holds a line too long to be a row")
        yield from complete
    if rest:
        raise BackupError("the data is cut short (no line break at its end)")


class _Table:
    """Decodes and checks the rows of one table."""

    def __init__(
        self, model: type[models.Model], line: bytes, keys: dict[type[models.Model], set[Any]]
    ) -> None:
        name = table(model)
        try:
            data = json.loads(line)
        except ValueError:
            data = None
        if not isinstance(data, dict) or data.get("table") != name:
            found = data.get("table") if isinstance(data, dict) else None
            raise BackupError(f"expected the table {name}, found {found or 'damaged data'}")
        self.model = model
        self._fields = fields(model)
        if data.get("columns") != [f.column for f in self._fields]:
            raise BackupError(f"{name}: its columns aren't this version's: {data.get('columns')}")
        self._codecs = _codecs(model)
        self._number = 0
        self._own_keys = keys.get(model)
        self._pk = _pk_index(model)
        self._references = [
            (n, f.column, keys[_parent(f)])
            for n, f in enumerate(self._fields)
            if isinstance(f, models.ForeignKey)
        ]

    def decode(self, line: bytes) -> Row:
        self._number += 1
        where = f"{table(self.model)}, row {self._number}"
        try:
            values = json.loads(line)
        except ValueError:
            raise BackupError(f"{where}: not JSON") from None
        if not isinstance(values, list) or len(values) != len(self._fields):
            raise BackupError(f"{where}: not a list of {len(self._fields)} values")
        row = []
        for codec, value in zip(self._codecs, values, strict=True):
            try:
                row.append(codec.decode(value))
            except (ValidationError, ValueError, TypeError) as e:
                raise BackupError(f"{where}: {codec.column}: {_problem(e)}") from None
        for n, column, known in self._references:
            if row[n] is not None and row[n] not in known:
                raise BackupError(f"{where}: {column} refers to a row the backup doesn't hold")
        if self._own_keys is not None:
            self._own_keys.add(row[self._pk])
        return row


def _parent(field: models.ForeignKey) -> type[models.Model]:
    """The model a foreign key refers to."""
    model = field.related_model
    assert not isinstance(model, str)  # noqa: S101 - resolved once the apps are loaded
    return model


def _problem(error: Exception) -> str:
    if isinstance(error, ValidationError):
        return " ".join(error.messages)
    return str(error) or type(error).__name__


def _pk_index(model: type[models.Model]) -> int:
    return next(n for n, f in enumerate(fields(model)) if f.primary_key)


@functools.cache
def _codecs(model: type[models.Model]) -> list[_Codec]:
    return [_Codec(f) for f in fields(model)]


class _Codec:
    """Turns a column's values as Django reads them into JSON, and back."""

    def __init__(self, field: models.Field) -> None:
        self.column = field.column
        self._field = field
        target = field.target_field if isinstance(field, models.ForeignKey) else field
        self._kind, self._convert = _conversion(field, target)
        self._json = isinstance(field, models.JSONField)
        # PostgreSQL's inet writes some IPv6 addresses otherwise than Django does.
        self._ip = isinstance(target, models.GenericIPAddressField)

    def encode(self, value: Any) -> Any:
        if value is None or self._json:
            return value
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, uuid.UUID):
            return str(value)
        if isinstance(value, bytes | memoryview):
            return base64.b64encode(bytes(value)).decode("ascii")
        if self._ip:
            return self._field.to_python(value)
        if isinstance(value, bool | int | str):
            return value
        raise TypeError(f"can't back up a {type(value).__name__}")

    def decode(self, value: Any) -> Any:
        if value is None:
            # In a JSON column that can't be NULL, null is JSON's null.
            if not (self._field.null or self._json):
                raise ValueError("null in a column that doesn't allow it")
            return None
        if self._kind is not None and type(value) is not self._kind:
            raise TypeError(f"expected {_KINDS[self._kind]}")
        return self._convert(value)


_KINDS: dict[type, str] = {str: "text", int: "a whole number", bool: "true or false"}


def _conversion(field: models.Field, target: models.Field) -> tuple[type | None, Callable]:
    """The JSON type of a column's values (None: any), and how to convert them."""
    if isinstance(field, models.JSONField):
        return None, _same
    if isinstance(target, models.UUIDField):
        return str, uuid.UUID
    if isinstance(target, models.DateTimeField):
        return str, _aware_datetime
    if isinstance(target, models.BinaryField):
        return str, _base64
    if isinstance(target, models.BooleanField):
        return bool, _same
    if isinstance(target, models.IntegerField):
        return int, target.to_python
    if isinstance(target, models.CharField | models.TextField | models.GenericIPAddressField):
        return str, target.to_python
    raise TypeError(f"{field}: no backup format for {type(target).__name__}")


def _same(value: Any) -> Any:
    return value


def _aware_datetime(text: str) -> datetime:
    value = datetime.fromisoformat(text)
    if value.tzinfo is None:
        raise ValueError("a time without a time zone")
    return value


def _base64(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except binascii.Error as e:
        raise ValueError(str(e)) from None
