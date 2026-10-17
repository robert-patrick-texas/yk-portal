"""Importing a radiator-yubikey export: accounts, YubiKeys, PINs and counters (addendum §7).

Every row is checked first, then the valid rows are applied in one
transaction. A full import creates the accounts and adds the YubiKeys, with
their PINs, that yk-portal doesn't have, and moves counters forward for those
it has; a counter sync (--counters-only) only moves counters forward. Nothing
else of an account or YubiKey yk-portal has is changed, since yk-portal owns
its users' data (addendum §1.4).

Reports name rows by line, username and public ID, never a secret.
"""

import enum
import hmac
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Q

from yk_portal.accounts.models import User
from yk_portal.accounts.services import create_migrated_user
from yk_portal.accounts.validators import validate_username
from yk_portal.audit.models import EventType
from yk_portal.audit.service import Actor, record
from yk_portal.authentication.passwords import PinHashes, hash_pin
from yk_portal.core import sha512_crypt
from yk_portal.portal_settings.service import current as current_settings
from yk_portal.yubikeys import modhex
from yk_portal.yubikeys.management import Migrated, NewYubikey, add_yubikey
from yk_portal.yubikeys.models import ProvisioningMethod, YubikeyCredential, private_id_digest
from yk_portal.yubikeys.otp import PUBLIC_ID_LENGTH, USAGE_COUNTER_MASK

from . import csvfile

MIGRATION_SOURCE = "radiator-yubikey export"

_PUBLIC_ID = re.compile(f"(?:[{modhex.ALPHABET}]{{2}}){{1,16}}")
_HEX_PRIVATE_ID = re.compile(r"[0-9a-f]{12}")
_MODHEX_PRIVATE_ID = re.compile(f"[{modhex.ALPHABET}]{{12}}")
_AES_KEY = re.compile(r"[0-9a-f]{32}")
_SEPARATORS = re.compile(r"[\s:]", re.ASCII)
_NUMBER = re.compile(r"[0-9]{1,9}")
# yubikey-db.sh's values for active.
_ACTIVE = {"", "1", "true", "yes", "y", "on"}
_INACTIVE = {"0", "false", "no", "n", "off"}
# Password formats Radiator reads as hashes: {SCHEME}... and $ID$...
_SCHEME = re.compile(r"\{[^}]*\}")
_CRYPT_ID = re.compile(r"\$[^$]*\$")
_CLEAR = "{clear}"
_SLOT = re.compile(r"\bslot ?([12])\b", re.IGNORECASE)
_NEVER = datetime.min.replace(tzinfo=UTC)


class Kind(enum.Enum):
    ADDED = "added"
    MOVED = "moved forward"
    UNCHANGED = "unchanged"
    SKIPPED = "skipped"
    INVALID = "invalid"


class ImportFailed(Exception):
    """The import stopped part way and was rolled back: nothing was imported."""


class _Invalid(Exception):
    """A row can't be imported; the message says why, without any secret."""


class _Reserved(_Invalid):
    """A row for a username reserved for Radiator, such as the anycast check's
    (addendum §9.2): invalid, or skipped with --skip-invalid (addendum §7.2)."""


@dataclass(frozen=True)
class Row:
    """A valid row of the file."""

    line: int
    username: str
    public_id: str
    private_id: bytes = field(repr=False)
    aes_key: bytes = field(repr=False)
    # The PIN as in the file; empty for none.
    password: str = field(repr=False)
    active: bool
    created: datetime | None
    accessed: datetime | None
    counter: int
    low: int
    label: str
    notes: tuple[str, ...] = ()


@dataclass
class RowReport:
    """What happened to one row, or would in a dry run."""

    line: int
    username: str
    public_id: str
    kind: Kind
    text: str
    account_created: bool = False
    row: Row | None = field(default=None, repr=False)
    credential: YubikeyCredential | None = field(default=None, repr=False)

    def __str__(self) -> str:
        notes = self.row.notes if self.row and self.kind != Kind.INVALID else ()
        text = "; ".join((self.text, *notes))
        return f"line {self.line}: {self.username or '-'} {self.public_id or '-'}: {text}"


@dataclass
class ImportReport:
    counters_only: bool
    rows: list[RowReport] = field(default_factory=list)

    def count(self, kind: Kind) -> int:
        return sum(r.kind == kind for r in self.rows)

    @property
    def accounts_created(self) -> int:
        return sum(r.account_created for r in self.rows)

    def totals(self) -> dict[str, int]:
        totals = {"rows": len(self.rows)}
        if not self.counters_only:
            totals |= {"accounts_created": self.accounts_created}
            totals |= {"yubikeys_added": self.count(Kind.ADDED)}
        totals |= {
            "moved_forward": self.count(Kind.MOVED),
            "unchanged": self.count(Kind.UNCHANGED),
            "skipped": self.count(Kind.SKIPPED),
            "invalid": self.count(Kind.INVALID),
        }
        return totals

    def summary(self) -> str:
        """The totals in a line, leaving out the zeros."""
        totals = self.totals()
        rows = _count(totals.pop("rows"), "row", "rows")
        names = {"accounts_created": ("account created", "accounts created")}
        names["yubikeys_added"] = ("added", "added")
        parts = [
            _count(n, *names.get(k, (k.replace("_", " "),) * 2)) for k, n in totals.items() if n
        ]
        return f"{rows}: {', '.join(parts)}." if parts else f"{rows}."


def run(
    data: bytes,
    actor: Actor,
    source: str,
    counters_only: bool = False,
    dry_run: bool = False,
    skip_invalid: bool = False,
) -> ImportReport:
    """Check every row of an export file, then apply the valid ones in one transaction.

    Args:
        data: The file's contents.
        actor: Who imports it.
        source: Where the file comes from, for the audit event.
        counters_only: Only move counters forward (addendum §7.5); rows yk-portal
            doesn't have, or has with other key values, are skipped.
        dry_run: Report what would happen, and change nothing.
        skip_invalid: Apply the valid rows even when some are invalid. Rows for
            usernames reserved for Radiator are then skipped, not invalid.

    Returns:
        Each row's outcome. Nothing is applied if a row is invalid and SKIP_INVALID
        is false. The audit event is recorded only when YubiKeys were added: moving
        counters forward is routine (addendum §7.1).

    Raises:
        csvfile.CsvError: The file isn't an export file.
        ImportFailed: yk-portal changed while the rows were applied.
        DecryptionError, MasterKeyError: A stored secret can't be decrypted.
    """
    columns, lines = csvfile.read(data)
    try:
        with transaction.atomic():
            report = _plan(columns, lines, counters_only, skip_invalid)
            if dry_run or (report.count(Kind.INVALID) and not skip_invalid):
                return report
            _apply(report, actor)
            if report.count(Kind.ADDED):
                details = {"mode": "counters-only" if counters_only else "full", "source": source}
                record(
                    EventType.RADIATOR_IMPORT_COMPLETED, actor, details=details | report.totals()
                )
    except (ValidationError, IntegrityError) as e:
        reason = " ".join(e.messages) if isinstance(e, ValidationError) else str(e)
        raise ImportFailed(
            f"yk-portal changed during the import ({reason}); nothing imported. Run it again."
        ) from None
    return report


def _plan(
    columns: int, lines: list[tuple[int, list[bytes]]], counters_only: bool, skip_invalid: bool
) -> ImportReport:
    """Each row's outcome, from the file and what yk-portal has now."""
    report = ImportReport(counters_only)
    for line, fields in lines:
        try:
            row = _parse(line, fields, columns, counters_only)
        except _Invalid as e:
            username, public_id = (_printable(f) for f in [*fields, b"", b""][:2])
            kind = Kind.SKIPPED if isinstance(e, _Reserved) and skip_invalid else Kind.INVALID
            report.rows.append(RowReport(line, username, public_id, kind, f"{kind.value}: {e}"))
            continue
        report.rows.append(RowReport(line, row.username, row.public_id, Kind.INVALID, "", row=row))
    credentials = list(YubikeyCredential.objects.select_related("user"))
    by_public_id = {c.public_id: c for c in credentials}
    by_digest = {c.private_id_digest: c for c in credentials}
    keys_of = Counter(c.user.pk for c in credentials)
    usernames = {r.username for r in report.rows if r.row}
    users = {u.username: u for u in User.objects.filter(username__in=usernames)}
    max_keys = current_settings().max_yubikeys_per_user
    seen_public_ids: dict[str, int] = {}
    seen_private_ids: dict[str, int] = {}
    new_keys: Counter[str] = Counter()
    for result in report.rows:
        if (row := result.row) is None:
            continue
        digest = private_id_digest(row.private_id)
        if row.public_id in seen_public_ids:
            result.text = f"invalid: public ID also on line {seen_public_ids[row.public_id]}"
            continue
        if digest in seen_private_ids:
            result.text = f"invalid: private ID also on line {seen_private_ids[digest]}"
            continue
        seen_public_ids[row.public_id], seen_private_ids[digest] = row.line, row.line
        credential = by_public_id.get(row.public_id)
        if credential is not None:
            _plan_known(result, credential, row, digest, counters_only)
            continue
        if counters_only:
            result.kind, result.text = Kind.SKIPPED, "skipped: unknown key"
            continue
        if (other := by_digest.get(digest)) is not None:
            result.text = f"invalid: private ID used by {other.public_id}"
            continue
        user = users.get(row.username)
        if (keys_of[user.pk] if user else 0) + new_keys[row.username] >= max_keys:
            result.text = f"invalid: over {max_keys} YubiKeys"
            continue
        result.account_created = user is None and not new_keys[row.username]
        new_keys[row.username] += 1
        result.kind = Kind.ADDED
        result.text = "added" + (", new account" if result.account_created else "")
        if not row.active:
            result.text += ", disabled"
    return report


def _plan_known(
    result: RowReport, credential: YubikeyCredential, row: Row, digest: str, counters_only: bool
) -> None:
    """The outcome of a row whose public ID yk-portal has.

    A full import takes it only as the same user's same YubiKey; a counter sync
    takes the same YubiKey under any username, since its OTPs are used up wherever
    Radiator accepted them.
    """
    result.credential = credential
    owner = credential.user.username
    if not counters_only and owner != row.username:
        result.text = f"invalid: key belongs to {owner}"
        return
    same_key = hmac.compare_digest(credential.private_id_digest, digest) and hmac.compare_digest(
        credential.aes_key(), row.aes_key
    )
    if not same_key:
        result.kind = Kind.SKIPPED if counters_only else Kind.INVALID
        result.text = f"{result.kind.value}: key values differ"
        return
    moves = []
    old = (credential.last_usage_counter, credential.last_session_counter)
    if (row.counter, row.low) > old:
        moves.append(f"counters {old[0]}/{old[1]} -> {row.counter}/{row.low}")
    if row.accessed and row.accessed > (credential.last_used_at or _NEVER):
        moves.append(f"last use {csvfile.format_time(row.accessed)}")
    result.kind = Kind.MOVED if moves else Kind.UNCHANGED
    result.text = ", ".join(moves) or "unchanged"
    if owner != row.username:
        result.text += f" (yk-portal user {owner})"


def _apply(report: ImportReport, actor: Actor) -> None:
    """Apply the planned rows. Reports of rows yk-portal moved ahead of meanwhile become
    unchanged."""
    accounts: dict[str, User] = {}
    for result in report.rows:
        row = result.row
        if row is None or result.kind not in (Kind.ADDED, Kind.MOVED):
            continue
        if result.kind == Kind.MOVED:
            assert result.credential is not None  # noqa: S101 - set for every MOVED row
            if not _move_forward(result.credential, row):
                result.kind, result.text = Kind.UNCHANGED, "unchanged"
            continue
        if row.username not in accounts:
            if result.account_created:
                user = create_migrated_user(row.username, actor, MIGRATION_SOURCE)
            else:
                user = User.objects.get(username=row.username)
            accounts[row.username] = user
        add_yubikey(
            accounts[row.username],
            actor,
            NewYubikey(row.public_id, row.private_id, row.aes_key, row.label, _slot(row.label)),
            ProvisioningMethod.MIGRATED,
            pin=_pin_hashes(row.password),
            migrated=Migrated(
                source=MIGRATION_SOURCE,
                enabled=row.active,
                usage_counter=row.counter,
                session_counter=row.low,
                created_at=row.created,
                last_used_at=row.accessed,
            ),
        )


def _move_forward(credential: YubikeyCredential, row: Row) -> bool:
    """Move a credential's counters, and its last use, to the row's where those are ahead
    (addendum §7.5). Each UPDATE applies only while the stored value is still behind, so
    a web login at the same moment isn't moved backward.

    Returns:
        Whether anything moved.
    """
    counter, low = row.counter, row.low
    moved = (
        YubikeyCredential.objects.filter(pk=credential.pk)
        .filter(
            Q(last_usage_counter__lt=counter)
            | Q(last_usage_counter=counter, last_session_counter__lt=low)
        )
        .update(last_usage_counter=counter, last_session_counter=low)
    )
    if row.accessed:
        moved += (
            YubikeyCredential.objects.filter(pk=credential.pk)
            .filter(Q(last_used_at__isnull=True) | Q(last_used_at__lt=row.accessed))
            .update(last_used_at=row.accessed)
        )
    return moved > 0


def _parse(line: int, fields: list[bytes], columns: int, counters_only: bool) -> Row:
    """A row checked as yubikey-db.sh checks an export row, then against yk-portal's rules.

    A counter sync checks only the fields it uses.

    Raises:
        _Invalid: Why the row can't be imported.
    """
    if len(fields) != columns:
        raise _Invalid(f"{len(fields)} fields, expected {columns}")
    try:
        values = [f.decode() for f in fields]
    except UnicodeDecodeError:
        raise _Invalid("not UTF-8") from None
    username, public_id, private_id, aes_key, password, active, created, accessed = values[:8]
    counter, low, high = values[8:11]
    label = values[11] if columns == len(csvfile.COLUMNS) else ""
    if not counters_only:
        try:
            validate_username(username)
        except ValidationError as e:
            if e.code == "reserved_username":
                raise _Reserved("reserved username") from None
            raise _Invalid("username") from None
    public_id = public_id.lower()
    if not _PUBLIC_ID.fullmatch(public_id):
        raise _Invalid("public ID")
    if not counters_only and len(public_id) != PUBLIC_ID_LENGTH:
        raise _Invalid(f"public ID not {PUBLIC_ID_LENGTH} characters")
    private_id = _SEPARATORS.sub("", private_id.lower())
    if _MODHEX_PRIVATE_ID.fullmatch(private_id):
        private_id = modhex.decode(private_id).hex()
    elif not _HEX_PRIVATE_ID.fullmatch(private_id):
        raise _Invalid("private ID")
    aes_key = _SEPARATORS.sub("", aes_key.lower())
    if not _AES_KEY.fullmatch(aes_key):
        raise _Invalid("AES key")
    if not counters_only and active.lower() not in _ACTIVE | _INACTIVE:
        raise _Invalid(f"active '{_printable(active)}'")
    if not all(_NUMBER.fullmatch(n) for n in (counter, low, high)):
        raise _Invalid("counter, low or high")
    if int(counter) > USAGE_COUNTER_MASK or int(low) > 255:
        raise _Invalid("counter or low out of range")
    notes = []
    if not counters_only:
        _check_label(label)
        _check_password(password)
        if created and csvfile.parse_time(created) is None:
            notes.append("bad created time, now used")
    if accessed and csvfile.parse_time(accessed) is None:
        notes.append("bad accessed time, ignored")
    return Row(
        line=line,
        username=username if not counters_only else _printable(username),
        public_id=public_id,
        private_id=bytes.fromhex(private_id),
        aes_key=bytes.fromhex(aes_key),
        password="" if password == _CLEAR else password,
        active=active.lower() in _ACTIVE,
        created=csvfile.parse_time(created),
        accessed=csvfile.parse_time(accessed),
        counter=int(counter),
        low=int(low),
        label=label,
        notes=tuple(notes),
    )


def _check_label(label: str) -> None:
    """radiator-yubikey's label rule, which yk-portal shares."""
    if any(unicodedata.category(c) == "Cc" for c in label) or len(label) > 255:
        raise _Invalid("label")


def _check_password(password: str) -> None:
    """The password column holds the PIN as a {crypt}$6$ hash, as plain text ({clear} or
    bare), or nothing (addendum §7.3). Other hash formats can't become a SHA-512 crypt
    hash. Plain text is taken as Radiator has it, without the password policy."""
    if password.startswith("{crypt}"):
        if not sha512_crypt.STORED_HASH.fullmatch(password):
            raise _Invalid("password hash not SHA-512")
        return
    if not password.startswith(_CLEAR) and (_SCHEME.match(password) or _CRYPT_ID.match(password)):
        raise _Invalid("password hash format")
    if any(unicodedata.category(c) == "Cc" for c in password):
        raise _Invalid("password has a control character")


def _pin_hashes(password: str) -> PinHashes | None:
    """The PIN hashes for a password column checked by _check_password: plain text gets
    both, a {crypt} hash is kept as it is (the first web login adds the Argon2id hash,
    addendum §2.8)."""
    if not password:
        return None
    if password.startswith("{crypt}"):
        return PinHashes(web="", radius=password)
    return hash_pin(password.removeprefix(_CLEAR))


def _slot(label: str) -> int | None:
    """The slot a label names, as in "spare, slot 2"; None if it names none, or both."""
    slots = {int(s) for s in _SLOT.findall(label)}
    return slots.pop() if len(slots) == 1 else None


def _count(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _printable(value: str | bytes) -> str:
    """VALUE for a report line, control characters shown as ?."""
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    return "".join("?" if unicodedata.category(c) == "Cc" else c for c in value)
