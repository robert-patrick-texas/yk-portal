"""Adding and managing YubiKey credentials (spec §13, §14, §20, §34; addendum §3.2).

Each change records an audit event without any secret. A broken rule raises
ValidationError, as in yk_portal.accounts.services. The pages check that the
signed-in user may act on the credential; reveal_* check the admin role too.
"""

import re
from dataclasses import dataclass, field

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from yk_portal.accounts.models import AccountState, User
from yk_portal.audit.models import EventType
from yk_portal.audit.service import Actor, record
from yk_portal.portal_settings.service import current as current_settings

from .models import (
    AES_KEY_BYTES,
    PRIVATE_ID_BYTES,
    ProvisioningMethod,
    YubikeyCredential,
    private_id_digest,
)
from .otp import OtpRejected, Rejection, Token, decrypt_token, parse_otp
from .service import accept_otp, find_credential
from .validators import validate_label, validate_public_id

_HEX = re.compile(r"[0-9a-f]*")
_SEPARATORS = re.compile(r"[\s:]")


@dataclass(frozen=True)
class NewYubikey:
    """What programming a YubiKey slot with ykman sets, and how to name it."""

    public_id: str
    private_id: bytes = field(repr=False)
    aes_key: bytes = field(repr=False)
    label: str = ""
    slot: int | None = None


def parse_private_id(text: str) -> bytes:
    """A private ID typed as 12 hex characters; spaces and colons are ignored."""
    return _parse_hex(text, PRIVATE_ID_BYTES, "private ID")


def parse_aes_key(text: str) -> bytes:
    """An AES key typed as 32 hex characters; spaces and colons are ignored."""
    return _parse_hex(text, AES_KEY_BYTES, "AES key")


def add_yubikey(
    user: User,
    actor: Actor,
    key: NewYubikey,
    method: ProvisioningMethod,
    test_otp: str | None = None,
) -> YubikeyCredential:
    """Add a YubiKey to USER (spec §13.2, §14).

    Args:
        user: The owner.
        actor: Who adds it.
        key: The YubiKey's values.
        method: SELF_PROVISIONED needs TEST_OTP; ADMIN_PROVISIONED doesn't (no proof of
            possession, spec §14), and its owner tests it while onboarding.
        test_otp: An OTP from the YubiKey, proving the values: it must decrypt with the AES
            key and carry the private ID. Its counters become the stored ones.

    Returns:
        The new credential.

    Raises:
        ValidationError: A value is invalid, the OTP doesn't fit the values, the public or
            private ID is registered already, or USER has the maximum number of YubiKeys.
    """
    public_id = key.public_id.strip().lower()
    validate_public_id(public_id)
    validate_label(key.label)
    if key.slot not in (None, 1, 2):
        raise ValidationError("Choose slot 1 or 2.", code="invalid_slot")
    if method == ProvisioningMethod.SELF_PROVISIONED and test_otp is None:
        raise ValueError("a self-provisioned YubiKey needs a test OTP")
    token = _check_test_otp(public_id, key, test_otp) if test_otp is not None else None
    with transaction.atomic():
        # Locked, so two adds at once can't pass the maximum.
        User.objects.select_for_update().get(pk=user.pk)
        limit = current_settings().max_yubikeys_per_user
        if YubikeyCredential.objects.filter(user=user).count() >= limit:
            raise ValidationError(
                f"An account can have at most {limit} YubiKeys.", code="too_many_yubikeys"
            )
        if YubikeyCredential.objects.filter(public_id=public_id).exists():
            raise ValidationError(
                "A YubiKey with this public ID is registered already.", code="public_id_taken"
            )
        digest = private_id_digest(key.private_id)
        if YubikeyCredential.objects.filter(private_id_digest=digest).exists():
            raise ValidationError(
                "A YubiKey with this private ID is registered already.", code="private_id_taken"
            )
        credential = YubikeyCredential(
            user=user,
            public_id=public_id,
            label=key.label,
            slot_number=key.slot,
            provisioning_method=method,
            created_by=actor.user,
            last_usage_counter=token.usage_counter if token else 0,
            last_session_counter=token.session_counter if token else 0,
            last_used_at=timezone.now() if token else None,
        )
        credential.set_secrets(key.private_id, key.aes_key)
        credential.save()
        details = {
            "public_id": public_id,
            "label": key.label,
            "slot": key.slot,
            "method": method,
            "tested": token is not None,
        }
        record(EventType.YUBIKEY_ADDED, actor, user, details=details)
    return credential


def check_yubikey(user: User, otp_text: str) -> YubikeyCredential:
    """Check an OTP from one of USER's enabled YubiKeys and save its counters (spec §44.2).

    Raises:
        OtpRejected: As for a login, but nothing counts toward lockout.
    """
    otp = parse_otp(otp_text.strip())
    credential = find_credential(user, otp.public_id)
    accept_otp(credential, otp)
    return credential


def update_yubikey(
    credential: YubikeyCredential, actor: Actor, label: str, slot: int | None
) -> None:
    """Change a YubiKey's label and slot (spec §20)."""
    validate_label(label)
    if slot not in (None, 1, 2):
        raise ValidationError("Choose slot 1 or 2.", code="invalid_slot")
    details: dict[str, str | int | None] = {"public_id": credential.public_id}
    if label != credential.label:
        details |= {"old_label": credential.label, "new_label": label}
    if slot != credential.slot_number:
        details |= {"old_slot": credential.slot_number, "new_slot": slot}
    if len(details) == 1:
        return
    with transaction.atomic():
        YubikeyCredential.objects.filter(pk=credential.pk).update(
            label=label, slot_number=slot, updated_at=timezone.now()
        )
        record(EventType.YUBIKEY_UPDATED, actor, credential.user, details=details)
    credential.refresh_from_db()


def set_yubikey_enabled(
    credential: YubikeyCredential, actor: Actor, enabled: bool, allow_last: bool = False
) -> None:
    """Enable or disable a YubiKey (spec §20). Nothing happens if it is so already.

    Args:
        allow_last: Allow disabling an ACTIVE account's last enabled YubiKey, which keeps
            it from signing in. Users can't; admins can.

    Raises:
        ValidationError: It is the last enabled YubiKey and ALLOW_LAST is false.
    """
    with transaction.atomic():
        locked = YubikeyCredential.objects.select_for_update().get(pk=credential.pk)
        if locked.enabled == enabled:
            return
        if not enabled and not allow_last:
            _keep_one(locked)
        locked.enabled = enabled
        locked.save(update_fields=["enabled", "updated_at"])
        event = EventType.YUBIKEY_ENABLED if enabled else EventType.YUBIKEY_DISABLED
        record(event, actor, locked.user, details={"public_id": locked.public_id})
    credential.refresh_from_db()


def remove_yubikey(credential: YubikeyCredential, actor: Actor, allow_last: bool = False) -> None:
    """Delete a YubiKey and its secrets (spec §20, §26).

    The removal doesn't reach Radiator (addendum §6.6): until an admin runs
    `yubikey-db.sh delete`, Radiator keeps the key as it was last exported.

    Raises:
        ValidationError: As for set_yubikey_enabled.
    """
    with transaction.atomic():
        locked = YubikeyCredential.objects.select_for_update().get(pk=credential.pk)
        if locked.enabled and not allow_last:
            _keep_one(locked)
        details = {"public_id": locked.public_id, "label": locked.label}
        user = locked.user
        locked.delete()
        record(EventType.YUBIKEY_REMOVED, actor, user, details=details)


def reveal_private_id(credential: YubikeyCredential, actor: Actor) -> str:
    """The private ID as hex, for an admin, audited (spec §20.2). Never logged."""
    _require_admin(actor)
    record(
        EventType.YUBIKEY_PRIVATE_ID_REVEALED,
        actor,
        credential.user,
        details={"public_id": credential.public_id},
    )
    return credential.private_id().hex()


def reveal_aes_key(credential: YubikeyCredential, actor: Actor) -> str:
    """The AES key as hex, for an admin, audited (spec §20.2). Never logged."""
    _require_admin(actor)
    record(
        EventType.YUBIKEY_AES_SECRET_REVEALED,
        actor,
        credential.user,
        details={"public_id": credential.public_id},
    )
    return credential.aes_key().hex()


def _parse_hex(text: str, length: int, name: str) -> bytes:
    cleaned = _SEPARATORS.sub("", text).lower()
    if len(cleaned) != 2 * length or not _HEX.fullmatch(cleaned):
        raise ValidationError(
            f"Enter the {name} as {2 * length} hex characters (0-9, a-f).", code="invalid_hex"
        )
    return bytes.fromhex(cleaned)


def _check_test_otp(public_id: str, key: NewYubikey, otp_text: str) -> Token:
    """The test OTP's token, if the OTP comes from a YubiKey with KEY's values."""
    try:
        otp = parse_otp(otp_text.strip())
    except OtpRejected:
        raise ValidationError(
            "Touch the YubiKey with the cursor in the OTP box: it types 44 letters.",
            code="malformed_otp",
        ) from None
    if otp.public_id != public_id:
        raise ValidationError(
            f"The OTP starts with public ID {otp.public_id}, not {public_id}.",
            code="wrong_public_id",
        )
    try:
        token = decrypt_token(otp.token, key.aes_key)
    except OtpRejected as e:
        assert e.reason == Rejection.BAD_CRC  # noqa: S101 - the only reason decrypt_token gives
        raise ValidationError(
            "The OTP doesn't decrypt with this AES key. Check the key, then touch the YubiKey "
            "again.",
            code="wrong_aes_key",
        ) from None
    if token.private_id != key.private_id:
        raise ValidationError(
            "The OTP doesn't carry this private ID. Check it, then touch the YubiKey again.",
            code="wrong_private_id",
        )
    return token


def _keep_one(credential: YubikeyCredential) -> None:
    """Refuse to take away an ACTIVE account's last enabled YubiKey."""
    others = YubikeyCredential.objects.filter(user=credential.user, enabled=True).exclude(
        pk=credential.pk
    )
    if credential.user.state == AccountState.ACTIVE and not others.exists():
        raise ValidationError(
            "This is your only enabled YubiKey: without it you can't sign in. Add another "
            "one first.",
            code="last_yubikey",
        )


def _require_admin(actor: Actor) -> None:
    if actor.user is None or not actor.user.is_admin:
        raise PermissionDenied("only admins can reveal YubiKey secrets")
