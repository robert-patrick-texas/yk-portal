"""YubiKey credentials (spec §21, §25.4; addendum §12).

The private ID and AES key are each stored as one AES-256-GCM value
(yk_portal.core.encryption), bound to their column and row. Each YubiKey has
its own PIN, typed before its OTP (addendum §2.2).
"""

import uuid
from typing import ClassVar

from django.db import models

from yk_portal.accounts.models import User
from yk_portal.core.encryption import lookup_digest, secret_box

from .otp import USAGE_COUNTER_MASK
from .validators import validate_label, validate_public_id

PRIVATE_ID_BYTES = 6
AES_KEY_BYTES = 16


def private_id_digest(private_id: bytes) -> str:
    return lookup_digest(private_id, "yubikey_credentials.private_id")


class ProvisioningMethod(models.TextChoices):
    SELF_PROVISIONED = "SELF_PROVISIONED"
    ADMIN_PROVISIONED = "ADMIN_PROVISIONED"
    MIGRATED = "MIGRATED"


class YubikeyCredential(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="yubikeys")
    label = models.CharField(max_length=255, blank=True, default="", validators=[validate_label])
    # Empty for an imported key whose slot isn't known (addendum §12).
    slot_number = models.PositiveSmallIntegerField(null=True, blank=True)
    public_id = models.CharField(max_length=12, unique=True, validators=[validate_public_id])
    encrypted_private_id = models.BinaryField()
    # A keyed digest of the private ID, so no two credentials share one: radiator-yubikey
    # replaces a row with the same private ID, even another user's (addendum §6.4).
    private_id_digest = models.CharField(max_length=64, unique=True)
    encrypted_aes_secret = models.BinaryField()
    # The PIN's Argon2id hash, for web logins, and its {crypt}$6$ SHA-512 crypt hash, for
    # the export to radiator-yubikey (addendum §2.2). Both empty until a PIN is set; a key
    # imported from Radiator may have only the SHA-512 hash (addendum §2.8).
    pin_hash = models.CharField(max_length=255, blank=True, default="")
    radius_pin_hash = models.CharField(max_length=255, blank=True, default="")
    # Consecutive failed logins with this YubiKey since its last success (addendum §2.14).
    failed_login_count = models.PositiveSmallIntegerField(default=0)
    enabled = models.BooleanField(default=True)
    # The last accepted OTP's counters, as radiator-yubikey stores them (addendum §8).
    last_usage_counter = models.PositiveIntegerField(default=0)
    last_session_counter = models.PositiveSmallIntegerField(default=0)
    provisioning_method = models.CharField(max_length=32, choices=ProvisioningMethod.choices)
    # "radiator-yubikey export" for keys the importer added (addendum §12).
    migration_source = models.CharField(max_length=64, blank=True, default="")
    created_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        db_column="created_by_user_id",
        related_name="+",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    objects: ClassVar[models.Manager[YubikeyCredential]] = models.Manager["YubikeyCredential"]()

    class Meta:
        db_table = "yubikey_credentials"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(slot_number__in=(1, 2)) | models.Q(slot_number__isnull=True),
                name="yubikey_credentials_slot_number_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(last_usage_counter__lte=USAGE_COUNTER_MASK),
                name="yubikey_credentials_last_usage_counter_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(last_session_counter__lte=255),
                name="yubikey_credentials_last_session_counter_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(provisioning_method__in=ProvisioningMethod.values),
                name="yubikey_credentials_provisioning_method_valid",
            ),
        ]

    def __str__(self) -> str:
        return self.public_id

    @property
    def has_pin(self) -> bool:
        return bool(self.pin_hash or self.radius_pin_hash)

    def set_secrets(self, private_id: bytes, aes_key: bytes) -> None:
        """Encrypt and set the private ID (6 bytes) and AES key (16 bytes). Doesn't save."""
        if len(private_id) != PRIVATE_ID_BYTES or len(aes_key) != AES_KEY_BYTES:
            raise ValueError("a private ID is 6 bytes and an AES key 16 bytes")
        self.private_id_digest = private_id_digest(private_id)
        box = secret_box()
        self.encrypted_private_id = box.encrypt(private_id, self._context("private_id"))
        self.encrypted_aes_secret = box.encrypt(aes_key, self._context("aes_secret"))

    def private_id(self) -> bytes:
        """The decrypted private ID. Raises DecryptionError if the stored value is bad."""
        return secret_box().decrypt(bytes(self.encrypted_private_id), self._context("private_id"))

    def aes_key(self) -> bytes:
        """The decrypted AES key. Raises DecryptionError if the stored value is bad."""
        return secret_box().decrypt(bytes(self.encrypted_aes_secret), self._context("aes_secret"))

    def _context(self, name: str) -> str:
        return f"yubikey_credentials.{name}:{self.pk}"
