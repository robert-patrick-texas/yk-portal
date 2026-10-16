"""Audit events (spec §25.6, §27; addendum §12).

User IDs are plain UUIDs, not foreign keys, so an event keeps the former ID
and username snapshot after the user is hard deleted (spec §26). details
never holds a secret, an email address or a full OTP.
"""

import uuid
from typing import ClassVar

from django.db import models
from django.utils import timezone


class EventType(models.TextChoices):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGIN_LOCKED = "LOGIN_LOCKED"
    ACCOUNT_CREATED = "ACCOUNT_CREATED"
    ACCOUNT_UPDATED = "ACCOUNT_UPDATED"
    ACCOUNT_DISABLED = "ACCOUNT_DISABLED"
    ACCOUNT_ENABLED = "ACCOUNT_ENABLED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"
    ACCOUNT_RESET_TO_PROVISIONING = "ACCOUNT_RESET_TO_PROVISIONING"
    PROVISIONING_COMPLETED = "PROVISIONING_COMPLETED"
    ACCOUNT_DELETED = "ACCOUNT_DELETED"
    USERNAME_CHANGED = "USERNAME_CHANGED"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"  # noqa: S105 - an event name
    TEMPORARY_PASSWORD_SET = "TEMPORARY_PASSWORD_SET"  # noqa: S105 - an event name
    ADMIN_ROLE_GRANTED = "ADMIN_ROLE_GRANTED"
    ADMIN_ROLE_REVOKED = "ADMIN_ROLE_REVOKED"
    YUBIKEY_ADDED = "YUBIKEY_ADDED"
    YUBIKEY_UPDATED = "YUBIKEY_UPDATED"
    YUBIKEY_DISABLED = "YUBIKEY_DISABLED"
    YUBIKEY_ENABLED = "YUBIKEY_ENABLED"
    YUBIKEY_REMOVED = "YUBIKEY_REMOVED"
    YUBIKEY_PRIVATE_ID_REVEALED = "YUBIKEY_PRIVATE_ID_REVEALED"
    YUBIKEY_AES_SECRET_REVEALED = "YUBIKEY_AES_SECRET_REVEALED"  # noqa: S105 - an event name
    BACKUP_CREATED = "BACKUP_CREATED"
    BACKUP_RESTORED = "BACKUP_RESTORED"
    MASTER_KEY_ROTATED = "MASTER_KEY_ROTATED"
    ADMIN_BOOTSTRAPPED = "ADMIN_BOOTSTRAPPED"
    SETTING_CHANGED = "SETTING_CHANGED"
    GROUP_CREATED = "GROUP_CREATED"
    GROUP_UPDATED = "GROUP_UPDATED"
    GROUP_DELETED = "GROUP_DELETED"
    GROUP_MEMBER_ADDED = "GROUP_MEMBER_ADDED"
    GROUP_MEMBER_REMOVED = "GROUP_MEMBER_REMOVED"
    RADIATOR_EXPORT_CREATED = "RADIATOR_EXPORT_CREATED"
    RADIATOR_IMPORT_COMPLETED = "RADIATOR_IMPORT_COMPLETED"


class Result(models.TextChoices):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class AuditEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(default=timezone.now)
    event_type = models.CharField(max_length=64, choices=EventType.choices)
    actor_user_id = models.UUIDField(null=True, blank=True)
    # The username, or "cli:<os user>" for the command line.
    actor_username_snapshot = models.CharField(max_length=255, blank=True, default="")
    target_user_id = models.UUIDField(null=True, blank=True)
    target_username_snapshot = models.CharField(max_length=255, blank=True, default="")
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    session_id = models.UUIDField(null=True, blank=True)
    result = models.CharField(max_length=8, choices=Result.choices, default=Result.SUCCESS)
    details = models.JSONField(default=dict, blank=True)

    objects: ClassVar[models.Manager[AuditEvent]] = models.Manager["AuditEvent"]()

    class Meta:
        db_table = "audit_events"

    def __str__(self) -> str:
        return f"{self.timestamp:%Y-%m-%d %H:%M:%S} {self.event_type}"
