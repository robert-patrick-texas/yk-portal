"""Web sessions (spec §19, §25.5).

The browser holds a random token; only its SHA-256 hash is stored, so the
table can't be used to take over a session. The idle timeout and maximum
length come from the settings at each request (addendum §3.3), so there is no
stored expiry.
"""

import uuid
from typing import ClassVar

from django.db import models

from yk_portal.accounts.models import User


class Session(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sessions")
    token_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True, default="")

    objects: ClassVar[models.Manager[Session]] = models.Manager["Session"]()

    class Meta:
        db_table = "sessions"

    def __str__(self) -> str:
        return f"session {self.pk} of {self.user}"
