"""Settings an admin changes at run time, one row per setting (addendum §3, §12).

The application holds the defaults and validation (yk_portal.portal_settings.service);
a setting without a row has its default.
"""

from typing import ClassVar

from django.db import models

from yk_portal.accounts.models import User


class Setting(models.Model):
    key = models.CharField(max_length=64, primary_key=True)
    # NULL for "none", the one setting that allows it: the default group.
    value = models.JSONField(null=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        db_column="updated_by_user_id",
        related_name="+",
    )

    objects: ClassVar[models.Manager[Setting]] = models.Manager["Setting"]()

    class Meta:
        db_table = "settings"

    def __str__(self) -> str:
        return self.key
