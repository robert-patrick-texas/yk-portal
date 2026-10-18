"""Run-time settings: defaults, validation, reading and changing (addendum §3).

Settings are read from the database on each use, so a change reaches every
process at once (addendum §3.3). Every change creates a SETTING_CHANGED audit
event with the old and new values (addendum §3.1).
"""

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, fields

from django.core.exceptions import ValidationError
from django.db import transaction

from yk_portal.accounts.models import Group, Theme
from yk_portal.audit.models import EventType
from yk_portal.audit.service import Actor, record

from .models import Setting


@dataclass(frozen=True)
class PortalSettings:
    """Every setting, with its default (addendum §3.2). Field names are the stored keys."""

    portal_name: str = "yk-portal"
    login_notice: str = ""
    idle_timeout_minutes: int = 20
    max_session_hours: int = 12
    temp_password_hours: int = 72
    failed_login_limit: int = 3
    max_yubikeys_per_user: int = 10
    step_up_before_reveal: bool = True
    default_group: uuid.UUID | None = None
    default_theme: str = Theme.BROWSER


# Plain text, escaped on output (addendum §3.4): (minimum, maximum) length.
TEXT_LENGTHS = {"portal_name": (1, 64), "login_notice": (0, 2000)}
# Whole numbers: (minimum, maximum).
NUMBER_RANGES = {
    "idle_timeout_minutes": (5, 240),
    "max_session_hours": (1, 24),
    "temp_password_hours": (1, 336),
    "failed_login_limit": (1, 10),
    "max_yubikeys_per_user": (1, 10),
}
KEYS = tuple(f.name for f in fields(PortalSettings))


def current() -> PortalSettings:
    """The settings now in effect: stored values, and defaults for the rest."""
    stored = dict(Setting.objects.filter(key__in=KEYS).values_list("key", "value"))
    if stored.get("default_group"):
        stored["default_group"] = uuid.UUID(stored["default_group"])
    return PortalSettings(**stored)


def update(changes: Mapping[str, object], actor: Actor) -> list[str]:
    """Check and store changed settings, auditing each change.

    Args:
        changes: New values by setting name, typed as in PortalSettings.
        actor: Who makes the change.

    Returns:
        The names of the settings whose value changed; unchanged values are skipped.

    Raises:
        ValidationError: A value is out of range, or a name is unknown. Errors are keyed
            by setting name, and nothing is changed.
    """
    changed = []
    with transaction.atomic():
        list(Setting.objects.select_for_update().filter(key__in=list(changes)))
        before = current()
        cleaned, errors = {}, {}
        for key, value in changes.items():
            try:
                cleaned[key] = _clean(key, value)
            except ValidationError as e:
                errors[key] = e.messages
        if errors:
            raise ValidationError(errors)
        for key, value in cleaned.items():
            old = getattr(before, key)
            if value == old:
                continue
            Setting.objects.update_or_create(
                key=key,
                defaults={
                    # JSON has no UUID type: the default group's ID is stored as text.
                    "value": str(value) if isinstance(value, uuid.UUID) else value,
                    "updated_by": actor.user,
                },
            )
            if key == "default_group":
                old, value = _group_name(old), _group_name(value)
            record(
                EventType.SETTING_CHANGED, actor, details={"setting": key, "old": old, "new": value}
            )
            changed.append(key)
    return changed


def _clean(key: str, value: object) -> object:
    """VALUE checked against KEY's rule, as PortalSettings holds it."""
    if key in TEXT_LENGTHS:
        low, high = TEXT_LENGTHS[key]
        if not isinstance(value, str) or not low <= len(value) <= high:
            raise ValidationError(
                f"Use {low} to {high} characters." if low else f"Use at most {high} characters."
            )
        return value
    if key in NUMBER_RANGES:
        low, high = NUMBER_RANGES[key]
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            raise ValidationError(f"Use a whole number from {low} to {high}.")
        return value
    if key == "step_up_before_reveal":
        if not isinstance(value, bool):
            raise ValidationError("Use on or off.")
        return value
    if key == "default_theme":
        if value not in Theme.values:
            raise ValidationError(f"Use one of: {', '.join(Theme.values)}.")
        return value
    if key == "default_group":
        if value is None:
            return None
        # Locked, so the group can't be deleted while it becomes the default (addendum §5.5).
        if not isinstance(value, uuid.UUID) or not (
            Group.objects.select_for_update().filter(pk=value).exists()
        ):
            raise ValidationError("Choose an existing group, or none.")
        return value
    raise ValidationError("Unknown setting.")


def _group_name(group_id: object) -> str | None:
    if group_id is None:
        return None
    return Group.objects.filter(pk=group_id).values_list("name", flat=True).first()
