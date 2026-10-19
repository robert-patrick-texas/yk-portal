"""Groups and memberships (addendum §5).

Groups grant nothing inside yk-portal and aren't exported in this version.
Each change records an audit event (addendum §5.8). A broken rule raises
ValidationError, as in yk_portal.accounts.services.
"""

from django.core.exceptions import ValidationError
from django.db import transaction

from yk_portal.audit.models import EventType
from yk_portal.audit.service import Actor, record
from yk_portal.core.db import recheck_on_conflict
from yk_portal.portal_settings.service import current as current_settings

from .models import Group, User, UserGroup
from .validators import validate_group_name


def create_group(name: str, actor: Actor, description: str = "") -> Group:
    """Create a group.

    Raises:
        ValidationError: The name breaks the rule, or another group has it in any case.
    """
    name = name.strip()
    validate_group_name(name)
    with transaction.atomic():
        _check_name_free(name)
        with recheck_on_conflict(lambda: _check_name_free(name)):
            group = Group.objects.create(name=name, description=description)
        record(EventType.GROUP_CREATED, actor, details={"group": name})
    return group


def update_group(group: Group, actor: Actor, name: str, description: str) -> None:
    """Rename a group or change its description. Its ID, and so its members, stay.

    Raises:
        ValidationError: As for create_group.
    """
    name = name.strip()
    validate_group_name(name)
    with transaction.atomic():
        locked = Group.objects.select_for_update().get(pk=group.pk)
        details: dict[str, str] = {"group": name}
        if name != locked.name:
            _check_name_free(name, locked)
            details["old_name"] = locked.name
        if description != locked.description:
            details["old_description"] = locked.description
            details["new_description"] = description
        if len(details) == 1:
            return
        locked.name, locked.description = name, description
        with recheck_on_conflict(lambda: _check_name_free(name, locked)):
            locked.save()
        record(EventType.GROUP_UPDATED, actor, details=details)
    group.refresh_from_db()


def delete_group(group: Group, actor: Actor) -> None:
    """Delete a group and its memberships, unless it is the default group (addendum §5.5).

    Raises:
        ValidationError: It is the default group.
    """
    with transaction.atomic():
        # Locked first, so it can't become the default while it is deleted.
        locked = Group.objects.select_for_update().get(pk=group.pk)
        if current_settings().default_group == locked.pk:
            raise ValidationError(
                "This is the default group; choose another default, or none, first.",
                code="default_group",
            )
        members = UserGroup.objects.filter(group=locked).count()
        locked.delete()
        record(EventType.GROUP_DELETED, actor, details={"group": locked.name, "members": members})


def add_member(group: Group, user: User, actor: Actor) -> None:
    """Add USER to GROUP. Nothing happens if USER is a member already."""
    with transaction.atomic():
        _, created = UserGroup.objects.get_or_create(user=user, group=group)
        if created:
            record(EventType.GROUP_MEMBER_ADDED, actor, user, details={"group": group.name})


def remove_member(group: Group, user: User, actor: Actor) -> None:
    """Remove USER from GROUP. Nothing happens if USER isn't a member."""
    with transaction.atomic():
        deleted, _ = UserGroup.objects.filter(user=user, group=group).delete()
        if deleted:
            record(EventType.GROUP_MEMBER_REMOVED, actor, user, details={"group": group.name})


def _check_name_free(name: str, group: Group | None = None) -> None:
    """Group names are unique regardless of case (addendum §5.2)."""
    others = Group.objects.filter(name__iexact=name)
    if group is not None:
        others = others.exclude(pk=group.pk)
    if others.exists():
        raise ValidationError("A group with that name exists.", code="group_name_taken")
