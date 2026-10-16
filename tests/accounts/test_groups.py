import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from yk_portal.accounts.groups import (
    add_member,
    create_group,
    delete_group,
    remove_member,
    update_group,
)
from yk_portal.accounts.models import Group, User, UserGroup
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.portal_settings import service as portal_settings

pytestmark = pytest.mark.django_db


def code_of(excinfo: pytest.ExceptionInfo[ValidationError]) -> str | None:
    return excinfo.value.error_list[0].code


def test_create_group(actor):
    group = create_group(" net-ops.West_1 ", actor, description="Network operations")
    assert group.name == "net-ops.West_1"
    assert group.description == "Network operations"
    event = AuditEvent.objects.get()
    assert event.event_type == EventType.GROUP_CREATED
    assert event.details == {"group": "net-ops.West_1"}


@pytest.mark.parametrize("name", ["", "net ops", "x" * 65, "équipe", "a/b", "a:b"])
def test_group_names_follow_the_radiator_rule(actor, name):
    with pytest.raises(ValidationError) as excinfo:
        create_group(name, actor)
    assert code_of(excinfo) == "invalid_group_name"


def test_group_names_are_unique_regardless_of_case(actor):
    create_group("NetOps", actor)
    with pytest.raises(ValidationError) as excinfo:
        create_group("netops", actor)
    assert code_of(excinfo) == "group_name_taken"
    with pytest.raises(IntegrityError), transaction.atomic():
        Group.objects.create(name="NETOPS")


def test_rename_keeps_the_id_and_members(actor, make_user):
    group = create_group("netops", actor)
    user = make_user()
    add_member(group, user, actor)
    group_id = group.pk
    update_group(group, actor, name="noc", description="")
    assert group.pk == group_id
    assert group.name == "noc"
    assert list(user.groups.all()) == [group]
    event = AuditEvent.objects.get(event_type=EventType.GROUP_UPDATED)
    assert event.details == {"group": "noc", "old_name": "netops"}


def test_rename_to_another_case_of_its_own_name(actor):
    group = create_group("netops", actor)
    update_group(group, actor, name="NetOps", description="")
    assert group.name == "NetOps"


def test_rename_to_a_name_in_use_is_refused(actor):
    create_group("noc", actor)
    group = create_group("netops", actor)
    with pytest.raises(ValidationError) as excinfo:
        update_group(group, actor, name="NOC", description="")
    assert code_of(excinfo) == "group_name_taken"


def test_change_description(actor):
    group = create_group("netops", actor, description="old")
    update_group(group, actor, name="netops", description="new")
    assert group.description == "new"
    event = AuditEvent.objects.get(event_type=EventType.GROUP_UPDATED)
    assert event.details == {"group": "netops", "old_description": "old", "new_description": "new"}


def test_update_without_a_change_records_nothing(actor):
    group = create_group("netops", actor, description="d")
    update_group(group, actor, name="netops", description="d")
    assert not AuditEvent.objects.filter(event_type=EventType.GROUP_UPDATED).exists()


def test_delete_group_removes_memberships_not_users(actor, make_user):
    group = create_group("netops", actor)
    users = [make_user(), make_user()]
    for user in users:
        add_member(group, user, actor)
    delete_group(group, actor)
    assert not Group.objects.exists()
    assert not UserGroup.objects.exists()
    assert User.objects.count() == 2
    event = AuditEvent.objects.get(event_type=EventType.GROUP_DELETED)
    assert event.details == {"group": "netops", "members": 2}


def test_the_default_group_cannot_be_deleted(actor):
    group = create_group("netops", actor)
    portal_settings.update({"default_group": group.pk}, actor)
    with pytest.raises(ValidationError) as excinfo:
        delete_group(group, actor)
    assert code_of(excinfo) == "default_group"
    assert Group.objects.filter(pk=group.pk).exists()
    portal_settings.update({"default_group": None}, actor)
    delete_group(group, actor)
    assert not Group.objects.exists()


def test_membership_changes_are_audited_once(actor, make_user):
    group = create_group("netops", actor)
    user = make_user("alice")
    add_member(group, user, actor)
    add_member(group, user, actor)
    assert list(user.groups.all()) == [group]
    remove_member(group, user, actor)
    remove_member(group, user, actor)
    assert not user.groups.exists()
    events = AuditEvent.objects.exclude(event_type=EventType.GROUP_CREATED).order_by("timestamp")
    assert [(e.event_type, e.target_username_snapshot, e.details) for e in events] == [
        (EventType.GROUP_MEMBER_ADDED, "alice", {"group": "netops"}),
        (EventType.GROUP_MEMBER_REMOVED, "alice", {"group": "netops"}),
    ]


def test_a_user_can_be_in_several_groups(actor, make_user):
    user = make_user()
    groups = [create_group(name, actor) for name in ("netops", "noc", "vip")]
    for group in groups:
        add_member(group, user, actor)
    assert set(user.groups.all()) == set(groups)


def test_deleting_a_user_removes_its_memberships(actor, make_user):
    group = create_group("netops", actor)
    user = make_user()
    add_member(group, user, actor)
    user.delete()
    assert not UserGroup.objects.exists()
    assert Group.objects.exists()
