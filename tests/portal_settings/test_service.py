import uuid

import pytest
from django.core.exceptions import ValidationError

from yk_portal.accounts.groups import create_group
from yk_portal.accounts.models import Theme
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.audit.service import Actor
from yk_portal.portal_settings.models import Setting
from yk_portal.portal_settings.service import KEYS, PortalSettings, current, update

pytestmark = pytest.mark.django_db


def test_defaults_match_addendum_3_2():
    assert current() == PortalSettings(
        portal_name="yk-portal",
        login_notice="",
        idle_timeout_minutes=20,
        max_session_hours=12,
        temp_password_hours=72,
        failed_login_limit=3,
        address_failure_limit=10,
        address_wait_minutes=15,
        max_yubikeys_per_user=10,
        step_up_before_reveal=True,
        default_group=None,
        default_theme=Theme.BROWSER,
    )


def test_update_and_read_back(actor):
    expected = PortalSettings(
        portal_name="NetOps <Portal>",
        login_notice="Authorized use only.\nActivity is logged.",
        idle_timeout_minutes=30,
        max_session_hours=8,
        temp_password_hours=24,
        failed_login_limit=5,
        address_failure_limit=20,
        address_wait_minutes=60,
        max_yubikeys_per_user=4,
        step_up_before_reveal=False,
        default_theme=Theme.DARK,
    )
    changes = {key: getattr(expected, key) for key in KEYS if key != "default_group"}
    assert update(changes, actor) == list(changes)
    assert current() == expected


def test_each_change_is_audited_with_old_and_new_values(actor):
    update({"idle_timeout_minutes": 30, "portal_name": "yk-portal"}, actor)
    update({"idle_timeout_minutes": 45}, actor)
    events = AuditEvent.objects.order_by("timestamp")
    assert [(e.event_type, e.details) for e in events] == [
        (EventType.SETTING_CHANGED, {"setting": "idle_timeout_minutes", "old": 20, "new": 30}),
        (EventType.SETTING_CHANGED, {"setting": "idle_timeout_minutes", "old": 30, "new": 45}),
    ]


def test_an_unchanged_value_is_skipped(actor):
    assert update({"failed_login_limit": 3}, actor) == []
    assert not Setting.objects.exists()
    assert not AuditEvent.objects.exists()


def test_updated_by(actor, make_user):
    admin = make_user(admin=True)
    update({"failed_login_limit": 4}, Actor.for_user(admin))
    assert Setting.objects.get(key="failed_login_limit").updated_by == admin
    update({"failed_login_limit": 5}, actor)
    assert Setting.objects.get(key="failed_login_limit").updated_by is None


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("portal_name", ""),
        ("portal_name", "x" * 65),
        ("portal_name", 5),
        ("login_notice", "x" * 2001),
        ("idle_timeout_minutes", 4),
        ("idle_timeout_minutes", 241),
        ("idle_timeout_minutes", "20"),
        ("idle_timeout_minutes", True),
        ("max_session_hours", 0),
        ("max_session_hours", 25),
        ("temp_password_hours", 0),
        ("temp_password_hours", 337),
        ("failed_login_limit", 0),
        ("failed_login_limit", 11),
        ("max_yubikeys_per_user", 0),
        ("max_yubikeys_per_user", 11),
        ("step_up_before_reveal", "on"),
        ("default_theme", "sepia"),
        ("default_group", uuid.uuid4()),
        ("default_group", "netops"),
        ("no_such_setting", 1),
    ],
)
def test_invalid_values_change_nothing(actor, key, value):
    with pytest.raises(ValidationError) as excinfo:
        update({"portal_name": "Valid", key: value}, actor)
    assert list(excinfo.value.message_dict) == [key]
    assert current() == PortalSettings()
    assert not AuditEvent.objects.exists()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("portal_name", "x"),
        ("portal_name", "x" * 64),
        ("login_notice", "x" * 2000),
        ("idle_timeout_minutes", 5),
        ("idle_timeout_minutes", 240),
        ("max_session_hours", 1),
        ("max_session_hours", 24),
        ("temp_password_hours", 1),
        ("temp_password_hours", 336),
        ("failed_login_limit", 1),
        ("failed_login_limit", 10),
        ("max_yubikeys_per_user", 1),
    ],
)
def test_limits_are_inclusive(actor, key, value):
    update({key: value}, actor)
    assert getattr(current(), key) == value


def test_default_group(actor):
    netops = create_group("netops", actor)
    update({"default_group": netops.pk}, actor)
    assert current().default_group == netops.pk
    update({"default_group": None}, actor)
    assert current().default_group is None
    events = AuditEvent.objects.filter(event_type=EventType.SETTING_CHANGED).order_by("timestamp")
    assert [e.details for e in events] == [
        {"setting": "default_group", "old": None, "new": "netops"},
        {"setting": "default_group", "old": "netops", "new": None},
    ]
