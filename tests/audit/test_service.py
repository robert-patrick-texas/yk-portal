import logging

import pytest
from django.db import transaction

from yk_portal.audit.models import AuditEvent, EventType, Result
from yk_portal.audit.service import Actor, record

pytestmark = pytest.mark.django_db


def test_record_stores_the_event(make_user):
    admin = make_user("boss", admin=True)
    user = make_user("alice")
    actor = Actor(user=admin, name="boss", source_ip="192.0.2.7")
    event = record(EventType.ACCOUNT_DISABLED, actor, user, details={"n": 1}, result=Result.FAILURE)
    stored = AuditEvent.objects.get()
    assert stored == event
    assert stored.actor_user_id == admin.pk
    assert stored.actor_username_snapshot == "boss"
    assert stored.target_user_id == user.pk
    assert stored.target_username_snapshot == "alice"
    assert stored.source_ip == "192.0.2.7"
    assert stored.result == Result.FAILURE
    assert stored.details == {"n": 1}


def test_events_outlive_the_user(make_user, actor):
    user = make_user("alice")
    record(EventType.ACCOUNT_DELETED, actor, user)
    user_id = user.pk
    user.delete()
    event = AuditEvent.objects.get()
    assert event.target_user_id == user_id
    assert event.target_username_snapshot == "alice"


def test_committed_events_are_copied_to_the_log(
    make_user, caplog, django_capture_on_commit_callbacks
):
    alice = make_user("alice")
    actor = Actor(user=make_user("boss", admin=True), name="boss", source_ip="192.0.2.7")
    with caplog.at_level(logging.INFO, logger="yk_portal.audit"):
        with django_capture_on_commit_callbacks(execute=True):
            event = record(EventType.ACCOUNT_UPDATED, actor, alice, details={"n": 2, "a": "x"})
    assert caplog.messages == [
        f"ACCOUNT_UPDATED id={event.pk} actor=boss target=alice ip=192.0.2.7 result=SUCCESS "
        'details={"a": "x", "n": 2}'
    ]


def test_the_log_line_marks_what_is_missing(caplog, django_capture_on_commit_callbacks):
    anonymous = Actor(user=None, name="")
    with caplog.at_level(logging.INFO, logger="yk_portal.audit"):
        with django_capture_on_commit_callbacks(execute=True):
            event = record(EventType.LOGIN_FAILURE, anonymous, result=Result.FAILURE)
    assert caplog.messages == [
        f"LOGIN_FAILURE id={event.pk} actor=- target=- ip=- result=FAILURE details={{}}"
    ]


def test_rolled_back_events_are_not_logged(actor, caplog, django_capture_on_commit_callbacks):
    with caplog.at_level(logging.INFO, logger="yk_portal.audit"):
        with django_capture_on_commit_callbacks(execute=True) as callbacks:
            try:
                with transaction.atomic():
                    record(EventType.SETTING_CHANGED, actor)
                    raise RuntimeError
            except RuntimeError:
                pass
    assert callbacks == []
    assert caplog.messages == []
    assert not AuditEvent.objects.exists()


def test_cli_actor(monkeypatch):
    monkeypatch.setattr("getpass.getuser", lambda: "yk-portal")
    monkeypatch.delenv("SUDO_USER", raising=False)
    assert Actor.cli() == Actor(user=None, name="cli:yk-portal")
    monkeypatch.setenv("SUDO_USER", "rob")
    assert Actor.cli().name == "cli:yk-portal (sudo by rob)"
