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


def test_committed_events_are_copied_to_the_log(actor, caplog, django_capture_on_commit_callbacks):
    with caplog.at_level(logging.INFO, logger="yk_portal.audit"):
        with django_capture_on_commit_callbacks(execute=True):
            record(EventType.SETTING_CHANGED, actor, details={"setting": "x", "new": 2})
    assert caplog.messages == [
        f"SETTING_CHANGED actor={actor.name} target=- result=SUCCESS "
        'details={"new": 2, "setting": "x"}'
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
