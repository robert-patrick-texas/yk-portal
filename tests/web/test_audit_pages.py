"""The admin audit log (spec §35; addendum §17.3, §17.4)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from django.urls import reverse

from yk_portal.accounts import services
from yk_portal.accounts.models import User
from yk_portal.audit.models import AuditEvent, EventType, Result
from yk_portal.audit.service import Actor, record
from yk_portal.authentication.models import Session
from yk_portal.authentication.sessions import COOKIE, start_session
from yk_portal.authentication.sessions import Client as SessionClient

pytestmark = pytest.mark.django_db


def signed_in(client, user: User) -> Session:
    session, token = start_session(user, SessionClient("127.0.0.1", "pytest"))
    client.cookies[COOKIE] = token
    return session


def page(response) -> str:
    assert response.status_code == 200, response.status_code
    return response.content.decode()


def listed(html: str) -> list[str]:
    """The event types in the list, top to bottom."""
    return [
        line.split("<code>")[1].split("</code>")[0]
        for line in html.splitlines()
        if line.strip().startswith("<td><code>")
    ]


@pytest.fixture
def root(client, make_user):
    user = make_user("root", admin=True)
    signed_in(client, user)
    return user


def at(when: datetime, event_type: EventType, actor: Actor, target: User | None = None, **kw):
    """An event with the timestamp WHEN: recorded, then given the time before it's saved."""
    event = AuditEvent(
        timestamp=when,
        event_type=event_type,
        actor_user_id=actor.user.pk if actor.user else None,
        actor_username_snapshot=actor.name,
        target_user_id=target.pk if target else None,
        target_username_snapshot=target.username if target else "",
        source_ip=actor.source_ip,
        **kw,
    )
    event.save()
    return event


# Who may see it


def test_anonymous_users_are_sent_to_sign_in(client):
    assert client.get(reverse("admin-audit")).headers["Location"] == reverse("login")


def test_users_are_refused_and_the_attempt_is_recorded(client, make_user):
    alice = make_user("alice")
    session = signed_in(client, alice)
    response = client.get(reverse("admin-audit") + "?q=root", REMOTE_ADDR="192.0.2.7")
    assert response.status_code == 403
    event = AuditEvent.objects.get()
    assert (event.event_type, event.result) == (EventType.ACCESS_DENIED, Result.FAILURE)
    assert (event.actor_user_id, event.actor_username_snapshot) == (alice.pk, "alice")
    assert (event.source_ip, event.session_id) == ("192.0.2.7", session.pk)
    assert event.details == {"method": "GET", "path": "/admin/audit/"}  # no query string


def test_refused_admin_actions_are_recorded(client, make_user):
    alice, bob = make_user("alice"), make_user("bob")
    signed_in(client, alice)
    client.post(reverse("admin-user-disable", args=[bob.pk]))
    event = AuditEvent.objects.get()
    assert event.event_type == EventType.ACCESS_DENIED
    assert event.details == {"method": "POST", "path": f"/admin/users/{bob.pk}/disable/"}


def test_only_admins_see_the_link(client, root, make_user):
    assert f'href="{reverse("admin-audit")}"' in page(client.get(reverse("home")))
    signed_in(client, make_user("alice"))
    assert f'href="{reverse("admin-audit")}"' not in page(client.get(reverse("home")))


def test_the_pages_are_not_cached(client, root, actor):
    event = record(EventType.SETTING_CHANGED, actor)
    for url in (reverse("admin-audit"), reverse("admin-audit-event", args=[event.pk])):
        assert "no-store" in client.get(url).headers["Cache-Control"]


# The list


def test_newest_first_with_details(client, root, actor, make_user):
    alice = make_user("alice")
    now = datetime.now(UTC)
    at(now - timedelta(hours=2), EventType.ACCOUNT_CREATED, actor, alice)
    failed = Actor(user=None, name="", source_ip="198.51.100.4")
    reason = {"reason": "wrong PIN", "public_ids": ["vvccccbbcdef", "vvccccbbcdeg"]}
    hour_ago = now - timedelta(hours=1)
    at(hour_ago, EventType.LOGIN_FAILURE, failed, alice, result=Result.FAILURE, details=reason)
    html = page(client.get(reverse("admin-audit")))
    assert listed(html) == ["LOGIN_FAILURE", "ACCOUNT_CREATED"]
    assert "2 events." in html
    assert '<span class="tag failure">failed</span>' in html
    assert "198.51.100.4" in html
    assert '<span class="muted">reason</span> wrong PIN' in html
    assert "vvccccbbcdef, vvccccbbcdeg" in html
    assert actor.name in html


def test_values_are_escaped(client, root, actor):
    record(EventType.GROUP_CREATED, actor, details={"group": "<script>x</script>"})
    html = page(client.get(reverse("admin-audit")))
    assert "<script>x" not in html and "&lt;script&gt;x" in html


def test_fifty_events_a_page(client, root, actor):
    for _ in range(51):
        record(EventType.SETTING_CHANGED, actor)
    first = page(client.get(reverse("admin-audit")))
    assert len(listed(first)) == 50 and "Page 1 of 2" in first and "Older" in first
    second = page(client.get(reverse("admin-audit") + "?page=2"))
    assert len(listed(second)) == 1 and "Newer" in second


@pytest.fixture
def history(actor, make_user):
    """Events by different actors, of different types, results and days."""
    alice, bob = make_user("alice"), make_user("bob")
    day = datetime(2026, 10, 1, 12, tzinfo=UTC)
    by_alice = Actor(user=alice, name="alice", source_ip="192.0.2.1")
    at(day, EventType.LOGIN_SUCCESS, by_alice, alice, details={"public_id": "vvccccbbcdef"})
    at(day + timedelta(days=1), EventType.ACCOUNT_DISABLED, actor, bob)
    at(day + timedelta(days=2), EventType.GROUP_CREATED, actor, details={"group": "noc"})
    anonymous = Actor(user=None, name="", source_ip="2001:db8::1")
    at(day + timedelta(days=3), EventType.LOGIN_FAILURE, anonymous, bob, result=Result.FAILURE)
    return alice, bob


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("q=alice", ["LOGIN_SUCCESS"]),
        ("q=BOB", ["LOGIN_FAILURE", "ACCOUNT_DISABLED"]),
        ("q=cli:", ["GROUP_CREATED", "ACCOUNT_DISABLED"]),
        ("q=192.0.2.1", ["LOGIN_SUCCESS"]),
        ("q=2001:DB8:0::1", ["LOGIN_FAILURE"]),  # any spelling of the address
        ("q=vvccccbbcdef", ["LOGIN_SUCCESS"]),  # in the details
        ("q=noc", ["GROUP_CREATED"]),
        ("event_type=ACCOUNT_DISABLED", ["ACCOUNT_DISABLED"]),
        ("result=FAILURE", ["LOGIN_FAILURE"]),
        ("since=2026-10-02&until=2026-10-03", ["GROUP_CREATED", "ACCOUNT_DISABLED"]),
        ("since=2026-10-04", ["LOGIN_FAILURE"]),
        ("until=2026-10-01", ["LOGIN_SUCCESS"]),
        ("q=nobody", []),
    ],
)
def test_search_and_filters(client, root, history, query, expected):
    html = page(client.get(reverse("admin-audit") + "?" + query))
    assert listed(html) == expected


@pytest.mark.parametrize("q", ["Clé", "clé", "CLÉ DE"])
def test_search_finds_any_letters_in_the_details(client, root, actor, q):
    """Labels and text settings hold any letters: found on SQLite as on PostgreSQL, in any
    case (addendum §18.3)."""
    details = {"public_id": "vvccccbbcdef", "old_label": "", "new_label": "Clé de secours"}
    record(EventType.YUBIKEY_UPDATED, actor, details=details)
    record(EventType.YUBIKEY_UPDATED, actor, details={"new_label": "Cle"})
    html = page(client.get(reverse("admin-audit"), {"q": q}))
    assert listed(html) == ["YUBIKEY_UPDATED"]
    assert "Clé de secours" in page(client.get(reverse("admin-audit"), {"q": "secours"}))


def test_dates_out_of_order_are_an_error(client, root, history):
    html = page(client.get(reverse("admin-audit") + "?since=2026-10-03&until=2026-10-01"))
    assert "The From date is after the To date." in html


def test_one_accounts_events_by_id(client, root, history):
    alice, bob = history
    html = page(client.get(reverse("admin-audit") + f"?user={bob.pk}"))
    assert listed(html) == ["LOGIN_FAILURE", "ACCOUNT_DISABLED"]
    assert f'Events of <a href="{reverse("admin-user", args=[bob.pk])}">bob</a>' in html
    assert f'value="{bob.pk}"' in html  # kept by the filter form


def test_a_deleted_accounts_events(client, root, make_user):
    nina = make_user("nina")
    nina_id = nina.pk
    services.delete_user(nina, Actor.for_user(root))
    html = page(client.get(reverse("admin-audit") + f"?user={nina_id}"))
    assert listed(html) == ["ACCOUNT_DELETED"]
    assert 'Events of nina <span class="tag">deleted</span>' in html


def test_the_user_page_links_to_the_accounts_events(client, root, make_user):
    alice = make_user("alice")
    html = page(client.get(reverse("admin-user", args=[alice.pk])))
    assert f'href="{reverse("admin-audit")}?user={alice.pk}"' in html


# An event's page


def test_an_events_page(client, root, make_user):
    alice = make_user("alice")
    session = Session.objects.get(user=root)
    actor = Actor(user=root, name="root", source_ip="192.0.2.9", session_id=session.pk)
    event = record(
        EventType.YUBIKEY_REMOVED, actor, alice, details={"public_id": "vvccccbbcdef", "x": None}
    )
    html = page(client.get(reverse("admin-audit-event", args=[event.pk])))
    assert "<code>YUBIKEY_REMOVED</code>" in html
    assert f'<a href="{reverse("admin-user", args=[root.pk])}">root</a>' in html
    assert f'<a href="{reverse("admin-user", args=[alice.pk])}">alice</a>' in html
    assert f'href="{reverse("admin-audit")}?user={alice.pk}"' in html
    assert "192.0.2.9" in html and str(session.pk) in html and str(event.pk) in html
    assert "<dt>public_id</dt>" in html and "vvccccbbcdef" in html
    assert '<dt>x</dt><dd class="wrap">—</dd>' in html


def test_an_events_page_after_the_target_is_deleted(client, root, make_user):
    nina = make_user("nina")
    services.delete_user(nina, Actor.for_user(root))
    event = AuditEvent.objects.get(event_type=EventType.ACCOUNT_DELETED)
    html = page(client.get(reverse("admin-audit-event", args=[event.pk])))
    assert 'nina <span class="tag">deleted</span>' in html
    assert reverse("admin-user", args=[event.target_user_id]) not in html


def test_an_unknown_event_is_not_found(client, root):
    assert client.get(reverse("admin-audit-event", args=[uuid.uuid4()])).status_code == 404
