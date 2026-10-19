"""The admin pages for accounts, groups and settings (spec §9, §15, §26; addendum §3, §5)."""

import re

import pytest
from django.urls import reverse

from yk_portal.accounts import groups as group_service
from yk_portal.accounts import services
from yk_portal.accounts.models import AccountState, Group, User
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.authentication.models import Session
from yk_portal.authentication.passwords import check_web_password
from yk_portal.authentication.sessions import COOKIE, start_session
from yk_portal.authentication.sessions import Client as SessionClient
from yk_portal.portal_settings import service as portal_settings
from yk_portal.yubikeys.models import YubikeyCredential

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("master_key")]


def signed_in(client, user: User) -> Session:
    """Give CLIENT a session for USER, without the sign-in page."""
    session, token = start_session(user, SessionClient("127.0.0.1", "pytest"))
    client.cookies[COOKIE] = token
    return session


def page(response) -> str:
    assert response.status_code == 200, response.status_code
    return response.content.decode()


def events(event_type: EventType) -> list[AuditEvent]:
    return list(AuditEvent.objects.filter(event_type=event_type))


@pytest.fixture
def root(client, make_user):
    """An ACTIVE admin, signed in."""
    user = make_user("root", admin=True)
    signed_in(client, user)
    return user


@pytest.fixture
def alice(make_user, make_credential):
    """An ACTIVE account with one YubiKey."""
    user = make_user("alice", email="alice@example.com")
    make_credential(user, public_id="vvccccbbcdeg", label="keyring")
    return user


# Who may open the admin pages (spec §6)


ADMIN_PAGES = ["admin-users", "admin-user-new", "admin-groups", "admin-group-new", "admin-settings"]


@pytest.mark.parametrize("name", ADMIN_PAGES)
def test_anonymous_users_are_sent_to_sign_in(client, name):
    assert client.get(reverse(name)).headers["Location"] == reverse("login")


@pytest.mark.parametrize("name", ADMIN_PAGES)
def test_users_without_the_admin_role_are_refused(client, alice, name):
    signed_in(client, alice)
    response = client.get(reverse(name))
    assert response.status_code == 403
    assert "This page is for admins." in response.content.decode()


def test_admin_actions_are_refused_to_users(client, alice, make_user):
    bob = make_user("bob")
    signed_in(client, alice)
    assert client.post(reverse("admin-user-disable", args=[bob.pk])).status_code == 403
    assert User.objects.get(pk=bob.pk).state == AccountState.ACTIVE


def test_a_provisioning_admin_is_sent_to_onboarding(client, make_user):
    signed_in(client, make_user("newroot", state=AccountState.PROVISIONING, admin=True))
    assert client.get(reverse("admin-users")).headers["Location"] == reverse("provision")


def test_a_role_taken_away_applies_at_the_next_request(client, root, make_user, actor):
    make_user("other", admin=True)
    assert client.get(reverse("admin-users")).status_code == 200
    services.revoke_admin(root, actor)
    assert client.get(reverse("admin-users")).status_code == 403


@pytest.mark.parametrize("name", ADMIN_PAGES)
def test_admin_pages_are_never_cached(client, root, name):
    assert "no-store" in client.get(reverse(name)).headers["Cache-Control"]


def test_only_admins_see_the_admin_links(client, root, alice):
    html = page(client.get(reverse("home")))
    assert reverse("admin-users") in html and reverse("admin-settings") in html
    signed_in(client, alice)
    assert reverse("admin-users") not in page(client.get(reverse("home")))


# The user list (spec §9)


def test_user_list(client, root, alice, actor):
    group_service.add_member(group_service.create_group("noc", actor), alice, actor)
    html = page(client.get(reverse("admin-users")))
    assert "2 accounts" in html
    assert reverse("admin-user", args=[alice.pk]) in html
    assert "alice@example.com" in html and "noc" in html
    assert re.search(r"root</a> <span class=\"tag\">admin</span>", html)
    assert not re.search(r"alice</a> <span class=\"tag\">admin</span>", html)


@pytest.mark.parametrize(
    ("query", "found"),
    [
        ({"q": "ALI"}, {"alice"}),
        ({"q": "example.com"}, {"alice"}),
        ({"state": "LOCKED"}, {"locked"}),
        ({"role": "admin"}, {"root"}),
        ({"role": "user"}, {"alice", "locked", "member"}),
        ({"group": "noc"}, {"member"}),
        ({"q": "nobody"}, set()),
    ],
)
def test_search_and_filters(client, root, alice, make_user, actor, query, found):
    make_user("locked", state=AccountState.LOCKED)
    noc = group_service.create_group("noc", actor)
    group_service.add_member(noc, make_user("member"), actor)
    if "group" in query:
        query = {"group": str(noc.pk)}
    html = page(client.get(reverse("admin-users"), query))
    shown = set(re.findall(r'<a href="/admin/users/[0-9a-f-]+/">([a-z]+)</a>', html))
    assert shown == found


@pytest.mark.parametrize("q", ["émile", "ÉMILE", "Émile"])
def test_search_ignores_the_case_of_any_letter(client, root, make_user, q):
    """Also on SQLite, whose LIKE folds only ASCII letters (addendum §18.3)."""
    make_user("ezola", display_name="Émile Zola")
    make_user("emil", display_name="Emil")
    html = page(client.get(reverse("admin-users"), {"q": q}))
    assert set(re.findall(r'<a href="/admin/users/[0-9a-f-]+/">([a-z]+)</a>', html)) == {"ezola"}


def test_pages_of_fifty(client, root, make_user):
    for n in range(60):
        make_user(f"user{n:02}")
    html = page(client.get(reverse("admin-users"), {"q": "user"}))
    assert "60 accounts" in html and "Page 1 of 2" in html
    assert "?q=user&amp;page=2" in html
    html = page(client.get(reverse("admin-users"), {"q": "user", "page": 2}))
    assert "user59" in html and "user09" not in html


# Creating accounts (spec §10)


def test_create_an_account(client, root, actor):
    noc = group_service.create_group("noc", actor)
    group_service.create_group("ops", actor)
    portal_settings.update({"default_group": noc.pk}, actor)
    form = page(client.get(reverse("admin-user-new")))
    # The default group is ticked to start with (addendum §5.4).
    assert re.search(rf'value="{noc.pk}"[^>]*checked', form)

    response = client.post(
        reverse("admin-user-new"), {"username": "Nina", "email": "", "groups": [str(noc.pk)]}
    )
    html = page(response)
    assert "no-store" in response.headers["Cache-Control"]
    nina = User.objects.get(username="nina")
    assert nina.state == AccountState.PROVISIONING and not nina.is_admin
    assert list(nina.groups.all()) == [noc]
    temporary = re.search(r"<code>([a-z0-9-]{19})</code>", html)
    assert temporary and check_web_password(temporary.group(1), nina.temporary_password_hash)
    assert "add a YubiKey and choose its PIN" in html
    assert reverse("admin-yubikey-add", args=[nina.pk]) in html


def test_create_with_a_display_name_and_comment(client, root):
    client.post(
        reverse("admin-user-new"),
        {"username": "nina", "display_name": "Nina Patel", "comment": "Joins the NOC in May"},
    )
    nina = User.objects.get(username="nina")
    assert (nina.display_name, nina.comment) == ("Nina Patel", "Joins the NOC in May")


def test_create_an_admin_without_groups(client, root, actor):
    noc = group_service.create_group("noc", actor)
    portal_settings.update({"default_group": noc.pk}, actor)
    client.post(reverse("admin-user-new"), {"username": "boss", "admin": "on"})
    boss = User.objects.get(username="boss")
    assert boss.is_admin
    assert not boss.groups.exists()  # unticked: no group, not the default


@pytest.mark.parametrize(
    ("username", "message"),
    [
        ("alice", "That username is taken."),
        ("svc.radius", "reserved for Radiator"),
        ("a b", "Use 1 to 255 lowercase letters"),
    ],
)
def test_create_refuses_bad_usernames(client, root, alice, username, message):
    html = page(client.post(reverse("admin-user-new"), {"username": username}))
    assert message in html
    assert User.objects.count() == 2


# One account's page and changes


def test_user_page(client, root, alice):
    html = page(client.get(reverse("admin-user", args=[alice.pk])))
    assert "<h1>alice" in html and "alice@example.com" in html
    assert "vvccccbbcdeg" in html and "keyring" in html
    assert (
        reverse("admin-yubikey-secrets", args=[alice.pk, YubikeyCredential.objects.get().pk])
        in html
    )
    assert "Make admin" in html and "Reset to provisioning" in html and "Disable" in html
    assert "Unlock" not in html and "New temporary password" not in html


def test_unknown_accounts_are_not_found(client, root):
    response = client.get(reverse("admin-user", args=["00000000-0000-0000-0000-000000000000"]))
    assert response.status_code == 404
    assert "Not found" in response.content.decode()


def test_edit_an_account(client, root, alice, actor):
    noc = group_service.create_group("noc", actor)
    ops = group_service.create_group("ops", actor)
    group_service.add_member(noc, alice, actor)
    before = list(AuditEvent.objects.values_list("pk", flat=True))
    response = client.post(
        reverse("admin-user-edit", args=[alice.pk]),
        {"username": "alicia", "email": "alicia@example.com", "groups": [str(ops.pk)]},
    )
    assert response.headers["Location"] == reverse("admin-user", args=[alice.pk])
    alice.refresh_from_db()
    assert (alice.username, alice.email) == ("alicia", "alicia@example.com")
    assert list(alice.groups.all()) == [ops]
    after = AuditEvent.objects.exclude(pk__in=before)
    assert sorted(after.values_list("event_type", flat=True)) == [
        EventType.ACCOUNT_UPDATED,
        EventType.GROUP_MEMBER_ADDED,
        EventType.GROUP_MEMBER_REMOVED,
        EventType.USERNAME_CHANGED,
    ]


def test_display_name_and_comment_are_for_admins(client, root, alice, actor):
    services.update_account(
        alice, actor, display_name="Smith, Alice <b>", comment="Badge 42\n<script>x</script>"
    )
    html = page(client.get(reverse("admin-user", args=[alice.pk])))
    assert "Smith, Alice &lt;b&gt;" in html
    assert "Badge 42<br>&lt;script&gt;x&lt;/script&gt;" in html
    assert "Smith, Alice &lt;b&gt;" in page(client.get(reverse("admin-users")))
    # Searching finds display names.
    html = page(client.get(reverse("admin-users"), {"q": "smith"}))
    assert reverse("admin-user", args=[alice.pk]) in html
    # The user never sees them.
    signed_in(client, alice)
    html = page(client.get(reverse("home")))
    assert "Smith" not in html and "Badge" not in html


def test_edit_the_display_name_and_comment(client, root, alice):
    edit = reverse("admin-user-edit", args=[alice.pk])
    html = page(
        client.post(
            edit, {"username": "alice", "email": "alice@example.com", "display_name": "A\tB"}
        )
    )
    assert "Use one line, without control characters." in html
    client.post(
        edit,
        {
            "username": "alice",
            "email": "alice@example.com",
            "display_name": "Alice Smith",
            "comment": "On call\r\nweekends",
        },
    )
    alice.refresh_from_db()
    assert (alice.display_name, alice.comment) == ("Alice Smith", "On call\nweekends")
    html = page(client.get(edit))
    assert 'value="Alice Smith"' in html and "On call\nweekends</textarea>" in html


def test_a_refused_edit_changes_nothing(client, root, alice):
    html = page(
        client.post(
            reverse("admin-user-edit", args=[alice.pk]),
            {"username": "root", "email": "new@example.com"},
        )
    )
    assert "That username is taken." in html
    alice.refresh_from_db()
    assert (alice.username, alice.email) == ("alice", "alice@example.com")


@pytest.mark.parametrize(
    ("name", "state", "after"),
    [
        ("admin-user-disable", AccountState.ACTIVE, AccountState.DISABLED),
        ("admin-user-disable", AccountState.PROVISIONING, AccountState.DISABLED),
        ("admin-user-enable", AccountState.DISABLED, AccountState.ACTIVE),
        ("admin-user-unlock", AccountState.LOCKED, AccountState.ACTIVE),
    ],
)
def test_state_changes(client, root, alice, name, state, after):
    User.objects.filter(pk=alice.pk).update(state=state)
    assert client.get(reverse(name, args=[alice.pk])).status_code == 405
    response = client.post(reverse(name, args=[alice.pk]))
    assert response.headers["Location"] == reverse("admin-user", args=[alice.pk])
    assert User.objects.get(pk=alice.pk).state == after


def test_a_refused_change_shows_why(client, root, make_user):
    disabled = make_user("dora", state=AccountState.DISABLED)  # no YubiKey with a PIN
    html = page(client.post(reverse("admin-user-enable", args=[disabled.pk])))
    assert "This account has no YubiKey with a PIN" in html
    assert User.objects.get(pk=disabled.pk).state == AccountState.DISABLED


def test_the_last_admin_is_kept(client, root):
    for name in ("admin-user-disable", "admin-user-revoke-admin"):
        html = page(client.post(reverse(name, args=[root.pk])))
        assert "This is the last enabled admin account" in html
    assert root.is_admin


def test_roles(client, root, alice):
    client.post(reverse("admin-user-grant-admin", args=[alice.pk]))
    assert alice.is_admin
    client.post(reverse("admin-user-revoke-admin", args=[alice.pk]))
    assert not alice.is_admin


def test_admins_who_give_up_the_role_go_home(client, root, make_user):
    make_user("other", admin=True)
    response = client.post(reverse("admin-user-revoke-admin", args=[root.pk]))
    assert response.headers["Location"] == reverse("home")


def test_reset_to_provisioning(client, root, alice):
    other, _ = start_session(alice, SessionClient("127.0.0.1", "pytest"))
    html = page(client.get(reverse("admin-user-reset", args=[alice.pk])))
    assert "its 1 enabled YubiKey is disabled, not deleted" in html
    html = page(client.post(reverse("admin-user-reset", args=[alice.pk])))
    alice.refresh_from_db()
    assert alice.state == AccountState.PROVISIONING
    temporary = re.search(r"<code>([a-z0-9-]{19})</code>", html)
    assert temporary and check_web_password(temporary.group(1), alice.temporary_password_hash)
    assert "add a YubiKey and choose its PIN" in html  # its only key is disabled
    assert not YubikeyCredential.objects.get(user=alice).enabled
    assert Session.objects.get(pk=other.pk).revoked_at is not None


def test_a_provisioning_account_gets_a_new_temporary_password(client, root, actor):
    nina = services.create_user("nina", actor).user
    old = nina.temporary_password_hash
    html = page(client.get(reverse("admin-user", args=[nina.pk])))
    assert "New temporary password" in html and "Reset to provisioning" not in html
    assert client.get(reverse("admin-user-temporary-password", args=[nina.pk])).status_code == 405
    html = page(client.post(reverse("admin-user-temporary-password", args=[nina.pk])))
    nina.refresh_from_db()
    assert nina.temporary_password_hash != old
    temporary = re.search(r"<code>([a-z0-9-]{19})</code>", html)
    assert temporary and check_web_password(temporary.group(1), nina.temporary_password_hash)


def test_a_new_temporary_password_only_while_provisioning(client, root, alice):
    html = page(client.post(reverse("admin-user-temporary-password", args=[alice.pk])))
    assert "Not allowed while the account is ACTIVE." in html


# Hard delete (spec §26; addendum §6.6)


def test_delete_an_account(client, root, alice):
    html = page(client.get(reverse("admin-user-delete", args=[alice.pk])))
    assert "vvccccbbcdeg" in html
    assert "sudo /opt/radiator-yubikey/yubikey-db.sh delete alice</code>" in html

    html = page(client.post(reverse("admin-user-delete", args=[alice.pk]), {"username": "alic"}))
    assert "Enter alice exactly." in html
    assert User.objects.filter(pk=alice.pk).exists()

    html = page(client.post(reverse("admin-user-delete", args=[alice.pk]), {"username": "alice"}))
    assert "Deleted alice" in html and "yubikey-db.sh delete alice</code>" in html
    assert not User.objects.filter(pk=alice.pk).exists()
    assert not YubikeyCredential.objects.filter(user_id=alice.pk).exists()
    assert events(EventType.ACCOUNT_DELETED)[0].actor_username_snapshot == "root"


def test_the_last_admin_cant_be_deleted(client, root):
    html = page(client.post(reverse("admin-user-delete", args=[root.pk]), {"username": "root"}))
    assert "This is the last enabled admin account" in html
    assert User.objects.filter(pk=root.pk).exists()


# Groups (addendum §5)


def test_group_list(client, root, alice, actor):
    noc = group_service.create_group("noc", actor, "Network operations")
    group_service.create_group("ops", actor)
    group_service.add_member(noc, alice, actor)
    portal_settings.update({"default_group": noc.pk}, actor)
    html = page(client.get(reverse("admin-groups")))
    assert "Network operations" in html
    assert re.search(r"noc</a> <span class=\"tag\">default</span>", html)
    assert re.search(r"<td>1</td>", html) and re.search(r"<td>0</td>", html)


def test_create_and_rename_a_group(client, root, actor):
    response = client.post(reverse("admin-group-new"), {"name": "noc", "description": "NOC"})
    noc = Group.objects.get(name="noc")
    assert response.headers["Location"] == reverse("admin-group", args=[noc.pk])
    client.post(reverse("admin-group-edit", args=[noc.pk]), {"name": "noc-tx", "description": ""})
    noc.refresh_from_db()
    assert (noc.name, noc.description) == ("noc-tx", "")
    assert [e.event_type for e in AuditEvent.objects.order_by("timestamp")] == [
        EventType.GROUP_CREATED,
        EventType.GROUP_UPDATED,
    ]


@pytest.mark.parametrize(
    ("name", "message"),
    [("NOC", "A group with that name exists."), ("no spaces", "Use 1 to 64 letters")],
)
def test_group_names_are_checked(client, root, actor, name, message):
    group_service.create_group("noc", actor)
    assert message in page(client.post(reverse("admin-group-new"), {"name": name}))
    assert Group.objects.count() == 1


def test_group_members(client, root, alice, actor):
    noc = group_service.create_group("noc", actor)
    add = reverse("admin-group-member-add", args=[noc.pk])
    assert client.get(add).status_code == 405
    html = page(client.post(add, {"username": "nobody"}))
    assert "No account has that username." in html
    response = client.post(add, {"username": "ALICE"})
    assert response.headers["Location"] == reverse("admin-group", args=[noc.pk])
    html = page(client.get(reverse("admin-group", args=[noc.pk])))
    assert reverse("admin-user", args=[alice.pk]) in html
    client.post(reverse("admin-group-member-remove", args=[noc.pk, alice.pk]))
    assert not alice.groups.exists()


def test_delete_a_group(client, root, alice, actor):
    noc = group_service.create_group("noc", actor)
    group_service.add_member(noc, alice, actor)
    html = page(client.get(reverse("admin-group-delete", args=[noc.pk])))
    assert "Its 1 member loses the group; their accounts stay." in html
    response = client.post(reverse("admin-group-delete", args=[noc.pk]))
    assert response.headers["Location"] == reverse("admin-groups")
    assert not Group.objects.exists()
    assert User.objects.filter(pk=alice.pk).exists()


def test_the_default_group_cant_be_deleted(client, root, actor):
    noc = group_service.create_group("noc", actor)
    portal_settings.update({"default_group": noc.pk}, actor)
    html = page(client.get(reverse("admin-group-delete", args=[noc.pk])))
    assert "This is the default group." in html and "Delete it" not in html
    html = page(client.post(reverse("admin-group-delete", args=[noc.pk])))
    assert "This is the default group; choose another default" in html
    assert Group.objects.exists()


# Settings (addendum §3)


def settings_form(**changes: object) -> dict[str, object]:
    data: dict[str, object] = {
        "portal_name": "yk-portal",
        "login_notice": "",
        "idle_timeout_minutes": 20,
        "max_session_hours": 12,
        "temp_password_hours": 72,
        "failed_login_limit": 3,
        "max_yubikeys_per_user": 10,
        "step_up_before_reveal": "on",
        "default_group": "",
        "default_theme": "browser",
    }
    return data | changes


def test_settings_page_shows_the_current_values(client, root, actor):
    portal_settings.update({"idle_timeout_minutes": 30}, actor)
    html = page(client.get(reverse("admin-settings")))
    assert 'name="idle_timeout_minutes" value="30"' in html
    assert "5 to 240 minutes." in html
    assert re.search(r'name="step_up_before_reveal"[^>]*checked', html)


def test_change_settings(client, root, actor):
    noc = group_service.create_group("noc", actor)
    response = client.post(
        reverse("admin-settings"),
        settings_form(
            portal_name="NOC portal",
            login_notice="Authorized use only.\r\nAll access is logged.",
            idle_timeout_minutes=30,
            step_up_before_reveal="",
            default_group=str(noc.pk),
            default_theme="dark",
        ),
    )
    assert response.headers["Location"] == reverse("admin-settings") + "?saved=1"
    current = portal_settings.current()
    assert current.portal_name == "NOC portal"
    assert current.login_notice == "Authorized use only.\nAll access is logged."
    assert current.idle_timeout_minutes == 30
    assert not current.step_up_before_reveal
    assert current.default_group == noc.pk
    assert current.default_theme == "dark"
    changed = {e.details["setting"] for e in events(EventType.SETTING_CHANGED)}
    assert changed == {
        "portal_name",
        "login_notice",
        "idle_timeout_minutes",
        "step_up_before_reveal",
        "default_group",
        "default_theme",
    }
    assert "Saved." in page(client.get(response.headers["Location"]))


def test_settings_out_of_range_change_nothing(client, root):
    html = page(
        client.post(
            reverse("admin-settings"),
            settings_form(portal_name="New", idle_timeout_minutes=2, failed_login_limit=11),
        )
    )
    assert "Use a whole number from 5 to 240." in html
    assert "Use a whole number from 1 to 10." in html
    assert portal_settings.current().portal_name == "yk-portal"
    assert not events(EventType.SETTING_CHANGED)
