"""Changes made at the same moment end the same way on SQLite and PostgreSQL
(spec §48; addendum §18.4).

SQLite's writers take turns; PostgreSQL's don't, and a check one transaction
makes can be overtaken by another. Each test runs its changes in threads
released together, and checks an outcome that holds in whatever order they run.
"""

import threading
from collections.abc import Callable

import pytest
from django.core.exceptions import ValidationError
from django.db import connections

from yk_portal.accounts import groups, services
from yk_portal.accounts.models import Role
from yk_portal.audit.models import AuditEvent, EventType
from yk_portal.portal_settings import service as portal_settings
from yk_portal.yubikeys import management
from yk_portal.yubikeys.management import NewYubikey
from yk_portal.yubikeys.models import ProvisioningMethod, YubikeyCredential

pytestmark = [pytest.mark.django_db(transaction=True), pytest.mark.usefixtures("master_key")]


@pytest.fixture(autouse=True)
def roles() -> None:
    """The roles of migration 0002, which an earlier transactional test's flush removed."""
    for name in (Role.USER, Role.ADMIN):
        Role.objects.get_or_create(name=name)


def at_once(*calls: Callable[[], object]) -> list[object]:
    """Run each call in its own thread, all at once: each one's result, or its exception."""
    barrier = threading.Barrier(len(calls))
    results: list[object] = [None] * len(calls)

    def run(n: int, call: Callable[[], object]) -> None:
        try:
            barrier.wait()
            results[n] = call()
        except Exception as e:  # noqa: BLE001 - checked by refusals()
            results[n] = e
        finally:
            connections.close_all()

    threads = [threading.Thread(target=run, args=(n, call)) for n, call in enumerate(calls)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def refusals(results: list[object]) -> list[str | None]:
    """The codes of the ValidationErrors among RESULTS. Any other exception is raised."""
    codes = []
    for result in results:
        if isinstance(result, ValidationError):
            codes.append(result.code)
        elif isinstance(result, BaseException):
            raise result
    return codes


# Checks of several rows (spec §9.1; addendum §14.3)


@pytest.mark.parametrize("change", ["revoke_admin", "disable", "delete_user"])
def test_two_admins_removing_each_other_leave_one(make_user, actor, change):
    a, b = make_user("a", admin=True), make_user("b", admin=True)
    results = at_once(
        lambda: services.revoke_admin(a, actor), lambda: getattr(services, change)(b, actor)
    )
    assert refusals(results) == ["last_admin"]
    assert services.enabled_admins().count() == 1


def test_two_bootstraps_make_one_admin(actor):
    results = at_once(
        lambda: services.bootstrap_admin("a", actor), lambda: services.bootstrap_admin("b", actor)
    )
    assert refusals(results) == ["admin_exists"]
    assert services.enabled_admins().count() == 1


@pytest.mark.parametrize("remove", [False, True])
def test_taking_both_yubikeys_leaves_one(make_user, make_credential, actor, remove):
    user = make_user("alice")
    keys = [make_credential(user), make_credential(user)]

    def take(key: YubikeyCredential) -> Callable[[], None]:
        if remove:
            return lambda: management.remove_yubikey(key, actor)
        return lambda: management.set_yubikey_enabled(key, actor, False)

    assert refusals(at_once(*map(take, keys))) == ["last_yubikey"]
    assert YubikeyCredential.objects.filter(user=user, enabled=True).count() == 1


# Unique values (yk_portal.core.db.recheck_on_conflict)


def test_one_username_for_two_accounts(actor):
    results = at_once(
        lambda: services.create_user("alice", actor), lambda: services.create_user("ALICE", actor)
    )
    assert refusals(results) == ["username_taken"]


def test_two_accounts_renamed_to_one_username(make_user, actor):
    a, b = make_user("a"), make_user("b")
    results = at_once(
        lambda: services.change_username(a, "c", actor),
        lambda: services.change_username(b, "c", actor),
    )
    assert refusals(results) == ["username_taken"]


def test_one_group_name_for_two_groups(actor):
    results = at_once(
        lambda: groups.create_group("noc", actor), lambda: groups.create_group("NOC", actor)
    )
    assert refusals(results) == ["group_name_taken"]


def test_one_yubikey_for_two_accounts(make_user, actor):
    alice, bob = make_user("alice"), make_user("bob")
    key = NewYubikey("vvccccbbcdef", bytes.fromhex("4a6f8e2d1c3b"), bytes(16))
    method = ProvisioningMethod.ADMIN_PROVISIONED
    results = at_once(
        lambda: management.add_yubikey(alice, actor, key, method),
        lambda: management.add_yubikey(bob, actor, key, method),
    )
    assert refusals(results) == ["public_id_taken"]


# Settings, which have no row until first changed (yk_portal.core.db.take_turns)


def test_settings_changes_each_record_the_value_they_replaced(actor):
    at_once(
        lambda: portal_settings.update({"failed_login_limit": 4}, actor),
        lambda: portal_settings.update({"failed_login_limit": 5}, actor),
    )
    events = AuditEvent.objects.filter(event_type=EventType.SETTING_CHANGED).order_by("timestamp")
    changes = [(e.details["old"], e.details["new"]) for e in events]
    assert changes in ([(3, 4), (4, 5)], [(3, 5), (5, 4)])
