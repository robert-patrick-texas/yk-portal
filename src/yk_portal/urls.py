from django.urls import URLPattern, URLResolver, path

from yk_portal.accounts import admin_views as admin_users
from yk_portal.accounts import group_views as admin_groups
from yk_portal.accounts import views as accounts
from yk_portal.audit import views as admin_audit
from yk_portal.authentication import views as authentication
from yk_portal.portal_settings import views as admin_settings
from yk_portal.web import views as web
from yk_portal.yubikeys import admin_views as admin_yubikeys
from yk_portal.yubikeys import views as yubikeys

USER = "admin/users/<uuid:user_id>/"
KEY = USER + "yubikeys/<uuid:credential_id>/"
GROUP = "admin/groups/<uuid:group_id>/"

urlpatterns: list[URLPattern | URLResolver] = [
    path("", web.home, name="home"),
    path("theme/", web.set_theme, name="theme"),
    path("login/", authentication.login, name="login"),
    path("logout/", authentication.logout, name="logout"),
    path("provision/", accounts.provision, name="provision"),
    path("provision/email/", accounts.provision_email, name="provision-email"),
    path("provision/yubikey/", accounts.provision_yubikey, name="provision-yubikey"),
    path("account/yubikeys/", yubikeys.yubikeys, name="yubikeys"),
    path("account/yubikeys/add/", yubikeys.add, name="yubikey-add"),
    path("account/yubikeys/test/", yubikeys.test, name="yubikey-test"),
    path("account/yubikeys/<uuid:credential_id>/edit/", yubikeys.edit, name="yubikey-edit"),
    path("account/yubikeys/<uuid:credential_id>/pin/", yubikeys.pin, name="yubikey-pin"),
    path(
        "account/yubikeys/<uuid:credential_id>/enable/",
        yubikeys.set_enabled,
        {"enabled": True},
        name="yubikey-enable",
    ),
    path(
        "account/yubikeys/<uuid:credential_id>/disable/",
        yubikeys.set_enabled,
        {"enabled": False},
        name="yubikey-disable",
    ),
    path("account/yubikeys/<uuid:credential_id>/remove/", yubikeys.remove, name="yubikey-remove"),
    # Admin pages (spec §9, §14, §20, §35; addendum §3, §5, §17)
    path("admin/users/", admin_users.users, name="admin-users"),
    path("admin/users/new/", admin_users.create, name="admin-user-new"),
    path(USER, admin_users.detail, name="admin-user"),
    path(USER + "edit/", admin_users.edit, name="admin-user-edit"),
    path(USER + "disable/", admin_users.disable, name="admin-user-disable"),
    path(USER + "enable/", admin_users.enable, name="admin-user-enable"),
    path(USER + "unlock/", admin_users.unlock, name="admin-user-unlock"),
    path(USER + "reset/", admin_users.reset, name="admin-user-reset"),
    path(
        USER + "temporary-password/",
        admin_users.temporary_password,
        name="admin-user-temporary-password",
    ),
    path(USER + "admin-role/grant/", admin_users.grant_admin, name="admin-user-grant-admin"),
    path(USER + "admin-role/revoke/", admin_users.revoke_admin, name="admin-user-revoke-admin"),
    path(USER + "delete/", admin_users.delete, name="admin-user-delete"),
    path(USER + "yubikeys/add/", admin_yubikeys.add, name="admin-yubikey-add"),
    path(KEY + "edit/", admin_yubikeys.edit, name="admin-yubikey-edit"),
    path(KEY + "pin/", admin_yubikeys.pin, name="admin-yubikey-pin"),
    path(
        KEY + "enable/",
        admin_yubikeys.set_enabled,
        {"enabled": True},
        name="admin-yubikey-enable",
    ),
    path(
        KEY + "disable/",
        admin_yubikeys.set_enabled,
        {"enabled": False},
        name="admin-yubikey-disable",
    ),
    path(KEY + "remove/", admin_yubikeys.remove, name="admin-yubikey-remove"),
    path(KEY + "secrets/", admin_yubikeys.secrets, name="admin-yubikey-secrets"),
    path("admin/groups/", admin_groups.groups, name="admin-groups"),
    path("admin/groups/new/", admin_groups.create, name="admin-group-new"),
    path(GROUP, admin_groups.detail, name="admin-group"),
    path(GROUP + "edit/", admin_groups.edit, name="admin-group-edit"),
    path(GROUP + "delete/", admin_groups.delete, name="admin-group-delete"),
    path(GROUP + "members/add/", admin_groups.add_member, name="admin-group-member-add"),
    path(
        GROUP + "members/<uuid:user_id>/remove/",
        admin_groups.remove_member,
        name="admin-group-member-remove",
    ),
    path("admin/settings/", admin_settings.settings_page, name="admin-settings"),
    path("admin/audit/", admin_audit.events, name="admin-audit"),
    path("admin/audit/<uuid:event_id>/", admin_audit.event, name="admin-audit-event"),
]
