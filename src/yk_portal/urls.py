from django.urls import URLPattern, URLResolver, path

from yk_portal.accounts import views as accounts
from yk_portal.authentication import views as authentication
from yk_portal.web import views as web
from yk_portal.yubikeys import views as yubikeys

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
]
