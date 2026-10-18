"""Which signed-in accounts may open a page.

A PROVISIONING account's session is restricted to onboarding (spec §13.1):
every other page sends it there, and the onboarding pages send ACTIVE
accounts home.
"""

import functools
from collections.abc import Callable

from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.shortcuts import redirect
from django.views.decorators.cache import never_cache

from yk_portal.accounts.models import AccountState

from .sessions import PortalRequest

type View = Callable[..., HttpResponse]


def active_required(view: View) -> View:
    """Only for ACTIVE accounts."""

    @functools.wraps(view)
    def check(request: PortalRequest, *args: object, **kwargs: object) -> HttpResponse:
        if request.account is None:
            return redirect("login")
        if request.account.state != AccountState.ACTIVE:
            return redirect("provision")
        return view(request, *args, **kwargs)

    return check


def admin_required(view: View) -> View:
    """Only for ACTIVE accounts with the admin role (spec §6), read at each request so a
    role taken away applies at once (spec §19). Other accounts get 403.

    Admin pages can show temporary passwords and YubiKey secrets: browsers and proxies
    may not keep them (spec §33).
    """

    @functools.wraps(view)
    @never_cache
    def check(request: PortalRequest, *args: object, **kwargs: object) -> HttpResponse:
        if request.account is None:
            return redirect("login")
        if request.account.state != AccountState.ACTIVE:
            return redirect("provision")
        if not request.account.is_admin:
            raise PermissionDenied
        return view(request, *args, **kwargs)

    return check


def provisioning_required(view: View) -> View:
    """Only for PROVISIONING accounts: onboarding."""

    @functools.wraps(view)
    def check(request: PortalRequest, *args: object, **kwargs: object) -> HttpResponse:
        if request.account is None:
            return redirect("login")
        if request.account.state != AccountState.PROVISIONING:
            return redirect("home")
        return view(request, *args, **kwargs)

    return check
