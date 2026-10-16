"""Which signed-in accounts may open a page.

A PROVISIONING account's session is restricted to onboarding (spec §13.1):
every other page sends it there, and the onboarding pages send ACTIVE
accounts home.
"""

import functools
from collections.abc import Callable

from django.http import HttpResponse
from django.shortcuts import redirect

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
