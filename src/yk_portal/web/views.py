from django.http import HttpResponse, HttpResponseNotAllowed
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme

from yk_portal.accounts.models import Theme
from yk_portal.authentication.access import active_required, provisioning_required
from yk_portal.authentication.sessions import PortalRequest

from .context_processors import THEME_COOKIE


@active_required
def home(request: PortalRequest) -> HttpResponse:
    return render(request, "web/home.html")


@provisioning_required
def welcome(request: PortalRequest) -> HttpResponse:
    """Where a PROVISIONING account lands. Onboarding comes in spec Phase 5."""
    return render(request, "web/welcome.html")


def set_theme(request: PortalRequest) -> HttpResponse:
    """Save a theme choice: to the signed-in user's account, and to this browser for the
    sign-in page (addendum §4.3)."""
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    theme = request.POST.get("theme", "")
    target = request.POST.get("next", "")
    if not url_has_allowed_host_and_scheme(
        target, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        target = "/"
    response = redirect(target)
    if theme in Theme.values:
        if request.account is not None:
            request.account.theme = theme
            request.account.save(update_fields=["theme", "updated_at"])
        response.set_cookie(
            THEME_COOKIE, theme, max_age=365 * 24 * 3600, secure=True, httponly=True, samesite="Lax"
        )
    return response
