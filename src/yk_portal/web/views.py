from django.http import HttpRequest, HttpResponse, HttpResponseNotAllowed
from django.shortcuts import redirect, render
from django.urls import get_script_prefix, reverse
from django.utils.http import url_has_allowed_host_and_scheme

from yk_portal.accounts.models import Theme
from yk_portal.authentication.access import active_required
from yk_portal.authentication.sessions import PortalRequest

from .context_processors import THEME_COOKIE


@active_required
def home(request: PortalRequest) -> HttpResponse:
    return render(request, "web/home.html")


def csrf_failure(request: HttpRequest, reason: str = "") -> HttpResponse:
    """A form refused for its CSRF token (spec §33): an old page, a cookie that has gone,
    or a form from another site. Django logs the reason."""
    return render(request, "web/csrf_failure.html", status=403)


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
        target = reverse("home")
    response = redirect(target)
    if theme in Theme.values:
        if request.account is not None:
            request.account.theme = theme
            request.account.save(update_fields=["theme", "updated_at"])
        response.set_cookie(
            THEME_COOKIE,
            theme,
            max_age=365 * 24 * 3600,
            path=get_script_prefix(),
            secure=True,
            httponly=True,
            samesite="Lax",
        )
    return response
