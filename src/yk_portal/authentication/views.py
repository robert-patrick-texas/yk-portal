from django.http import HttpResponse, HttpResponseNotAllowed
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods

from .forms import LoginForm
from .login import LoginFailed, log_in
from .sessions import (
    COOKIE,
    Client,
    PortalRequest,
    end_session,
    request_actor,
    set_session_cookie,
)


@require_http_methods(["GET", "POST"])
def login(request: PortalRequest) -> HttpResponse:
    """The sign-in page (spec §16). Every failure shows the same message."""
    if request.account is not None:
        return redirect("home")
    form = LoginForm(request.POST if request.method == "POST" else None)
    error = ""
    if form.is_valid():
        try:
            _, token = log_in(
                form.cleaned_data["username"], form.cleaned_data["passcode"], Client.of(request)
            )
        except LoginFailed as e:
            error = str(e)
        else:
            response = redirect("home")
            set_session_cookie(response, token)
            return response
    return render(request, "authentication/login.html", {"form": form, "error": error})


def logout(request: PortalRequest) -> HttpResponse:
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    if request.portal_session is not None:
        end_session(request.portal_session, request_actor(request))
    response = redirect("login")
    response.delete_cookie(COOKIE, samesite="Strict")
    return response
