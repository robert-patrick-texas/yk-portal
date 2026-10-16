"""Onboarding pages for PROVISIONING accounts (spec §13): email, permanent password,
then the YubiKey step, which completes it."""

from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.shortcuts import redirect, render

from yk_portal.authentication.access import provisioning_required
from yk_portal.authentication.sessions import PortalRequest, request_actor
from yk_portal.yubikeys.forms import OtpForm, YubikeyForm
from yk_portal.yubikeys.otp import OtpRejected, Rejection

from . import services
from .forms import EmailForm, PasswordForm
from .models import User
from .onboarding import finish_with_new_yubikey, finish_with_otp, needs_new_yubikey


def _account(request: PortalRequest) -> User:
    assert request.account is not None  # noqa: S101 - the access decorators ensure it
    return request.account


@provisioning_required
def provision(request: PortalRequest) -> HttpResponse:
    account = _account(request)
    return render(
        request,
        "accounts/provision.html",
        {
            "email_done": bool(account.email),
            "password_done": bool(account.password_hash),
            "new_yubikey": needs_new_yubikey(account),
        },
    )


@provisioning_required
def provision_email(request: PortalRequest) -> HttpResponse:
    account = _account(request)
    form = EmailForm(
        request.POST if request.method == "POST" else None, initial={"email": account.email}
    )
    if form.is_valid():
        services.set_email(account, form.cleaned_data["email"], request_actor(request))
        return redirect("provision")
    return render(request, "accounts/provision_email.html", {"form": form})


@provisioning_required
def provision_password(request: PortalRequest) -> HttpResponse:
    form = PasswordForm(request.POST if request.method == "POST" else None)
    if form.is_valid():
        services.set_password(
            _account(request), form.cleaned_data["password"], request_actor(request)
        )
        return redirect("provision")
    return render(request, "accounts/provision_password.html", {"form": form})


@provisioning_required
def provision_yubikey(request: PortalRequest) -> HttpResponse:
    account = _account(request)
    try:
        services.check_ready_to_finish(account)
    except ValidationError:
        return redirect("provision")
    data = request.POST if request.method == "POST" else None
    if needs_new_yubikey(account):
        form = YubikeyForm(data)
        if form.is_valid():
            try:
                finish_with_new_yubikey(
                    account, form.new_yubikey(), form.cleaned_data["otp"], request_actor(request)
                )
            except ValidationError as e:
                form.add_service_error(e)
            else:
                return redirect("home")
    else:
        form = OtpForm(data)
        if form.is_valid():
            try:
                finish_with_otp(account, form.cleaned_data["otp"], request_actor(request))
            except OtpRejected as e:
                form.add_error("otp", otp_message(e.reason))
            else:
                return redirect("home")
    return render(request, "accounts/provision_yubikey.html", {"form": form})


def otp_message(reason: Rejection) -> str:
    """What a signed-in user is told when an OTP from their own YubiKey is refused."""
    if reason in (Rejection.UNKNOWN_KEY, Rejection.OTHER_USERS_KEY):
        return "That OTP doesn't come from one of your YubiKeys."
    if reason == Rejection.DISABLED_KEY:
        return "That YubiKey is disabled."
    if reason == Rejection.REPLAYED:
        return "That OTP was used before. Touch the YubiKey again."
    return "That OTP wasn't accepted. Touch the YubiKey again."
