"""A signed-in user's YubiKeys (spec §20): list, add, test, edit, disable, remove."""

import uuid

from django.core.exceptions import ValidationError
from django.http import HttpResponse, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404, redirect, render

from yk_portal.accounts.models import User
from yk_portal.accounts.views import otp_message
from yk_portal.authentication.access import active_required
from yk_portal.authentication.sessions import PortalRequest, request_actor

from . import management
from .forms import OtpForm, YubikeyEditForm, YubikeyForm
from .models import ProvisioningMethod, YubikeyCredential
from .otp import OtpRejected


def _account(request: PortalRequest) -> User:
    assert request.account is not None  # noqa: S101 - the access decorators ensure it
    return request.account


def _own(request: PortalRequest, credential_id: uuid.UUID) -> YubikeyCredential:
    """One of the signed-in user's YubiKeys; any other ID is not found."""
    return get_object_or_404(YubikeyCredential, pk=credential_id, user=_account(request))


def _list(request: PortalRequest, error: str = "") -> HttpResponse:
    credentials = YubikeyCredential.objects.filter(user=_account(request)).order_by("created_at")
    return render(
        request,
        "yubikeys/list.html",
        {
            "credentials": credentials,
            "error": error,
            "can_add": len(credentials) < request.portal_settings.max_yubikeys_per_user,
        },
    )


@active_required
def yubikeys(request: PortalRequest) -> HttpResponse:
    return _list(request)


@active_required
def add(request: PortalRequest) -> HttpResponse:
    form = YubikeyForm(request.POST if request.method == "POST" else None)
    if form.is_valid():
        try:
            management.add_yubikey(
                _account(request),
                request_actor(request),
                form.new_yubikey(),
                ProvisioningMethod.SELF_PROVISIONED,
                form.cleaned_data["otp"],
            )
        except ValidationError as e:
            form.add_service_error(e)
        else:
            return redirect("yubikeys")
    return render(request, "yubikeys/add.html", {"form": form})


@active_required
def test(request: PortalRequest) -> HttpResponse:
    form = OtpForm(request.POST if request.method == "POST" else None)
    tested = None
    if form.is_valid():
        try:
            tested = management.check_yubikey(_account(request), form.cleaned_data["otp"])
        except OtpRejected as e:
            form.add_error("otp", otp_message(e.reason))
        else:
            form = OtpForm()
    return render(request, "yubikeys/test.html", {"form": form, "tested": tested})


@active_required
def edit(request: PortalRequest, credential_id: uuid.UUID) -> HttpResponse:
    credential = _own(request, credential_id)
    form = YubikeyEditForm(
        request.POST if request.method == "POST" else None,
        initial={"label": credential.label, "slot": credential.slot_number},
    )
    if form.is_valid():
        management.update_yubikey(
            credential,
            request_actor(request),
            form.cleaned_data["label"],
            form.cleaned_data["slot"],
        )
        return redirect("yubikeys")
    return render(request, "yubikeys/edit.html", {"form": form, "credential": credential})


@active_required
def set_enabled(request: PortalRequest, credential_id: uuid.UUID, enabled: bool) -> HttpResponse:
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    try:
        management.set_yubikey_enabled(
            _own(request, credential_id), request_actor(request), enabled
        )
    except ValidationError as e:
        return _list(request, error=e.messages[0])
    return redirect("yubikeys")


@active_required
def remove(request: PortalRequest, credential_id: uuid.UUID) -> HttpResponse:
    credential = _own(request, credential_id)
    error = ""
    if request.method == "POST":
        try:
            management.remove_yubikey(credential, request_actor(request))
        except ValidationError as e:
            error = e.messages[0]
        else:
            return redirect("yubikeys")
    return render(request, "yubikeys/remove.html", {"credential": credential, "error": error})
