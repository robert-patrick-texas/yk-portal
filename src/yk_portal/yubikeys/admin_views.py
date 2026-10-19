"""Admin pages for any account's YubiKeys (spec §14, §20, §34): pre-provision, edit, set
the PIN, disable, remove, reveal the secrets.

Admins may disable or remove an ACTIVE account's last enabled YubiKey (addendum §14.3),
and set a PIN without an OTP (addendum §2.16).
"""

import uuid

from django.core.exceptions import ValidationError
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404, redirect, render

from yk_portal.accounts.models import AccountState, User
from yk_portal.authentication.access import admin_required
from yk_portal.authentication.login import LoginFailed, confirm_identity
from yk_portal.authentication.sessions import PortalRequest, request_actor

from . import management
from .forms import AdminPinForm, AdminYubikeyForm, StepUpForm, YubikeyEditForm
from .models import ProvisioningMethod, YubikeyCredential

# How long a revealed secret stays on the page (spec §34).
REVEAL_SECONDS = 60
STEP_UP_FAILED = (
    "Your PIN and OTP weren’t accepted. Type the PIN of one of your YubiKeys, then touch it."
)


def _credential(user_id: uuid.UUID, credential_id: uuid.UUID) -> YubikeyCredential:
    """One of the account's YubiKeys; a YubiKey of another account is not found."""
    return get_object_or_404(
        YubikeyCredential.objects.select_related("user"), pk=credential_id, user_id=user_id
    )


def _back(credential: YubikeyCredential) -> HttpResponse:
    return redirect("admin-user", credential.user.pk)


@admin_required
def add(request: PortalRequest, user_id: uuid.UUID) -> HttpResponse:
    """Pre-provision a YubiKey (spec §14): no proof of possession, no PIN."""
    user = get_object_or_404(User, pk=user_id)
    form = AdminYubikeyForm(request.POST if request.method == "POST" else None)
    if form.is_valid():
        try:
            management.add_yubikey(
                user,
                request_actor(request),
                form.new_yubikey(),
                ProvisioningMethod.ADMIN_PROVISIONED,
                form.cleaned_data["otp"] or None,
            )
        except ValidationError as e:
            form.add_service_error(e)
        else:
            return redirect("admin-user", user.pk)
    return render(request, "yubikeys/admin/add.html", {"form": form, "user": user})


@admin_required
def edit(request: PortalRequest, user_id: uuid.UUID, credential_id: uuid.UUID) -> HttpResponse:
    credential = _credential(user_id, credential_id)
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
        return _back(credential)
    return render(request, "yubikeys/admin/edit.html", {"form": form, "credential": credential})


@admin_required
def pin(request: PortalRequest, user_id: uuid.UUID, credential_id: uuid.UUID) -> HttpResponse:
    """Set a YubiKey's PIN without an OTP (addendum §2.16). The owner's sessions end."""
    credential = _credential(user_id, credential_id)
    form = AdminPinForm(
        request.POST if request.method == "POST" else None, owner=credential.user.username
    )
    if form.is_valid():
        try:
            management.admin_set_pin(
                credential,
                request_actor(request),
                form.cleaned_data["pin"],
                form.cleaned_data["everywhere"],
                keep=request.portal_session,
            )
        except ValidationError as e:
            form.add_error("pin", e)
        else:
            return _back(credential)
    return render(request, "yubikeys/admin/pin.html", {"form": form, "credential": credential})


@admin_required
def set_enabled(
    request: PortalRequest, user_id: uuid.UUID, credential_id: uuid.UUID, enabled: bool
) -> HttpResponse:
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    credential = _credential(user_id, credential_id)
    management.set_yubikey_enabled(credential, request_actor(request), enabled, allow_last=True)
    return _back(credential)


@admin_required
def remove(request: PortalRequest, user_id: uuid.UUID, credential_id: uuid.UUID) -> HttpResponse:
    """Remove a YubiKey. The page reminds the admin that Radiator keeps it (addendum §6.6,
    §14.5)."""
    credential = _credential(user_id, credential_id)
    if request.method == "POST":
        management.remove_yubikey(credential, request_actor(request), allow_last=True)
        return _back(credential)
    last = (
        credential.user.state == AccountState.ACTIVE
        and credential.enabled
        and not YubikeyCredential.objects.filter(user_id=user_id, enabled=True)
        .exclude(pk=credential.pk)
        .exists()
    )
    return render(request, "yubikeys/admin/remove.html", {"credential": credential, "last": last})


@admin_required
def secrets(request: PortalRequest, user_id: uuid.UUID, credential_id: uuid.UUID) -> HttpResponse:
    """Reveal the private ID or AES key (spec §20.2, §34), after the admin's PIN and OTP
    again if the setting asks for it (addendum §3.2). Each reveal is audited; the value is
    shown only in the response to the POST, which isn't cached, and the page hides it
    after REVEAL_SECONDS."""
    credential = _credential(user_id, credential_id)
    step_up = request.portal_settings.step_up_before_reveal
    form = StepUpForm(request.POST if request.method == "POST" and step_up else None)
    revealed: dict[str, str] = {}
    error = ""
    if request.method == "POST":
        which = request.POST.get("secret", "")
        if which not in ("private_id", "aes_key", "both"):
            return HttpResponseBadRequest()
        confirmed = not step_up
        actor = request_actor(request)
        if step_up and form.is_valid():
            admin = request.account
            assert admin is not None  # noqa: S101 - admin_required ensures it
            try:
                confirm_identity(actor, form.cleaned_data["passcode"])
            except LoginFailed:
                admin.refresh_from_db()
                if admin.state != AccountState.ACTIVE:
                    return redirect("login")  # the failure locked the account: sessions ended
                error = STEP_UP_FAILED
            else:
                confirmed = True
            form = StepUpForm()  # the passcode is never sent back
        if confirmed:
            if which in ("private_id", "both"):
                revealed["private_id"] = management.reveal_private_id(
                    credential, actor, step_up=step_up
                )
            if which in ("aes_key", "both"):
                revealed["aes_key"] = management.reveal_aes_key(credential, actor, step_up=step_up)
    return render(
        request,
        "yubikeys/admin/secrets.html",
        {
            "credential": credential,
            "step_up": step_up,
            "form": form,
            "error": error,
            "revealed": revealed,
            "reveal_seconds": REVEAL_SECONDS,
        },
    )
