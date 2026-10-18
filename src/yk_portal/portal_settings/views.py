"""The admin settings page (addendum §3)."""

import dataclasses

from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse

from yk_portal.authentication.access import admin_required
from yk_portal.authentication.sessions import PortalRequest, request_actor

from . import service
from .forms import SettingsForm


@admin_required
def settings_page(request: PortalRequest) -> HttpResponse:
    initial = dataclasses.asdict(request.portal_settings)
    initial["default_group"] = str(initial["default_group"] or "")
    form = SettingsForm(request.POST if request.method == "POST" else None, initial=initial)
    if form.is_valid():
        try:
            service.update(form.cleaned_data, request_actor(request))
        except ValidationError as e:
            for key, messages in e.message_dict.items():
                form.add_error(key, ValidationError(messages))
        else:
            return redirect(reverse("admin-settings") + "?saved=1")
    return render(
        request,
        "portal_settings/settings.html",
        {"form": form, "saved": request.method == "GET" and "saved" in request.GET},
    )
