"""The admin audit log (spec §35 GET /admin/audit; addendum §17.3): newest first,
searched and filtered, and each event's page."""

import ipaddress
import uuid
from datetime import UTC, datetime, time, timedelta
from typing import Any

from django.core.paginator import Paginator
from django.db.models import Q, QuerySet, TextField
from django.db.models.functions import Cast
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render

from yk_portal.accounts.models import User
from yk_portal.authentication.access import admin_required
from yk_portal.authentication.sessions import PortalRequest

from .forms import EventFilterForm
from .models import AuditEvent

PAGE_SIZE = 50


@admin_required
def events(request: PortalRequest) -> HttpResponse:
    form = EventFilterForm(request.GET)
    found = AuditEvent.objects.all()
    # Not "account": every page's layout reads that as the signed-in account.
    filtered_account = None
    if form.is_valid():
        found = _filter(found, form.cleaned_data)
        if form.cleaned_data["user"]:
            filtered_account = _account(form.cleaned_data["user"])
    page = Paginator(found.order_by("-timestamp"), PAGE_SIZE).get_page(request.GET.get("page"))
    context = {"form": form, "page": page, "filtered_account": filtered_account}
    return render(request, "audit/admin/events.html", context)


@admin_required
def event(request: PortalRequest, event_id: uuid.UUID) -> HttpResponse:
    found = get_object_or_404(AuditEvent, pk=event_id)
    ids = {found.actor_user_id, found.target_user_id} - {None}
    existing = set(User.objects.filter(pk__in=ids).values_list("pk", flat=True))
    return render(request, "audit/admin/event.html", {"event": found, "existing": existing})


def _filter(found: QuerySet[AuditEvent], data: dict[str, Any]) -> QuerySet[AuditEvent]:
    if q := data["q"].strip():
        # details as text: public IDs, group and setting names, reasons.
        found = found.annotate(details_text=Cast("details", TextField()))
        match = (
            Q(actor_username_snapshot__icontains=q)
            | Q(target_username_snapshot__icontains=q)
            | Q(details_text__icontains=q)
        )
        try:
            match |= Q(source_ip=str(ipaddress.ip_address(q)))
        except ValueError:
            pass
        found = found.filter(match)
    if data["event_type"]:
        found = found.filter(event_type=data["event_type"])
    if data["result"]:
        found = found.filter(result=data["result"])
    # Dates are UTC days, as the pages show times.
    if data["since"]:
        found = found.filter(timestamp__gte=datetime.combine(data["since"], time(), UTC))
    if data["until"]:
        end = datetime.combine(data["until"], time(), UTC) + timedelta(days=1)
        found = found.filter(timestamp__lt=end)
    if data["user"]:
        found = found.filter(Q(actor_user_id=data["user"]) | Q(target_user_id=data["user"]))
    return found


def _account(user_id: uuid.UUID) -> dict[str, object]:
    """Who an account filter is for: its username now, or after a hard delete, the newest
    snapshot of it."""
    user = User.objects.filter(pk=user_id).first()
    if user is not None:
        return {"id": user_id, "username": user.username, "exists": True}
    latest = (
        AuditEvent.objects.filter(Q(actor_user_id=user_id) | Q(target_user_id=user_id))
        .order_by("-timestamp")
        .first()
    )
    username = ""
    if latest is not None:
        if latest.target_user_id == user_id:
            username = latest.target_username_snapshot
        else:
            username = latest.actor_username_snapshot
    return {"id": user_id, "username": username or str(user_id), "exists": False}
