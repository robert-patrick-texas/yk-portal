"""Admin pages for groups (addendum §5): list, create, rename and describe, members,
delete."""

import uuid

from django.core.exceptions import ValidationError
from django.db.models import Count
from django.http import HttpResponse, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404, redirect, render

from yk_portal.authentication.access import admin_required
from yk_portal.authentication.sessions import PortalRequest, request_actor

from . import groups as service
from .forms import AddMemberForm, GroupForm
from .models import Group, User, UserGroup
from .services import normalize_username


@admin_required
def groups(request: PortalRequest) -> HttpResponse:
    found = Group.objects.annotate(member_count=Count("user_groups")).order_by("name")
    return render(
        request,
        "accounts/admin/groups.html",
        {"groups": found, "default_group": request.portal_settings.default_group},
    )


@admin_required
def create(request: PortalRequest) -> HttpResponse:
    form = GroupForm(request.POST if request.method == "POST" else None)
    if form.is_valid():
        try:
            group = service.create_group(
                form.cleaned_data["name"],
                request_actor(request),
                form.cleaned_data["description"],
            )
        except ValidationError as e:
            form.add_error("name", e)
        else:
            return redirect("admin-group", group.pk)
    return render(request, "accounts/admin/group_form.html", {"form": form, "group": None})


def _group(group_id: uuid.UUID) -> Group:
    return get_object_or_404(Group, pk=group_id)


def _detail(
    request: PortalRequest, group: Group, form: AddMemberForm | None = None
) -> HttpResponse:
    return render(
        request,
        "accounts/admin/group.html",
        {
            "group": group,
            "members": User.objects.filter(user_groups__group=group).order_by("username"),
            "is_default": request.portal_settings.default_group == group.pk,
            "form": form or AddMemberForm(),
        },
    )


@admin_required
def detail(request: PortalRequest, group_id: uuid.UUID) -> HttpResponse:
    return _detail(request, _group(group_id))


@admin_required
def edit(request: PortalRequest, group_id: uuid.UUID) -> HttpResponse:
    group = _group(group_id)
    form = GroupForm(
        request.POST if request.method == "POST" else None,
        initial={"name": group.name, "description": group.description},
    )
    if form.is_valid():
        try:
            service.update_group(
                group,
                request_actor(request),
                form.cleaned_data["name"],
                form.cleaned_data["description"],
            )
        except ValidationError as e:
            form.add_error("name", e)
        else:
            return redirect("admin-group", group.pk)
    return render(request, "accounts/admin/group_form.html", {"form": form, "group": group})


@admin_required
def delete(request: PortalRequest, group_id: uuid.UUID) -> HttpResponse:
    """Delete a group and its memberships, after a confirmation that shows how many members
    it has (addendum §5.5)."""
    group = _group(group_id)
    error = ""
    if request.method == "POST":
        try:
            service.delete_group(group, request_actor(request))
        except ValidationError as e:
            error = e.messages[0]
        else:
            return redirect("admin-groups")
    return render(
        request,
        "accounts/admin/group_delete.html",
        {
            "group": group,
            "member_count": UserGroup.objects.filter(group=group).count(),
            "is_default": request.portal_settings.default_group == group.pk,
            "error": error,
        },
    )


@admin_required
def add_member(request: PortalRequest, group_id: uuid.UUID) -> HttpResponse:
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    group = _group(group_id)
    form = AddMemberForm(request.POST)
    if form.is_valid():
        username = normalize_username(form.cleaned_data["username"])
        user = User.objects.filter(username=username).first()
        if user is None:
            form.add_error("username", "No account has that username.")
        else:
            service.add_member(group, user, request_actor(request))
            return redirect("admin-group", group.pk)
    return _detail(request, group, form=form)


@admin_required
def remove_member(request: PortalRequest, group_id: uuid.UUID, user_id: uuid.UUID) -> HttpResponse:
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    group = _group(group_id)
    service.remove_member(group, get_object_or_404(User, pk=user_id), request_actor(request))
    return redirect("admin-group", group.pk)
