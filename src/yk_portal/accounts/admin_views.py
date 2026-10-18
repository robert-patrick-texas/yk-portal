"""Admin pages for accounts (spec §9, §10, §15, §26): list and search, create, view,
edit, change state, roles, temporary passwords, hard delete.

A refused change shows its reason on the account's page; nothing changes.
"""

import uuid
from collections.abc import Callable

from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Exists, OuterRef, Q, QuerySet
from django.http import HttpResponse, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404, redirect, render

from yk_portal.audit.service import Actor
from yk_portal.authentication.access import admin_required
from yk_portal.authentication.sessions import PortalRequest, request_actor
from yk_portal.yubikeys.models import YubikeyCredential

from . import groups, services
from .forms import ConfirmUsernameForm, UserCreateForm, UserEditForm, UserFilterForm
from .models import AccountState, Group, Role, User, UserRole
from .onboarding import needs_new_yubikey

PAGE_SIZE = 50


def _with_roles(users: QuerySet[User]) -> QuerySet[User]:
    """USERS, each with has_admin_role, without a query per user."""
    admin = UserRole.objects.filter(user=OuterRef("pk"), role__name=Role.ADMIN)
    return users.annotate(has_admin_role=Exists(admin))


@admin_required
def users(request: PortalRequest) -> HttpResponse:
    form = UserFilterForm(request.GET)
    found = _with_roles(User.objects.all())
    if form.is_valid():
        data = form.cleaned_data
        if data["q"]:
            found = found.filter(
                Q(username__icontains=data["q"])
                | Q(display_name__icontains=data["q"])
                | Q(email__icontains=data["q"])
            )
        if data["state"]:
            found = found.filter(state=data["state"])
        if data["role"]:
            found = found.filter(has_admin_role=data["role"] == "admin")
        if data["group"]:
            found = found.filter(user_groups__group=data["group"])
    found = (
        found.annotate(yubikey_count=Count("yubikeys", distinct=True))
        .prefetch_related("groups")
        .order_by("username")
    )
    page = Paginator(found, PAGE_SIZE).get_page(request.GET.get("page"))
    return render(request, "accounts/admin/users.html", {"form": form, "page": page})


@admin_required
def create(request: PortalRequest) -> HttpResponse:
    default = request.portal_settings.default_group
    form = UserCreateForm(
        request.POST if request.method == "POST" else None,
        initial={"groups": Group.objects.filter(pk=default)},
    )
    if form.is_valid():
        data = form.cleaned_data
        try:
            account = services.create_user(
                data["username"],
                request_actor(request),
                email=data["email"],
                admin=data["admin"],
                groups=data["groups"],
                display_name=data["display_name"],
                comment=data["comment"],
            )
        except ValidationError as e:
            form.add_error(_field_of(e), e)
        else:
            return _temporary_password(
                request, account.user, account.temporary_password, "Account created"
            )
    return render(request, "accounts/admin/user_new.html", {"form": form})


def _field_of(error: ValidationError) -> str:
    """The field of the create and edit forms that an error from the services concerns."""
    code = error.error_list[0].code or ""
    if code == "invalid":  # Django's email validator
        return "email"
    return next((f for f in ("display_name", "comment") if code.startswith(f)), "username")


def _temporary_password(
    request: PortalRequest, user: User, temporary_password: str, heading: str
) -> HttpResponse:
    """The page that shows a temporary password, the one time it is shown (spec §11)."""
    return render(
        request,
        "accounts/admin/temporary_password.html",
        {
            "user": user,
            "temporary_password": temporary_password,
            "heading": heading,
            "new_yubikey": needs_new_yubikey(user),
        },
    )


def _user(user_id: uuid.UUID) -> User:
    return get_object_or_404(User, pk=user_id)


def _detail(request: PortalRequest, user: User, error: str = "") -> HttpResponse:
    credentials = YubikeyCredential.objects.filter(user=user).order_by("created_at")
    return render(
        request,
        "accounts/admin/user.html",
        {
            "user": user,
            "is_admin": user.is_admin,
            "user_groups": user.groups.order_by("name"),
            "credentials": credentials,
            "can_add": len(credentials) < request.portal_settings.max_yubikeys_per_user,
            "error": error,
        },
    )


@admin_required
def detail(request: PortalRequest, user_id: uuid.UUID) -> HttpResponse:
    return _detail(request, _user(user_id))


@admin_required
def edit(request: PortalRequest, user_id: uuid.UUID) -> HttpResponse:
    user = _user(user_id)
    current_groups = set(user.groups.all())
    form = UserEditForm(
        request.POST if request.method == "POST" else None,
        initial={
            "username": user.username,
            "email": user.email,
            "display_name": user.display_name,
            "comment": user.comment,
            "groups": current_groups,
        },
    )
    if form.is_valid():
        data = form.cleaned_data
        actor = request_actor(request)
        try:
            with transaction.atomic():
                services.change_username(user, data["username"], actor)
                services.update_account(
                    user,
                    actor,
                    email=data["email"],
                    display_name=data["display_name"],
                    comment=data["comment"],
                )
                for group in set(data["groups"]) - current_groups:
                    groups.add_member(group, user, actor)
                for group in current_groups - set(data["groups"]):
                    groups.remove_member(group, user, actor)
        except ValidationError as e:
            user.refresh_from_db()
            form.add_error(_field_of(e), e)
        else:
            return redirect("admin-user", user.pk)
    return render(request, "accounts/admin/user_edit.html", {"form": form, "user": user})


def _action(change: Callable[[User, Actor], None]) -> Callable[..., HttpResponse]:
    """A POST that changes an account's state or roles, then shows its page again."""

    @admin_required
    def view(request: PortalRequest, user_id: uuid.UUID) -> HttpResponse:
        if request.method != "POST":
            return HttpResponseNotAllowed(["POST"])
        user = _user(user_id)
        try:
            change(user, request_actor(request))
        except ValidationError as e:
            return _detail(request, user, error=e.messages[0])
        if user == request.account and not (user.state == AccountState.ACTIVE and user.is_admin):
            return redirect("home")  # admins who disabled themselves or gave up the role
        return redirect("admin-user", user.pk)

    return view


disable = _action(services.disable)
enable = _action(services.enable)
unlock = _action(services.unlock)
grant_admin = _action(services.grant_admin)
revoke_admin = _action(services.revoke_admin)


@admin_required
def reset(request: PortalRequest, user_id: uuid.UUID) -> HttpResponse:
    """Reset to provisioning (spec §15), after a confirmation."""
    user = _user(user_id)
    if request.method == "POST":
        try:
            temporary_password = services.reset_to_provisioning(user, request_actor(request))
        except ValidationError as e:
            return _detail(request, user, error=e.messages[0])
        return _temporary_password(request, user, temporary_password, "Reset to provisioning")
    enabled = YubikeyCredential.objects.filter(user=user, enabled=True).count()
    return render(request, "accounts/admin/reset.html", {"user": user, "enabled": enabled})


@admin_required
def temporary_password(request: PortalRequest, user_id: uuid.UUID) -> HttpResponse:
    """A new temporary password for a PROVISIONING account (spec §11)."""
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    user = _user(user_id)
    try:
        temporary = services.set_temporary_password(user, request_actor(request))
    except ValidationError as e:
        return _detail(request, user, error=e.messages[0])
    return _temporary_password(request, user, temporary, "New temporary password")


@admin_required
def delete(request: PortalRequest, user_id: uuid.UUID) -> HttpResponse:
    """Hard delete (spec §26), confirmed by entering the username. The page reminds the admin
    that Radiator keeps the account's YubiKeys (addendum §6.6)."""
    user = _user(user_id)
    form = ConfirmUsernameForm(
        request.POST if request.method == "POST" else None, expected=user.username
    )
    error = ""
    if form.is_valid():
        username = user.username
        try:
            services.delete_user(user, request_actor(request))
        except ValidationError as e:
            error = e.messages[0]
        else:
            return render(request, "accounts/admin/deleted.html", {"username": username})
    public_ids = YubikeyCredential.objects.filter(user=user).values_list("public_id", flat=True)
    return render(
        request,
        "accounts/admin/delete.html",
        {
            "user": user,
            "form": form,
            "error": error,
            "public_ids": sorted(public_ids),
            "is_self": user == request.account,
        },
    )
