"""Accounts, roles and groups (spec §6, §7, §23, §25.1-§25.3; addendum §5, §12)."""

import uuid
from typing import ClassVar

from django.db import models
from django.db.models.functions import Lower

from .validators import validate_group_name, validate_username


class AccountState(models.TextChoices):
    PROVISIONING = "PROVISIONING"
    ACTIVE = "ACTIVE"
    LOCKED = "LOCKED"
    DISABLED = "DISABLED"


class Theme(models.TextChoices):
    BROWSER = "browser"
    LIGHT = "light"
    DARK = "dark"


class Role(models.Model):
    """user (every account) or admin (added on top, spec §6)."""

    USER = "user"
    ADMIN = "admin"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=32, unique=True)

    objects: ClassVar[models.Manager[Role]] = models.Manager["Role"]()

    class Meta:
        db_table = "roles"

    def __str__(self) -> str:
        return self.name


class User(models.Model):
    # Immutable; every reference to a user uses it, never the username (spec §23).
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=255, unique=True, validators=[validate_username])
    email = models.EmailField(blank=True, default="")
    # Argon2id, for web logins. Empty for an account imported from Radiator
    # until its first web login (addendum §2.8).
    password_hash = models.CharField(max_length=255, blank=True, default="")
    # {crypt}$6$... SHA-512 crypt, for the export to radiator-yubikey (addendum §2.2).
    radius_password_hash = models.CharField(max_length=255, blank=True, default="")
    temporary_password_hash = models.CharField(max_length=255, blank=True, default="")
    temporary_password_expires_at = models.DateTimeField(null=True, blank=True)
    state = models.CharField(
        max_length=16, choices=AccountState.choices, default=AccountState.PROVISIONING
    )
    failed_login_count = models.PositiveSmallIntegerField(default=0)
    theme = models.CharField(max_length=8, choices=Theme.choices, default=Theme.BROWSER)
    roles = models.ManyToManyField(Role, through="UserRole", related_name="users")
    groups = models.ManyToManyField("Group", through="UserGroup", related_name="users")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_at = models.DateTimeField(null=True, blank=True)

    objects: ClassVar[models.Manager[User]] = models.Manager["User"]()

    class Meta:
        db_table = "users"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(username=Lower("username")), name="users_username_lowercase"
            ),
            models.CheckConstraint(
                condition=models.Q(state__in=AccountState.values), name="users_state_valid"
            ),
            models.CheckConstraint(
                condition=models.Q(theme__in=Theme.values), name="users_theme_valid"
            ),
        ]

    def __str__(self) -> str:
        return self.username

    @property
    def is_admin(self) -> bool:
        return UserRole.objects.filter(user=self, role__name=Role.ADMIN).exists()


class UserRole(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_roles")
    role = models.ForeignKey(Role, on_delete=models.PROTECT, related_name="user_roles")

    objects: ClassVar[models.Manager[UserRole]] = models.Manager["UserRole"]()

    class Meta:
        db_table = "user_roles"
        constraints = [
            models.UniqueConstraint(fields=["user", "role"], name="user_roles_user_role_unique"),
        ]

    def __str__(self) -> str:
        return f"{self.user} has {self.role}"


class Group(models.Model):
    """An admin-defined group. Grants nothing inside yk-portal (addendum §5.6)."""

    # Immutable, so a rename changes only the name (addendum §5.2).
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=64, validators=[validate_group_name])
    description = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects: ClassVar[models.Manager[Group]] = models.Manager["Group"]()

    class Meta:
        db_table = "groups"
        constraints = [
            models.UniqueConstraint(Lower("name"), name="groups_name_unique_any_case"),
        ]

    def __str__(self) -> str:
        return self.name


class UserGroup(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_groups")
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="user_groups")

    objects: ClassVar[models.Manager[UserGroup]] = models.Manager["UserGroup"]()

    class Meta:
        db_table = "user_groups"
        constraints = [
            models.UniqueConstraint(fields=["user", "group"], name="user_groups_user_group_unique"),
        ]

    def __str__(self) -> str:
        return f"{self.user} in {self.group}"
