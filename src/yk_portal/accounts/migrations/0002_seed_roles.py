"""The two roles of spec §6: user (every account) and admin (added on top)."""

import uuid

from django.db import migrations

ROLES = ("user", "admin")


def create_roles(apps, schema_editor):
    Role = apps.get_model("accounts", "Role")
    for name in ROLES:
        Role.objects.get_or_create(name=name, defaults={"id": uuid.uuid4()})


def delete_roles(apps, schema_editor):
    apps.get_model("accounts", "Role").objects.filter(name__in=ROLES).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(create_roles, delete_roles),
    ]
