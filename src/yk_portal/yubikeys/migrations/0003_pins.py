from django.db import migrations, models


def copy_passwords_to_pins(apps, schema_editor):
    """Each YubiKey takes its account's password as its PIN (addendum §2.2)."""
    User = apps.get_model("accounts", "User")
    YubikeyCredential = apps.get_model("yubikeys", "YubikeyCredential")
    for user in User.objects.exclude(password_hash="", radius_password_hash=""):
        YubikeyCredential.objects.filter(user=user).update(
            pin_hash=user.password_hash, radius_pin_hash=user.radius_password_hash
        )


def copy_pins_to_passwords(apps, schema_editor):
    """Back: each account takes the PIN of its YubiKey used last."""
    User = apps.get_model("accounts", "User")
    YubikeyCredential = apps.get_model("yubikeys", "YubikeyCredential")
    for user in User.objects.all():
        key = (
            YubikeyCredential.objects.filter(user=user)
            .exclude(pin_hash="", radius_pin_hash="")
            .order_by(models.F("last_used_at").desc(nulls_last=True))
            .first()
        )
        if key is not None:
            user.password_hash, user.radius_password_hash = key.pin_hash, key.radius_pin_hash
            user.save(update_fields=["password_hash", "radius_password_hash"])


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0004_user_theme_unset"),
        ("yubikeys", "0002_private_id_digest"),
    ]

    operations = [
        migrations.AddField(
            model_name="yubikeycredential",
            name="pin_hash",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="yubikeycredential",
            name="radius_pin_hash",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="yubikeycredential",
            name="failed_login_count",
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.RunPython(copy_passwords_to_pins, copy_pins_to_passwords),
    ]
