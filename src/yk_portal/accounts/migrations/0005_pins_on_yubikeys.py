from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0004_user_theme_unset"),
        # Copies the passwords to the YubiKeys' PINs first.
        ("yubikeys", "0003_pins"),
    ]

    operations = [
        migrations.RemoveField(model_name="user", name="password_hash"),
        migrations.RemoveField(model_name="user", name="radius_password_hash"),
    ]
