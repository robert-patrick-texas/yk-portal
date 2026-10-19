"""LOGIN_THROTTLED, and an index on the address for the per-address limit (addendum §20.4).

Changing only the choices doesn't touch the table: SQLite doesn't rebuild it, so the
immutability triggers of migration 0004 stay (tests/test_migrations.py checks them).
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("audit", "0005_details_unicode"),
    ]

    operations = [
        migrations.AlterField(
            model_name="auditevent",
            name="event_type",
            field=models.CharField(
                choices=[
                    ("LOGIN_SUCCESS", "Login Success"),
                    ("LOGIN_FAILURE", "Login Failure"),
                    ("LOGIN_LOCKED", "Login Locked"),
                    ("LOGIN_THROTTLED", "Login Throttled"),
                    ("LOGOUT", "Logout"),
                    ("ACCESS_DENIED", "Access Denied"),
                    ("ACCOUNT_CREATED", "Account Created"),
                    ("ACCOUNT_UPDATED", "Account Updated"),
                    ("ACCOUNT_DISABLED", "Account Disabled"),
                    ("ACCOUNT_ENABLED", "Account Enabled"),
                    ("ACCOUNT_LOCKED", "Account Locked"),
                    ("ACCOUNT_UNLOCKED", "Account Unlocked"),
                    ("ACCOUNT_RESET_TO_PROVISIONING", "Account Reset To Provisioning"),
                    ("PROVISIONING_COMPLETED", "Provisioning Completed"),
                    ("ACCOUNT_DELETED", "Account Deleted"),
                    ("USERNAME_CHANGED", "Username Changed"),
                    ("PASSWORD_CHANGED", "Password Changed"),
                    ("TEMPORARY_PASSWORD_SET", "Temporary Password Set"),
                    ("ADMIN_ROLE_GRANTED", "Admin Role Granted"),
                    ("ADMIN_ROLE_REVOKED", "Admin Role Revoked"),
                    ("YUBIKEY_ADDED", "Yubikey Added"),
                    ("YUBIKEY_UPDATED", "Yubikey Updated"),
                    ("YUBIKEY_DISABLED", "Yubikey Disabled"),
                    ("YUBIKEY_ENABLED", "Yubikey Enabled"),
                    ("YUBIKEY_REMOVED", "Yubikey Removed"),
                    ("YUBIKEY_PRIVATE_ID_REVEALED", "Yubikey Private Id Revealed"),
                    ("YUBIKEY_AES_SECRET_REVEALED", "Yubikey Aes Secret Revealed"),
                    ("BACKUP_CREATED", "Backup Created"),
                    ("BACKUP_RESTORED", "Backup Restored"),
                    ("MASTER_KEY_ROTATED", "Master Key Rotated"),
                    ("ADMIN_BOOTSTRAPPED", "Admin Bootstrapped"),
                    ("SETTING_CHANGED", "Setting Changed"),
                    ("GROUP_CREATED", "Group Created"),
                    ("GROUP_UPDATED", "Group Updated"),
                    ("GROUP_DELETED", "Group Deleted"),
                    ("GROUP_MEMBER_ADDED", "Group Member Added"),
                    ("GROUP_MEMBER_REMOVED", "Group Member Removed"),
                    ("RADIATOR_EXPORT_CREATED", "Radiator Export Created"),
                    ("RADIATOR_IMPORT_COMPLETED", "Radiator Import Completed"),
                ],
                max_length=64,
            ),
        ),
        migrations.AddIndex(
            model_name="auditevent",
            index=models.Index(fields=["source_ip", "timestamp"], name="audit_events_source_ip"),
        ),
    ]
