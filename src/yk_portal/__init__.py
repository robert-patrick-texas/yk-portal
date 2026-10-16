"""yk-portal: a web portal to manage user accounts and YubiKey OTP credentials."""

import os
import sys


def main() -> None:
    """Run the yk-portal command: Django's management commands, with production settings."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "yk_portal.settings.production")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
