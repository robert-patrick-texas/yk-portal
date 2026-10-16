#!/usr/bin/env python
"""Development entry point: Django's management commands, with development settings."""

import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "yk_portal.settings.dev")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
