"""Development settings: a local SQLite database and a fixed, public secret key.

Never use these on a server. manage.py uses them by default; the installed
yk-portal command does not.
"""

from pathlib import Path

from .base import *  # noqa: F403

DEBUG = True
SECRET_KEY = "dev-only-not-secret"  # noqa: S105
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": Path.cwd() / "dev.sqlite3",
    },
}
