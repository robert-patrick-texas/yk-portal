"""Test settings: an in-memory SQLite database.

The PostgreSQL test run (spec §44.6, §48) is added with the PostgreSQL backend.
"""

from .base import *  # noqa: F403

SECRET_KEY = "test-only-not-secret"  # noqa: S105

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
}
