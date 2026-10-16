"""Test settings: an in-memory SQLite database, or PostgreSQL.

YK_PORTAL_TEST_DATABASE=postgresql runs the same tests against PostgreSQL
(spec §44.6, §48), connecting with the usual libpq defaults and environment
(PGHOST, PGUSER, ...). The test database, test_yk_portal, is created and
dropped by the test run.
"""

import os

from .base import *  # noqa: F403

SECRET_KEY = "test-only-not-secret"  # noqa: S105

if os.environ.get("YK_PORTAL_TEST_DATABASE") == "postgresql":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": "yk_portal",
        },
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
        },
    }
