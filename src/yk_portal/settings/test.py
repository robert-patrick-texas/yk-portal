"""Test settings: SQLite, or PostgreSQL, with the production database settings.

YK_PORTAL_TEST_DATABASE=postgresql runs the same tests against PostgreSQL
(spec §44.6, §48), connecting with the usual libpq defaults and environment
(PGHOST, PGUSER, ...). The test database, test_yk_portal, is created and
dropped by the test run.

SQLite's test database is a file in the temporary directory, not memory, so
threads share it as the application's workers share theirs, and it runs with
the production options (WAL, IMMEDIATE transactions).
"""

import os
import tempfile
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

from yk_portal.core.config import postgresql_database, sqlite_database

from .base import *  # noqa: F403

SECRET_KEY = "test-only-not-secret"  # noqa: S105

match os.environ.get("YK_PORTAL_TEST_DATABASE", "sqlite"):
    case "sqlite":
        _path = Path(tempfile.gettempdir()) / f"yk-portal-test-{os.getpid()}.sqlite3"
        DATABASES = {"default": sqlite_database(_path) | {"TEST": {"NAME": _path}}}
    case "postgresql":
        DATABASES = {"default": postgresql_database({"dbname": "yk_portal"})}
    case other:
        raise ImproperlyConfigured(f"YK_PORTAL_TEST_DATABASE={other}: use sqlite or postgresql")
