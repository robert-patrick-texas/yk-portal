"""Development settings: a local SQLite database and a fixed, public secret key.

Never use these on a server. manage.py uses them by default; the installed
yk-portal command does not. Files are in the current directory: dev.sqlite3,
and dev-master.key (make it with: uv run yk-portal master-key-create dev-master.key).
"""

from pathlib import Path

from yk_portal.core.config import sqlite_database

from .base import *  # noqa: F403

DEBUG = True
SECRET_KEY = "dev-only-not-secret"  # noqa: S105
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]"]

DATABASES = {"default": sqlite_database(Path.cwd() / "dev.sqlite3")}
YK_MASTER_KEY_PATH = str(Path.cwd() / "dev-master.key")
