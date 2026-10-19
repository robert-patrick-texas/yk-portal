import importlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command

from yk_portal.core.config import load_config
from yk_portal.core.master_key import create_master_key, derive_keys, load_master_key

REPO = Path(__file__).resolve().parent.parent


def test_system_checks_pass():
    call_command("check", fail_level="WARNING")


@pytest.mark.django_db
def test_migrations_match_the_models():
    call_command("makemigrations", check=True, dry_run=True, verbosity=0)


def test_example_configuration_is_valid():
    config = load_config(REPO / "config.example.toml")
    assert config.database.backend == "sqlite"


@dataclass
class Production:
    key: Path

    def load(self) -> ModuleType:
        """Import the production settings module afresh."""
        try:
            return importlib.import_module("yk_portal.settings.production")
        finally:
            sys.modules.pop("yk_portal.settings.production", None)


@pytest.fixture
def production(tmp_path, monkeypatch) -> Production:
    """The production settings, with a configuration and master key path in tmp_path."""
    key = tmp_path / "master.key"
    config = tmp_path / "config.toml"
    config.write_text(
        '[application]\npublic_base_url = "https://yk.example.com:8443"\n'
        f'[database]\nsqlite_path = "{tmp_path}/db.sqlite3"\n'
        f'[security]\nmaster_key_path = "{key}"\n'
    )
    monkeypatch.setenv("YK_PORTAL_CONFIG", str(config))
    monkeypatch.delitem(sys.modules, "yk_portal.settings.production", raising=False)
    return Production(key)


def test_production_settings_from_configuration(production):
    create_master_key(production.key)
    settings = production.load()
    assert settings.DEBUG is False
    assert settings.SECRET_KEY == derive_keys(load_master_key(production.key)).django_secret_key
    assert settings.ALLOWED_HOSTS == ["yk.example.com"]
    assert settings.CSRF_TRUSTED_ORIGINS == ["https://yk.example.com:8443"]
    assert settings.DATABASES["default"]["NAME"] == production.key.parent / "db.sqlite3"
    assert settings.YK_MASTER_KEY_PATH == str(production.key)
    assert not hasattr(settings, "_keys")


def test_production_settings_need_the_master_key(production):
    with pytest.raises(ImproperlyConfigured, match="yk-portal master-key-create"):
        production.load()


def test_production_settings_need_a_configuration(production, monkeypatch, tmp_path):
    monkeypatch.setenv("YK_PORTAL_CONFIG", str(tmp_path / "absent.toml"))
    with pytest.raises(ImproperlyConfigured, match="absent.toml: not found"):
        production.load()


def test_production_sends_audit_events_to_the_journal_at_any_level(production):
    """Audit events are kept apart from the application's log, and not filtered by its
    level (spec §40; addendum §17.6)."""
    create_master_key(production.key)
    config = Path(os.environ["YK_PORTAL_CONFIG"])
    config.write_text(config.read_text() + '[logging]\nlevel = "ERROR"\n')
    logging = production.load().LOGGING
    assert logging["root"]["level"] == "ERROR"
    assert logging["loggers"]["yk_portal.audit"] == {
        "handlers": ["journal"],
        "level": "INFO",
        "propagate": False,
    }
    assert logging["handlers"]["journal"] == {"()": "yk_portal.audit.journal.journal_handler"}
