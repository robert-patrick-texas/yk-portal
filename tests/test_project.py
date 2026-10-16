import importlib

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command


def test_system_checks_pass():
    call_command("check", fail_level="WARNING")


def test_production_settings_refuse_to_load_until_configured():
    with pytest.raises(ImproperlyConfigured, match="no production configuration"):
        importlib.import_module("yk_portal.settings.production")
