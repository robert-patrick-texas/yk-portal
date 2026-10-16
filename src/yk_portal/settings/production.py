"""Production settings, built from /etc/yk-portal/config.toml and the master key.

They arrive with the configuration loader (spec §47, Phase 1). Until then this
module refuses to load, so the installed yk-portal command can never run with
development settings by accident.
"""

from django.core.exceptions import ImproperlyConfigured

raise ImproperlyConfigured(
    "yk-portal has no production configuration yet (spec Phase 1). "
    "For development, use manage.py or set DJANGO_SETTINGS_MODULE=yk_portal.settings.dev."
)
