"""Production settings, built from /etc/yk-portal/config.toml and the master key.

Django's secret key is derived from the master key (spec §22.5), so the
application doesn't start without a readable master key. $YK_PORTAL_CONFIG
names another configuration file.
"""

from django.core.exceptions import ImproperlyConfigured

from yk_portal.core.config import ConfigError, django_database, load_config
from yk_portal.core.master_key import MasterKeyError, derive_keys, load_master_key

from .base import *  # noqa: F403

try:
    YK_CONFIG = load_config()
    _keys = derive_keys(load_master_key(YK_CONFIG.master_key_path))
except (ConfigError, MasterKeyError) as e:
    raise ImproperlyConfigured(str(e)) from None

DEBUG = False
SECRET_KEY = _keys.django_secret_key
del _keys

ALLOWED_HOSTS = [YK_CONFIG.application.public_host]
CSRF_TRUSTED_ORIGINS = [YK_CONFIG.application.public_origin]
DATABASES = {"default": django_database(YK_CONFIG.database)}
YK_MASTER_KEY_PATH = str(YK_CONFIG.master_key_path)
YK_TRUSTED_PROXIES = YK_CONFIG.trusted_proxy_addresses

# TLS ends at the reverse proxy (spec §32), which sets X-Forwarded-Proto. The
# application listens only where the proxy reaches it (listen_address), so no
# one else can set that header.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# The application's log goes to standard error, which systemd sends to the
# journal. Audit events go to the journal on their own, as yk-portal-audit,
# whatever the configured level and whoever runs the command (spec §40;
# addendum §17.6).
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "stderr": {"class": "logging.StreamHandler"},
        "journal": {"()": "yk_portal.audit.journal.journal_handler"},
    },
    "root": {"handlers": ["stderr"], "level": YK_CONFIG.log_level},
    "loggers": {
        "yk_portal.audit": {"handlers": ["journal"], "level": "INFO", "propagate": False},
    },
}
