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

# TLS ends at the reverse proxy (spec §32), which sets X-Forwarded-Proto. The
# application listens only where the proxy reaches it (listen_address), so no
# one else can set that header.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Standard error goes to the systemd journal. Separate audit logging comes
# with the audit service (spec §40).
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"stderr": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["stderr"], "level": YK_CONFIG.log_level},
}
