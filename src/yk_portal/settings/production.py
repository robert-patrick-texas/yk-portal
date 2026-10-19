"""Production settings, built from /etc/yk-portal/config.toml and the master key.

Django's secret key is derived from the master key (spec §22.5), so the
application doesn't start without a readable master key. $YK_PORTAL_CONFIG
names another configuration file.
"""

from urllib.parse import urlsplit

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

_application = YK_CONFIG.application
ALLOWED_HOSTS = [_application.public_host]
CSRF_TRUSTED_ORIGINS = [_application.public_origin]
DATABASES = {"default": django_database(YK_CONFIG.database)}
YK_MASTER_KEY_PATH = str(YK_CONFIG.master_key_path)
YK_TRUSTED_PROXIES = YK_CONFIG.trusted_proxy_addresses

# Published under a path (public_base_url https://HOST/PATH), the reverse proxy
# strips the path and the application puts it back in its links, and its
# cookies go only to that path. STATIC_URL is given whole: Django adds the
# path to a relative one only when first read, and that is before any request.
FORCE_SCRIPT_NAME = _application.public_path or None
CSRF_COOKIE_PATH = _application.public_path + "/"
STATIC_URL = _application.public_path + "/static/"

# TLS ends at the reverse proxy (spec §32), which sets X-Forwarded-Proto.
# ForwardedHeadersMiddleware drops it from any other address. Plain HTTP is
# redirected to the public address: only a client that bypasses the proxy
# sees it. On a host name of its own, browsers keep to HTTPS for a year
# (HSTS), on that name and the names under it, not its siblings; under a path,
# the policy would be the whole site's, so it is the site's to set.
# Preloading is for a whole registered domain: the enterprise's choice.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = True
SECURE_SSL_HOST = urlsplit(_application.public_base_url).netloc
SECURE_HSTS_SECONDS = 0 if _application.public_path else 365 * 24 * 3600
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = False
SILENCED_SYSTEM_CHECKS = ["security.W021"]  # HSTS preload, above

# The application's log goes to standard error, which systemd sends to the
# journal. Audit events go to the journal on their own, as yk-portal-audit,
# whatever the configured level and whoever runs the command (spec §40;
# addendum §17.6).
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    # The journal adds the time and the process.
    "formatters": {"plain": {"format": "%(levelname)s %(name)s: %(message)s"}},
    "handlers": {
        "stderr": {"class": "logging.StreamHandler", "formatter": "plain"},
        "journal": {"()": "yk_portal.audit.journal.journal_handler"},
    },
    "root": {"handlers": ["stderr"], "level": YK_CONFIG.log_level},
    "loggers": {
        "yk_portal.audit": {"handlers": ["journal"], "level": "INFO", "propagate": False},
    },
}
