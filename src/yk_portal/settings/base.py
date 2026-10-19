"""Settings shared by every environment.

Values an admin changes at run time (timeouts, portal name, default group) are
stored in the database, not here (addendum §3). Values needed before the
database is reachable come from /etc/yk-portal/config.toml (addendum §3.5),
read by the production settings.
"""

import ipaddress
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent.parent

INSTALLED_APPS = [
    "django.contrib.staticfiles",
    "yk_portal.core",
    "yk_portal.accounts",
    "yk_portal.authentication",
    "yk_portal.yubikeys",
    "yk_portal.audit",
    "yk_portal.portal_settings",
    "yk_portal.radiator",
    "yk_portal.backup",
    "yk_portal.web",
]

MIDDLEWARE = [
    # Before the host name is checked (spec §41).
    "yk_portal.web.middleware.HealthCheckMiddleware",
    "yk_portal.web.middleware.ForwardedHeadersMiddleware",
    "yk_portal.web.middleware.SecurityHeadersMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "yk_portal.authentication.sessions.SessionMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "yk_portal.urls"
WSGI_APPLICATION = "yk_portal.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.template.context_processors.csrf",
                "yk_portal.web.context_processors.portal",
            ],
        },
    },
]

# Web logins use Argon2id (addendum §2.2). The SHA-512 crypt hash for Radiator
# is made separately, by yk_portal.core.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.Argon2PasswordHasher"]

# Models declare UUID primary keys explicitly (addendum §13).
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LANGUAGE_CODE = "en-us"
USE_I18N = False
TIME_ZONE = "UTC"
USE_TZ = True

# Static files are served by the application (WhiteNoise) from the installed package,
# so the reverse proxy only proxies and no collectstatic step is needed. Browsers may
# keep them for a minute, so a new version's styles show soon after an upgrade.
STATIC_URL = "static/"
WHITENOISE_USE_FINDERS = True
WHITENOISE_AUTOREFRESH = False
WHITENOISE_ALLOW_ALL_ORIGINS = False

# Request size limits (spec §33): the largest form, the settings page, is a few KiB.
# No form takes files.
DATA_UPLOAD_MAX_MEMORY_SIZE = 256 * 1024
DATA_UPLOAD_MAX_NUMBER_FILES = 0

# The master key file (spec §22.4); production takes it from the configuration.
YK_MASTER_KEY_PATH = "/etc/yk-portal/master.key"

# Proxies whose X-Forwarded-For is believed, for the client address in sessions
# and the audit log; production takes them from the configuration.
YK_TRUSTED_PROXIES = (ipaddress.ip_network("127.0.0.1/32"), ipaddress.ip_network("::1/128"))

# Not Django's usual name: under a path of a site, another application's
# csrftoken cookie would be sent too, and could be the one read.
CSRF_COOKIE_NAME = "yk_csrftoken"
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_SECURE = True
CSRF_FAILURE_VIEW = "yk_portal.web.views.csrf_failure"
X_FRAME_OPTIONS = "DENY"
