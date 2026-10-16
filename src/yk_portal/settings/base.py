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
    "django.middleware.security.SecurityMiddleware",
    "yk_portal.web.middleware.ContentSecurityPolicyMiddleware",
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

STATIC_URL = "static/"

# The master key file (spec §22.4); production takes it from the configuration.
YK_MASTER_KEY_PATH = "/etc/yk-portal/master.key"

# Proxies whose X-Forwarded-For is believed, for the client address in sessions
# and the audit log; production takes them from the configuration.
YK_TRUSTED_PROXIES = (ipaddress.ip_network("127.0.0.1/32"), ipaddress.ip_network("::1/128"))

CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_SECURE = True
X_FRAME_OPTIONS = "DENY"
