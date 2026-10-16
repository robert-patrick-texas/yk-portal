"""WSGI entry point for the application server, with production settings."""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "yk_portal.settings.production")

application = get_wsgi_application()
