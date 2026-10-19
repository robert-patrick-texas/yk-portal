"""yk-portal serve: the application server, behind the reverse proxy (spec §3, §32).

gunicorn, configured from /etc/yk-portal/config.toml: it listens on
listen_address and listen_port, where only the reverse proxy should reach it,
with the configured number of worker processes. The application is loaded
before the workers start, so a missing master key or a bad setting stops the
server at once, with the reason, instead of failing in every worker. It tells
systemd when it is ready (deploy/yk-portal.service).
"""

import importlib.metadata
import logging
import os
import sys
from collections.abc import Callable
from typing import Any

from gunicorn.app.base import BaseApplication

from .core.config import Config, ConfigError, load_config

logger = logging.getLogger("yk_portal.server")

USAGE = (
    "usage: yk-portal serve\n"
    "Runs the application server, as configured in /etc/yk-portal/config.toml\n"
    "(or $YK_PORTAL_CONFIG), until it is stopped. systemd runs it as yk-portal.service."
)


def serve(args: list[str]) -> int:
    """yk-portal serve: run the application server until it is stopped."""
    if args[:1] in (["-h"], ["--help"]):
        print(USAGE)
        return 0
    if args:
        print(USAGE, file=sys.stderr)
        return 2
    try:
        config = load_config()
    except ConfigError as e:
        print(f"yk-portal: {e}", file=sys.stderr)
        return 1
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "yk_portal.settings.production")
    Server(config).run()  # exits when the server stops
    return 0


def options(config: Config) -> dict[str, Any]:
    """gunicorn's settings for this configuration."""
    application = config.application
    return {
        "bind": [application.bind],
        "workers": application.workers,
        "preload_app": True,
        # The reverse proxy logs requests, with the clients' addresses.
        "accesslog": None,
        "errorlog": "-",
        "loglevel": config.log_level.lower(),
        "forwarded_allow_ips": ",".join(str(n) for n in config.trusted_proxy_addresses),
        # Only X-Forwarded-Proto says HTTPS, as Django reads it. No header may set
        # SCRIPT_NAME or PATH_INFO: a client could otherwise choose the path the
        # application sees, past the proxy's rules, through a proxy that passes
        # headers with "_" in their names. The path comes from public_base_url.
        "secure_scheme_headers": {"X-FORWARDED-PROTO": "https"},
        "forwarder_headers": "",
        "proc_name": "yk-portal",
        # In memory: on disk, the workers' heartbeat can stall (gunicorn's advice).
        "worker_tmp_dir": "/dev/shm",  # noqa: S108 - gunicorn makes them with mkstemp
        "umask": 0o077,
        # gunicorn's run-time control socket (gunicornc) isn't needed: systemd manages it.
        "control_socket_disable": True,
    }


class Server(BaseApplication):
    """gunicorn with yk-portal's settings and WSGI application."""

    def __init__(self, config: Config) -> None:
        self.config = config
        super().__init__(usage=USAGE, prog="yk-portal serve")

    def load_config(self) -> None:
        assert self.cfg is not None  # noqa: S101 - set by BaseApplication first
        for key, value in options(self.config).items():
            self.cfg.set(key, value)

    def load(self) -> Callable[..., Any]:
        from django.core.exceptions import ImproperlyConfigured

        try:
            from django.core.wsgi import get_wsgi_application

            application = get_wsgi_application()
        except ImproperlyConfigured as e:
            # gunicorn shows a RuntimeError's message and exits with status 1.
            raise RuntimeError(f"yk-portal: {e}") from None
        _starting(self.config)
        return application


def _starting(config: Config) -> None:
    """Log what is starting, and anything that would keep it from serving requests
    (spec §40). A problem doesn't stop it: the database may come up later, and
    /health/ready tells monitoring until it does."""
    from django.db import connections

    from .web.health import readiness

    logger.info(
        "yk-portal %s starting at %s, with the %s database",
        importlib.metadata.version("yk-portal"),
        config.application.public_base_url,
        config.database.backend,
    )
    for problem in readiness():
        logger.warning("not ready: %s", problem)
    # The workers are forked from this process: each must open its own connection.
    connections.close_all()
