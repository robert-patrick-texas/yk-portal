"""Load /etc/yk-portal/config.toml: the settings needed before the database is reachable.

Settings an admin changes at run time are stored in the database instead
(addendum §3). This file holds no secrets: the PostgreSQL password belongs in
a passfile named by the connection string, and the master key in its own file
(spec §22.4, §31). Unknown sections and keys are errors, so a misspelt key is
never silently ignored.
"""

import ipaddress
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

DEFAULT_PATH = Path("/etc/yk-portal/config.toml")
ENV_VAR = "YK_PORTAL_CONFIG"

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

type IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ConfigError(Exception):
    """The configuration file is missing, unreadable or invalid."""


@dataclass(frozen=True)
class ApplicationConfig:
    listen_address: str
    listen_port: int
    public_base_url: str

    @property
    def public_host(self) -> str:
        """The host name users browse to, for ALLOWED_HOSTS."""
        return urlsplit(self.public_base_url).hostname or ""

    @property
    def public_origin(self) -> str:
        """scheme://host[:port], for CSRF_TRUSTED_ORIGINS."""
        url = urlsplit(self.public_base_url)
        return f"{url.scheme}://{url.netloc}"


@dataclass(frozen=True)
class DatabaseConfig:
    backend: Literal["sqlite", "postgresql"]
    sqlite_path: Path
    # The connection string split into libpq keywords; empty for SQLite.
    postgres_params: dict[str, str]


@dataclass(frozen=True)
class Config:
    path: Path
    application: ApplicationConfig
    database: DatabaseConfig
    master_key_path: Path
    trusted_proxy_addresses: tuple[IPNetwork, ...]
    log_level: str


_REQUIRED: Any = object()


class _Section:
    """One [table] of the file. Each value read is removed; finish() reports the rest."""

    def __init__(self, path: Path, name: str, data: object) -> None:
        if not isinstance(data, dict):
            raise ConfigError(f"{path}: [{name}] must be a table")
        self.path = path
        self.name = name
        self.data: dict[str, object] = dict(data)

    def error(self, key: str, problem: str) -> ConfigError:
        return ConfigError(f"{self.path}: [{self.name}] {key}: {problem}")

    def _take(self, key: str, default: object) -> object:
        if key in self.data:
            return self.data.pop(key)
        if default is _REQUIRED:
            raise self.error(key, "required")
        return default

    def get_str(self, key: str, default: str = _REQUIRED) -> str:
        value = self._take(key, default)
        if not isinstance(value, str) or not value:
            raise self.error(key, "must be a non-empty string")
        return value

    def get_optional_str(self, key: str) -> str | None:
        return self.get_str(key) if key in self.data else None

    def get_int(self, key: str, default: int = _REQUIRED) -> int:
        value = self._take(key, default)
        if not isinstance(value, int) or isinstance(value, bool):
            raise self.error(key, "must be a whole number")
        return value

    def get_str_list(self, key: str, default: list[str] = _REQUIRED) -> list[str]:
        value = self._take(key, default)
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            raise self.error(key, "must be a list of non-empty strings")
        return value

    def get_absolute_path(self, key: str, default: str = _REQUIRED) -> Path:
        path = Path(self.get_str(key, default))
        if not path.is_absolute():
            raise self.error(key, "must be an absolute path")
        return path

    def finish(self) -> None:
        if self.data:
            names = ", ".join(sorted(self.data))
            raise ConfigError(f"{self.path}: [{self.name}] unknown key(s): {names}")


def load_config(path: Path | None = None) -> Config:
    """Read and check the configuration file.

    The path is, in order: the argument, $YK_PORTAL_CONFIG, /etc/yk-portal/config.toml.
    """
    if path is None:
        path = Path(os.environ.get(ENV_VAR) or DEFAULT_PATH)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"{path}: not found (see config.example.toml)") from None
    except PermissionError:
        raise ConfigError(f"{path}: permission denied") from None
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"{path}: not valid TOML: {e}") from None

    sections = {"application", "database", "security", "proxy", "logging"}
    unknown = sorted(set(data) - sections)
    if unknown:
        raise ConfigError(f"{path}: unknown section(s): {', '.join(unknown)}")

    def section(name: str) -> _Section:
        return _Section(path, name, data.get(name, {}))

    app = section("application")
    application = ApplicationConfig(
        listen_address=_ip_address(app, "listen_address", "127.0.0.1"),
        listen_port=_port(app, "listen_port", 8000),
        public_base_url=_public_base_url(app, "public_base_url"),
    )
    app.finish()

    db = section("database")
    database = _database(db)
    db.finish()

    security = section("security")
    master_key_path = security.get_absolute_path("master_key_path", "/etc/yk-portal/master.key")
    security.finish()

    proxy = section("proxy")
    trusted = _networks(proxy, "trusted_proxy_addresses", ["127.0.0.1", "::1"])
    proxy.finish()

    log = section("logging")
    level = log.get_str("level", "INFO").upper()
    if level not in LOG_LEVELS:
        raise log.error("level", f"must be one of {', '.join(LOG_LEVELS)}")
    log.finish()

    return Config(
        path=path,
        application=application,
        database=database,
        master_key_path=master_key_path,
        trusted_proxy_addresses=trusted,
        log_level=level,
    )


def _ip_address(section: _Section, key: str, default: str) -> str:
    value = section.get_str(key, default)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise section.error(key, "must be an IPv4 or IPv6 address") from None


def _port(section: _Section, key: str, default: int) -> int:
    value = section.get_int(key, default)
    if not 1 <= value <= 65535:
        raise section.error(key, "must be between 1 and 65535")
    return value


def _public_base_url(section: _Section, key: str) -> str:
    value = section.get_str(key)
    try:
        url = urlsplit(value)
        _ = url.port  # raises ValueError for an invalid port
    except ValueError:
        raise section.error(key, "is not a valid URL") from None
    if url.scheme != "https" or not url.hostname:
        raise section.error(key, "must be an https:// URL with a host name")
    if url.path not in ("", "/") or url.query or url.fragment or url.username:
        raise section.error(key, "must be https://HOST or https://HOST:PORT, with nothing after")
    return f"https://{url.netloc}"


def _database(section: _Section) -> DatabaseConfig:
    backend = section.get_str("backend", "sqlite")
    sqlite_path = section.get_absolute_path("sqlite_path", "/var/lib/yk-portal/yk-portal.sqlite3")
    dsn = section.get_optional_str("postgres_dsn")
    if backend == "sqlite":
        return DatabaseConfig("sqlite", sqlite_path, {})
    if backend != "postgresql":
        raise section.error("backend", "must be sqlite or postgresql")
    if dsn is None:
        raise section.error("postgres_dsn", "required when backend is postgresql")
    return DatabaseConfig("postgresql", sqlite_path, _postgres_params(section, dsn))


def _postgres_params(section: _Section, dsn: str) -> dict[str, str]:
    # psycopg loads libpq on import: import it only when PostgreSQL is used.
    import psycopg
    from psycopg.conninfo import conninfo_to_dict

    try:
        params = {k: str(v) for k, v in conninfo_to_dict(dsn).items()}
    except psycopg.ProgrammingError as e:
        raise section.error("postgres_dsn", f"not a valid connection string: {e}") from None
    if "password" in params:
        raise section.error(
            "postgres_dsn", "must not contain a password; put it in a passfile (passfile=PATH)"
        )
    if "dbname" not in params and "service" not in params:
        raise section.error("postgres_dsn", "must name the database (dbname=...) or a service")
    return params


def _networks(section: _Section, key: str, default: list[str]) -> tuple[IPNetwork, ...]:
    networks = []
    for value in section.get_str_list(key, default):
        try:
            networks.append(ipaddress.ip_network(value))
        except ValueError:
            raise section.error(key, f"{value!r} is not an IP address or network") from None
    return tuple(networks)


def django_database(database: DatabaseConfig) -> dict[str, Any]:
    """The DATABASES["default"] entry for this configuration."""
    if database.backend == "sqlite":
        return sqlite_database(database.sqlite_path)
    return postgresql_database(database.postgres_params)


def postgresql_database(params: dict[str, str]) -> dict[str, Any]:
    """A DATABASES entry for PostgreSQL, from libpq keywords (spec §30; addendum §18).

    Each worker keeps its connection for a minute, checked before reuse, so a request
    doesn't pay for a new connection and its TLS handshake: no pool is needed at this
    scale. application_name shows yk-portal's connections in pg_stat_activity, unless
    the connection string names them otherwise.
    """
    params = {"application_name": "yk-portal"} | params
    return {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": params.pop("dbname", ""),
        "USER": params.pop("user", ""),
        "HOST": params.pop("host", ""),
        "PORT": params.pop("port", ""),
        "CONN_MAX_AGE": 60,
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": params,
    }


def sqlite_database(path: Path) -> dict[str, Any]:
    """A DATABASES entry for a SQLite file (spec §30).

    Django turns on foreign keys itself. WAL lets the web pages read while a
    login writes; synchronous=FULL makes every committed OTP counter survive a
    power cut, so an OTP can't be replayed afterwards (spec §17). IMMEDIATE
    transactions take the write lock at BEGIN, so concurrent logins queue
    rather than fail.
    """
    return {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": path,
        "OPTIONS": {
            "transaction_mode": "IMMEDIATE",
            "timeout": 5,
            "init_command": "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        },
    }
