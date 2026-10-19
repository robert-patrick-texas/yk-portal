import ipaddress
from pathlib import Path

import pytest
from django.db.utils import ConnectionHandler

from yk_portal.core.config import (
    ConfigError,
    django_database,
    load_config,
    sqlite_database,
)

MINIMAL = """
[application]
public_base_url = "https://yk.example.com"
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text)
    return path


def load(tmp_path: Path, text: str):
    return load_config(write(tmp_path, text))


def test_minimal_file_gets_defaults(tmp_path):
    config = load(tmp_path, MINIMAL)
    assert config.application.listen_address == "127.0.0.1"
    assert config.application.listen_port == 8000
    assert config.application.public_base_url == "https://yk.example.com"
    assert config.database.backend == "sqlite"
    assert config.database.sqlite_path == Path("/var/lib/yk-portal/yk-portal.sqlite3")
    assert config.master_key_path == Path("/etc/yk-portal/master.key")
    assert config.trusted_proxy_addresses == (
        ipaddress.ip_network("127.0.0.1/32"),
        ipaddress.ip_network("::1/128"),
    )
    assert config.log_level == "INFO"


def test_full_sqlite_file(tmp_path):
    config = load(
        tmp_path,
        """
        [application]
        listen_address = "::1"
        listen_port = 8443
        public_base_url = "https://yk.example.com:8443/"

        [database]
        backend = "sqlite"
        sqlite_path = "/srv/yk/db.sqlite3"

        [security]
        master_key_path = "/srv/yk/master.key"

        [proxy]
        trusted_proxy_addresses = ["10.0.0.0/24", "2001:db8::1"]

        [logging]
        level = "warning"
        """,
    )
    assert config.application.listen_address == "::1"
    assert config.application.public_base_url == "https://yk.example.com:8443"
    assert config.application.public_host == "yk.example.com"
    assert config.application.public_origin == "https://yk.example.com:8443"
    assert config.database.sqlite_path == Path("/srv/yk/db.sqlite3")
    assert config.master_key_path == Path("/srv/yk/master.key")
    assert config.trusted_proxy_addresses[0] == ipaddress.ip_network("10.0.0.0/24")
    assert config.log_level == "WARNING"


def test_postgresql_connection_string_maps_to_django(tmp_path):
    dsn = (
        "host=db.example.com port=5433 dbname=yk_portal user=yk"
        " sslmode=verify-full passfile=/etc/yk-portal/pgpass"
    )
    config = load(
        tmp_path, MINIMAL + f'[database]\nbackend = "postgresql"\npostgres_dsn = "{dsn}"\n'
    )
    assert django_database(config.database) == {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "yk_portal",
        "USER": "yk",
        "HOST": "db.example.com",
        "PORT": "5433",
        "CONN_MAX_AGE": 60,
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": {
            "application_name": "yk-portal",
            "sslmode": "verify-full",
            "passfile": "/etc/yk-portal/pgpass",
        },
    }


def test_postgresql_connection_string_may_name_the_application(tmp_path):
    dsn = "dbname=yk_portal application_name=portal-2"
    config = load(
        tmp_path, MINIMAL + f'[database]\nbackend = "postgresql"\npostgres_dsn = "{dsn}"\n'
    )
    assert django_database(config.database)["OPTIONS"] == {"application_name": "portal-2"}


@pytest.mark.parametrize(
    ("dsn", "message"),
    [
        ("dbname=yk password=secret", "must not contain a password"),
        ("host=db.example.com user=yk", "must name the database"),
        ("dbname='unterminated", "not a valid connection string"),
    ],
)
def test_bad_postgresql_connection_strings(tmp_path, dsn, message):
    text = MINIMAL + f'[database]\nbackend = "postgresql"\npostgres_dsn = "{dsn}"\n'
    with pytest.raises(ConfigError, match=message):
        load(tmp_path, text)


def test_postgresql_needs_a_connection_string(tmp_path):
    with pytest.raises(ConfigError, match="postgres_dsn: required"):
        load(tmp_path, MINIMAL + '[database]\nbackend = "postgresql"\n')


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", r"\[application\] public_base_url: required"),
        ("[application]\npublic_base_url = 'http://yk.example.com'", "must be an https:// URL"),
        ("[application]\npublic_base_url = 'https://yk.example.com/portal'", "nothing after"),
        ("[application]\npublic_base_url = 'https://yk.example.com:99999'", "not a valid URL"),
        (MINIMAL + "listen_address = 'localhost'", "must be an IPv4 or IPv6 address"),
        (MINIMAL + "listen_port = 0", "between 1 and 65535"),
        (MINIMAL + "listen_port = true", "must be a whole number"),
        (MINIMAL + "listen_port = '8000'", "must be a whole number"),
        (MINIMAL + "colour = 'blue'", r"\[application\] unknown key\(s\): colour"),
        (MINIMAL + "[extra]\nx = 1", r"unknown section\(s\): extra"),
        (MINIMAL + "[database]\nbackend = 'mysql'", "must be sqlite or postgresql"),
        (MINIMAL + "[database]\nsqlite_path = 'yk.sqlite3'", "must be an absolute path"),
        (MINIMAL + "[proxy]\ntrusted_proxy_addresses = ['10.0.0.1/8']", "not an IP address"),
        (MINIMAL + "[proxy]\ntrusted_proxy_addresses = '10.0.0.1'", "must be a list"),
        (MINIMAL + "[logging]\nlevel = 'LOUD'", "must be one of"),
        (MINIMAL + "[security]\nmaster_key_path = ''", "must be a non-empty string"),
        ("database = 'sqlite'\n" + MINIMAL, r"\[database\] must be a table"),
        ("[application\n", "not valid TOML"),
    ],
)
def test_invalid_files(tmp_path, text, message):
    with pytest.raises(ConfigError, match=message):
        load(tmp_path, text)


def test_missing_file_names_the_path(tmp_path):
    path = tmp_path / "absent.toml"
    with pytest.raises(ConfigError, match=f"{path}: not found"):
        load_config(path)


def test_path_from_environment(tmp_path, monkeypatch):
    path = write(tmp_path, MINIMAL)
    monkeypatch.setenv("YK_PORTAL_CONFIG", str(path))
    assert load_config().path == path


def test_sqlite_connections_use_wal_and_full_sync(tmp_path, django_db_blocker):
    handler = ConnectionHandler({"default": sqlite_database(tmp_path / "test.sqlite3")})
    connection = handler["default"]
    with django_db_blocker.unblock():
        with connection.cursor() as cursor:
            assert cursor.execute("PRAGMA journal_mode").fetchone() == ("wal",)
            assert cursor.execute("PRAGMA synchronous").fetchone() == (2,)  # FULL
            assert cursor.execute("PRAGMA foreign_keys").fetchone() == (1,)
        connection.close()
