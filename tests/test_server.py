"""yk-portal serve and the production settings (spec §32, §33, §49; addendum §20).

These run the installed yk-portal command in its own process, with a
configuration file and master key of their own and a SQLite database, as
systemd would run it.
"""

import json
import os
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from yk_portal.core.config import load_config
from yk_portal.core.master_key import create_master_key
from yk_portal.server import options

COMMAND = str(Path(sys.executable).with_name("yk-portal"))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def config(tmp_path):
    """write(public_base_url=..., extra=...): a configuration file, and its environment."""

    def write(public_base_url: str = "https://yk.example.com", extra: str = "") -> dict:
        key = tmp_path / "master.key"
        if not key.exists():
            create_master_key(key)
        path = tmp_path / "config.toml"
        path.write_text(
            "[application]\n"
            f"listen_port = {free_port()}\n"
            "workers = 2\n"
            f'public_base_url = "{public_base_url}"\n'
            f"{extra}"
            "[database]\n"
            f'sqlite_path = "{tmp_path / "yk-portal.sqlite3"}"\n'
            "[security]\n"
            f'master_key_path = "{key}"\n'
        )
        env = {k: v for k, v in os.environ.items() if not k.startswith(("DJANGO_", "YK_PORTAL"))}
        return env | {"YK_PORTAL_CONFIG": str(path)}

    return write


def run(env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - the installed command
        [COMMAND, *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        umask=0o022,  # as from a shell or sudo
    )


def production_settings(env: dict, *names: str) -> list:
    code = (
        "import django, json; django.setup(); from django.conf import settings; "
        f"print(json.dumps([getattr(settings, n) for n in {list(names)!r}]))"
    )
    env = env | {"DJANGO_SETTINGS_MODULE": "yk_portal.settings.production"}
    result = subprocess.run(  # noqa: S603 - this interpreter
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True
    )
    return json.loads(result.stdout)


def test_the_production_settings_pass_djangos_deployment_checks(config):
    result = run(config(), "check", "--deploy", "--fail-level", "WARNING")
    assert result.returncode == 0, result.stderr
    assert "no issues (1 silenced)" in result.stdout


def test_the_production_settings_at_the_sites_root(config):
    assert production_settings(
        config(),
        "FORCE_SCRIPT_NAME",
        "CSRF_COOKIE_PATH",
        "ALLOWED_HOSTS",
        "CSRF_TRUSTED_ORIGINS",
        "SECURE_SSL_HOST",
        "SECURE_HSTS_SECONDS",
        "DEBUG",
    ) == [
        None,
        "/",
        ["yk.example.com"],
        ["https://yk.example.com"],
        "yk.example.com",
        31536000,
        False,
    ]


def test_the_production_settings_under_a_path(config):
    env = config("https://dev.example.com:8443/yk/")
    assert production_settings(
        env, "FORCE_SCRIPT_NAME", "CSRF_COOKIE_PATH", "CSRF_TRUSTED_ORIGINS", "SECURE_SSL_HOST"
    ) == ["/yk", "/yk/", ["https://dev.example.com:8443"], "dev.example.com:8443"]


def test_gunicorn_options(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        '[application]\nlisten_address = "::1"\nlisten_port = 8100\nworkers = 3\n'
        'public_base_url = "https://yk.example.com"\n'
        '[proxy]\ntrusted_proxy_addresses = ["::1", "10.0.0.0/24"]\n'
        '[logging]\nlevel = "warning"\n'
    )
    assert options(load_config(path)) == {
        "bind": ["[::1]:8100"],
        "workers": 3,
        "preload_app": True,
        "accesslog": None,
        "errorlog": "-",
        "loglevel": "warning",
        "forwarded_allow_ips": "::1/128,10.0.0.0/24",
        "secure_scheme_headers": {"X-FORWARDED-PROTO": "https"},
        "forwarder_headers": "",
        "proc_name": "yk-portal",
        "worker_tmp_dir": "/dev/shm",  # noqa: S108
        "umask": 0o077,
        "control_socket_disable": True,
    }


def get(port: int, path: str, **headers: str) -> tuple[int, dict, bytes]:
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers)  # noqa: S310
    opener = urllib.request.build_opener(NoRedirects)
    try:
        with opener.open(request, timeout=10) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


@pytest.fixture
def server(config, request):
    """A running yk-portal serve, with its database migrated, and its port. Its
    public_base_url is the test's parameter, if it has one."""
    env = config(getattr(request, "param", "https://yk.example.com"))
    config = load_config(Path(env["YK_PORTAL_CONFIG"]))
    port = config.application.listen_port
    assert run(env, "migrate", "-v", "0").returncode == 0
    # Whatever the umask, the database is the service account's alone.
    assert stat.S_IMODE(config.database.sqlite_path.stat().st_mode) == 0o600
    process = subprocess.Popen(  # noqa: S603 - the installed command
        [COMMAND, "serve"], env=env, stderr=subprocess.PIPE, text=True
    )
    deadline = time.monotonic() + 30
    while True:
        try:
            if get(port, "/health/ready")[0] == 200:
                break
        except OSError:
            pass
        assert process.poll() is None and time.monotonic() < deadline, "the server didn't start"
        time.sleep(0.2)
    yield process, port
    if process.poll() is None:
        process.kill()
        process.wait()


def test_serve(server):
    process, port = server
    proxied = {"Host": "yk.example.com", "X-Forwarded-Proto": "https"}
    status, headers, body = get(port, "/login/", **proxied, **{"X-Forwarded-For": "192.0.2.5"})
    assert status == 200 and b"Sign in" in body
    assert headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
    assert headers["Cache-Control"] == "no-store"
    assert "Secure" in headers["Set-Cookie"]
    # Without the proxy's header: plain HTTP, sent to the public address.
    status, headers, _ = get(port, "/login/", Host="yk.example.com")
    assert (status, headers["Location"]) == (301, "https://yk.example.com/login/")
    # Another host name: refused.
    assert get(port, "/login/", **(proxied | {"Host": "evil.example"}))[0] == 400
    status, headers, _ = get(port, "/static/web/portal.css", **proxied)
    assert (status, headers["Cache-Control"]) == (200, "max-age=60, public")
    assert get(port, "/health/live")[2] == b'{"status": "live"}'
    # Even from the trusted proxy, no header chooses the path the application sees.
    assert get(port, "/x/health/live", **proxied, SCRIPT_NAME="/x")[0] == 404
    status, _, body = get(port, "/login/", **proxied, PATH_INFO="/health/live")
    assert status == 200 and b"Sign in" in body

    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=30) == 0
    log = process.stderr.read() if process.stderr else ""
    assert "yk-portal 0.1.0 starting at https://yk.example.com, with the sqlite database" in log
    assert "Shutting down: Master" in log


@pytest.mark.parametrize("server", ["https://dev.example.com/yk"], indirect=True)
def test_serve_under_a_path(server):
    """The proxy strips /yk; every link, static file and cookie carries it again."""
    _, port = server
    proxied = {"Host": "dev.example.com", "X-Forwarded-Proto": "https"}
    status, headers, body = get(port, "/login/", **proxied)
    assert status == 200
    html = body.decode()
    assert 'action="/yk/login/"' in html
    assert 'href="/yk/static/web/portal.css"' in html
    assert 'src="/yk/static/web/reveal.js"' in html
    assert "yk_csrftoken=" in headers["Set-Cookie"] and "Path=/yk/" in headers["Set-Cookie"]
    # The site's HSTS policy is the site's to set.
    assert "Strict-Transport-Security" not in headers
    assert get(port, "/static/web/portal.css", **proxied)[0] == 200
    status, headers, _ = get(port, "/", **proxied)
    assert (status, headers["Location"]) == (302, "/yk/login/")


def test_serve_stops_at_once_without_the_master_key(config, tmp_path):
    env = config()
    (tmp_path / "master.key").unlink()
    result = run(env, "serve")
    assert result.returncode == 1
    assert "master.key: not found; create it with 'yk-portal master-key-create'" in result.stderr


def test_serve_stops_at_once_with_a_bad_configuration(config):
    result = run(config(extra="colour = 'blue'\n"), "serve")
    assert result.returncode == 1
    assert "[application] unknown key(s): colour" in result.stderr


def test_serve_usage(config):
    assert run(config(), "serve", "--help").stdout.startswith("usage: yk-portal serve")
    assert run(config(), "serve", "extra").returncode == 2


def test_serve_warns_when_not_ready(config):
    """It still starts: the database may come later. Here there is none yet."""
    env = config()
    port = load_config(Path(env["YK_PORTAL_CONFIG"])).application.listen_port
    process = subprocess.Popen(  # noqa: S603 - the installed command
        [COMMAND, "serve"], env=env, stderr=subprocess.PIPE, text=True
    )
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                status, _, body = get(port, "/health/ready")
                break
            except OSError:
                assert time.monotonic() < deadline
                time.sleep(0.2)
        assert (status, json.loads(body)) == (503, {"status": "not ready", "failed": ["database"]})
    finally:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=30)
    log = process.stderr.read() if process.stderr else ""
    assert "not ready: database: there is no database yet; run yk-portal migrate" in log
