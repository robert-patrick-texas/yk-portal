"""Production hardening of the web application (spec §32, §33, §41, §48; addendum §20)."""

import json
import re
import uuid
from pathlib import Path

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import Client
from django.urls import URLPattern, URLResolver, get_resolver, reverse, set_script_prefix

from yk_portal.core.master_key import create_master_key
from yk_portal.web import health

pytestmark = pytest.mark.django_db

SRC = Path(__file__).resolve().parents[2] / "src" / "yk_portal"


# Health checks (spec §41)


def test_live(client):
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "live"}
    assert response.headers["Content-Type"] == "application/json"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_ready(client, master_key):
    response = client.get("/health/ready")
    assert (response.status_code, response.json()) == (200, {"status": "ready"})
    assert client.head("/health/ready").status_code == 200


def test_health_checks_answer_any_host_name(client, master_key, settings):
    """Local monitoring asks the application directly, as http://127.0.0.1:8000."""
    settings.ALLOWED_HOSTS = ["yk.example.com"]
    assert client.get("/health/ready", HTTP_HOST="127.0.0.1:8000").status_code == 200
    assert client.get(reverse("login"), HTTP_HOST="127.0.0.1:8000").status_code == 400


def test_health_checks_only_read(client):
    response = client.post("/health/live")
    assert (response.status_code, response.headers["Allow"]) == (405, "GET, HEAD")


def test_not_ready_without_the_master_key(client, settings, tmp_path, caplog):
    settings.YK_MASTER_KEY_PATH = str(tmp_path / "missing.key")
    response = client.get("/health/ready")
    assert (response.status_code, response.json()) == (
        503,
        {"status": "not ready", "failed": ["master key"]},
    )
    assert str(tmp_path) not in response.content.decode()  # the reason goes to the log only
    assert "not ready: master key: " in caplog.text and "missing.key: not found" in caplog.text


def test_not_ready_when_the_master_key_file_changed(client, settings, tmp_path):
    """The running application still uses the key it read: restart it."""
    path = tmp_path / "master.key"
    create_master_key(path)
    settings.YK_MASTER_KEY_PATH = str(path)
    assert client.get("/health/ready").status_code == 200
    path.unlink()
    create_master_key(path)
    assert client.get("/health/ready").json()["failed"] == ["master key"]


@pytest.mark.django_db(transaction=True)
def test_not_ready_with_migrations_missing(client, master_key):
    executor = MigrationExecutor(connection)
    try:
        executor.migrate([("audit", "0005_details_unicode")])
        response = client.get("/health/ready")
        assert (response.status_code, response.json()["failed"]) == (503, ["migrations"])
    finally:
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())


@pytest.mark.skipif(connection.vendor != "sqlite", reason="a SQLite file")
def test_not_ready_without_a_database_and_none_is_created(master_key, tmp_path, monkeypatch):
    path = tmp_path / "none.sqlite3"
    monkeypatch.setitem(connection.settings_dict, "NAME", path)
    (problem,) = health.readiness()
    assert (problem.check, problem.reason) == (
        "database",
        "there is no database yet; run yk-portal migrate",
    )
    assert not path.exists()


# Forwarded headers (spec §32)


@pytest.fixture
def https_only(settings):
    settings.SECURE_SSL_REDIRECT = True
    settings.SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    settings.ALLOWED_HOSTS = ["yk.example.com"]
    settings.SECURE_SSL_HOST = "yk.example.com"


def test_the_proxy_says_https(client, https_only):
    response = client.get(
        reverse("login"),
        HTTP_HOST="yk.example.com",
        REMOTE_ADDR="127.0.0.1",
        HTTP_X_FORWARDED_PROTO="https",
    )
    assert response.status_code == 200


def test_only_a_trusted_proxy_says_https(client, https_only):
    """A client that reaches the application directly can't claim HTTPS: it is sent to
    the public address, like any plain-HTTP request."""
    response = client.get(
        reverse("login"),
        HTTP_HOST="yk.example.com",
        REMOTE_ADDR="192.0.2.9",
        HTTP_X_FORWARDED_PROTO="https",
    )
    assert response.status_code == 301
    assert response.headers["Location"] == "https://yk.example.com/login/"


def test_health_checks_arent_redirected(client, https_only, master_key):
    assert client.get("/health/ready", REMOTE_ADDR="127.0.0.1").status_code == 200


# Security headers (spec §33)


def test_every_page_has_the_security_headers(client):
    headers = client.get(reverse("login")).headers
    assert headers["Content-Security-Policy"] == (
        "default-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'; object-src 'none'"
    )
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "same-origin"
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert headers["Permissions-Policy"].startswith("camera=()")


def test_redirects_have_them_too(client):
    response = client.get(reverse("home"))
    assert response.status_code == 302
    assert response.headers["Cache-Control"] == "no-store"


def test_static_files_are_served_and_may_be_cached_briefly(client):
    response = client.get("/static/web/portal.css")
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("text/css")
    assert response.headers["Cache-Control"] == "max-age=60, public"
    assert "Access-Control-Allow-Origin" not in response.headers
    assert client.get("/static/web/missing.css").status_code == 404


# CSRF (spec §33, §48)


def _routes(patterns=None, prefix=""):
    for pattern in patterns if patterns is not None else get_resolver().url_patterns:
        if isinstance(pattern, URLResolver):
            yield from _routes(pattern.url_patterns, prefix)
        elif isinstance(pattern, URLPattern) and pattern.name:
            yield pattern


def _url(pattern: URLPattern) -> str:
    kwargs = {name: uuid.uuid4() for name in pattern.pattern.converters}
    return reverse(pattern.name, kwargs=kwargs)


@pytest.mark.parametrize("pattern", list(_routes()), ids=lambda p: p.name)
def test_every_form_needs_its_csrf_token(pattern, alice_signed_in):
    """Signed in or not, a POST without the token changes nothing."""
    response = alice_signed_in.post(_url(pattern), {"username": "x"})
    assert response.status_code == 403
    assert "Form not accepted" in response.content.decode()


@pytest.fixture
def alice_signed_in(make_user):
    from yk_portal.authentication.sessions import COOKIE, start_session
    from yk_portal.authentication.sessions import Client as SessionClient

    browser = Client(enforce_csrf_checks=True)
    alice = make_user("alice", admin=True)
    _, token = start_session(alice, SessionClient("127.0.0.1", "pytest"))
    browser.cookies[COOKIE] = token
    return browser


def _forms() -> list[tuple[str, str, str]]:
    """Every form in the templates: its template, its method and its HTML."""
    forms = []
    for template in sorted(SRC.rglob("templates/**/*.html")):
        for form in re.findall(r"<form\b[^>]*>.*?</form>", template.read_text(), re.S):
            method = re.search(r'method="(get|post)"', form.split(">", 1)[0])
            name = str(template.relative_to(SRC))
            forms.append((name, method.group(1) if method else "", form))
    return forms


def test_every_post_form_carries_the_token():
    forms = [(name, form) for name, method, form in _forms() if method == "post"]
    assert len(forms) > 30
    for name, form in forms:
        assert "{% csrf_token %}" in form, name


def test_only_the_search_forms_put_their_fields_in_the_url():
    """No secret in a browser URL (spec §33, §48): every form says its method, and only
    the searches use GET."""
    assert all(method for _, method, _ in _forms())
    assert {name for name, method, _ in _forms() if method == "get"} == {
        "accounts/templates/accounts/admin/users.html",
        "audit/templates/audit/admin/events.html",
    }


@pytest.mark.parametrize("query", ["' OR '1'='1", "%", "_", "\\", "'; DROP TABLE users; --"])
def test_searches_take_any_text_as_text(admin_client_signed_in, make_user, query):
    """SQL injection attempts (spec §48): the ORM sends the text as a parameter, and
    LIKE's wildcards are escaped."""
    make_user("bob")
    for url in (reverse("admin-users"), reverse("admin-audit")):
        response = admin_client_signed_in.get(url, {"q": query})
        assert response.status_code == 200
    assert (
        "bob"
        not in admin_client_signed_in.get(reverse("admin-users"), {"q": query}).content.decode()
    )


@pytest.fixture
def admin_client_signed_in(make_user):
    from yk_portal.authentication.sessions import COOKIE, start_session
    from yk_portal.authentication.sessions import Client as SessionClient

    browser = Client()
    root = make_user("root", admin=True)
    _, token = start_session(root, SessionClient("127.0.0.1", "pytest"))
    browser.cookies[COOKIE] = token
    return browser


# Request size (spec §32, §33)


def test_a_large_form_is_refused(client):
    response = client.post(reverse("login"), {"username": "x", "passcode": "p" * 300_000})
    assert response.status_code == 400


def test_files_are_refused(client):
    upload = SimpleUploadedFile("a.txt", b"x")
    response = client.post(reverse("login"), {"username": "x", "file": upload})
    assert response.status_code == 400


# Published under a path (addendum §20.2)


@pytest.fixture
def under_yk(settings):
    """As the production settings set it up for public_base_url https://HOST/yk."""
    settings.FORCE_SCRIPT_NAME = "/yk"
    settings.CSRF_COOKIE_PATH = "/yk/"
    settings.STATIC_URL = "/yk/static/"
    set_script_prefix("/yk/")
    yield
    set_script_prefix("/")


def test_links_and_cookies_carry_the_path(under_yk, client, make_user, make_credential, make_otp):
    from yk_portal.authentication.passwords import hash_pin

    html = client.get("/login/").content.decode()
    assert 'action="/yk/login/"' in html
    assert 'href="/yk/static/web/portal.css"' in html
    assert client.cookies["yk_csrftoken"]["path"] == "/yk/"
    alice = make_user("alice")
    hashes = hash_pin("Passw0rd!")
    make_credential(
        alice,
        public_id="vvccccbbcdef",
        private_id="4a6f8e2d1c3b",
        aes_key="6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d",
        pin_hash=hashes.web,
        radius_pin_hash=hashes.radius,
    )
    otp = make_otp("vvccccbbcdef", "4a6f8e2d1c3b", "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d", 1)
    response = client.post("/login/", {"username": "alice", "passcode": "Passw0rd!" + otp})
    assert response.headers["Location"] == "/yk/"
    assert response.cookies["yk_session"]["path"] == "/yk/"
    response = client.post("/theme/", {"theme": "dark", "next": "https://elsewhere.example/"})
    assert response.headers["Location"] == "/yk/"
    assert response.cookies["yk_theme"]["path"] == "/yk/"
    response = client.post("/logout/")
    assert response.headers["Location"] == "/yk/login/"
    assert response.cookies["yk_session"]["path"] == "/yk/"


def test_static_files_under_the_path(under_yk, client):
    # The proxy strips /yk, so the application sees the path without it.
    assert client.get("/static/web/portal.css").status_code == 200


def test_health_checks_under_the_path(under_yk, client, master_key):
    assert json.loads(client.get("/health/ready").content) == {"status": "ready"}
