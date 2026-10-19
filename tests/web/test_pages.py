import re
from pathlib import Path

import pytest
from django.test import Client
from django.urls import reverse

from yk_portal.accounts import services
from yk_portal.accounts.models import AccountState, Theme, User
from yk_portal.authentication.models import Session
from yk_portal.authentication.passwords import hash_pin
from yk_portal.authentication.sessions import COOKIE
from yk_portal.portal_settings import service as portal_settings
from yk_portal.web.context_processors import THEME_COOKIE

pytestmark = pytest.mark.django_db

PIN = "Passw0rd!"
PUBLIC_ID = "vvccccbbcdef"
PRIVATE_ID = "4a6f8e2d1c3b"
K1 = "6b1f0a9d2c7e4f3a8b5d0c1e9f2a7b6d"
SRC = Path(__file__).resolve().parents[2] / "src" / "yk_portal"


@pytest.fixture(scope="session")
def hashes():
    return hash_pin(PIN)


@pytest.fixture
def alice(make_user, make_credential, hashes):
    user = make_user("alice")
    make_credential(
        user,
        public_id=PUBLIC_ID,
        private_id=PRIVATE_ID,
        aes_key=K1,
        pin_hash=hashes.web,
        radius_pin_hash=hashes.radius,
    )
    return user


@pytest.fixture
def passcode(make_otp):
    """passcode(session): alice's PIN and a fresh OTP."""
    return lambda session: PIN + make_otp(PUBLIC_ID, PRIVATE_ID, K1, 3, session)


def sign_in(client: Client, username: str, passcode: str):
    return client.post(reverse("login"), {"username": username, "passcode": passcode})


def without_csrf_tokens(html: bytes) -> str:
    return re.sub(r'name="csrfmiddlewaretoken" value="[^"]+"', "", html.decode())


# Signing in and out


def test_login_page(client):
    response = client.get(reverse("login"))
    assert response.status_code == 200
    html = response.content.decode()
    assert "<title>Sign in · yk-portal</title>" in html
    assert 'name="passcode"' in html
    assert response.headers["Content-Security-Policy"].startswith("default-src 'self'")


def test_login_notice_and_portal_name_are_plain_text(client, actor):
    portal_settings.update(
        {
            "portal_name": "NOC <b>Portal</b>",
            "login_notice": "Authorized use only.\n<script>x</script>",
        },
        actor,
    )
    html = client.get(reverse("login")).content.decode()
    assert "NOC &lt;b&gt;Portal&lt;/b&gt;" in html
    assert "Authorized use only.<br>&lt;script&gt;x&lt;/script&gt;" in html
    assert "<script>" not in html


def test_sign_in_and_out(client, alice, passcode):
    response = sign_in(client, "alice", passcode(1))
    assert response.status_code == 302
    assert response.headers["Location"] == reverse("home")
    cookie = response.cookies[COOKIE]
    assert cookie["httponly"] and cookie["secure"] and cookie["samesite"] == "Strict"
    assert not cookie["max-age"]  # ends with the browser session
    assert "<h1>alice</h1>" in client.get(reverse("home")).content.decode()

    assert client.get(reverse("logout")).status_code == 405
    response = client.post(reverse("logout"))
    assert response.headers["Location"] == reverse("login")
    assert response.cookies[COOKIE].value == ""
    assert Session.objects.get().revoked_at is not None
    client.cookies[COOKIE] = cookie.value  # the old cookie no longer works
    assert client.get(reverse("home")).headers["Location"] == reverse("login")


def test_every_failure_looks_the_same(client, alice, passcode, make_otp):
    pages = [
        sign_in(client, "alice", "wrong-pin1" + passcode(1)[len(PIN) :]),
        sign_in(client, "nobody", passcode(2)),
        sign_in(client, "alice", PIN + make_otp(PUBLIC_ID, "111111111111", K1, 3, 3)),
    ]
    assert {page.status_code for page in pages} == {200}
    bodies = {without_csrf_tokens(page.content).replace("nobody", "alice") for page in pages}
    assert len(bodies) == 1
    assert "Sign-in failed. Check your username, PIN and YubiKey." in bodies.pop()
    assert COOKIE not in pages[0].cookies


def test_signed_in_users_skip_the_login_page(client, alice, passcode):
    sign_in(client, "alice", passcode(1))
    assert client.get(reverse("login")).headers["Location"] == reverse("home")


def test_a_new_login_replaces_any_old_cookie(client, alice, passcode):
    client.cookies[COOKIE] = "planted-by-someone-else"
    response = sign_in(client, "alice", passcode(1))
    assert response.cookies[COOKIE].value != "planted-by-someone-else"


def test_an_invalid_cookie_is_removed(client, db):
    client.cookies[COOKIE] = "expired-or-forged"
    response = client.get(reverse("login"))
    assert response.cookies[COOKIE].value == ""


def test_login_needs_the_csrf_token(alice, passcode):
    client = Client(enforce_csrf_checks=True)
    assert sign_in(client, "alice", passcode(1)).status_code == 403


# Who may open which page


def test_anonymous_users_are_sent_to_sign_in(client, db):
    assert client.get(reverse("home")).headers["Location"] == reverse("login")
    assert client.get(reverse("provision")).headers["Location"] == reverse("login")


def test_provisioning_sessions_are_restricted_to_onboarding(client, actor):
    account = services.create_user("nina", actor)
    sign_in(client, "nina", account.temporary_password)
    assert client.get(reverse("home")).headers["Location"] == reverse("provision")
    assert "Set up your account" in client.get(reverse("provision")).content.decode()


def test_active_accounts_skip_onboarding(client, alice, passcode):
    sign_in(client, "alice", passcode(1))
    assert client.get(reverse("provision")).headers["Location"] == reverse("home")


def test_a_disabled_account_is_signed_out(client, alice, passcode, actor):
    sign_in(client, "alice", passcode(1))
    services.disable(alice, actor)
    assert client.get(reverse("home")).headers["Location"] == reverse("login")


# Themes (addendum §4)


def theme_attribute(html: str) -> str | None:
    match = re.search(r'<html lang="en"(?: data-theme="(\w+)")?>', html)
    assert match
    return match.group(1)


def test_the_browser_decides_by_default(client, db):
    assert theme_attribute(client.get(reverse("login")).content.decode()) is None


def test_the_default_theme_setting(client, actor):
    portal_settings.update({"default_theme": Theme.DARK}, actor)
    assert theme_attribute(client.get(reverse("login")).content.decode()) == "dark"


def test_the_sign_in_page_remembers_this_browsers_choice(client, actor):
    portal_settings.update({"default_theme": Theme.DARK}, actor)
    response = client.post(reverse("theme"), {"theme": "browser", "next": reverse("login")})
    assert response.headers["Location"] == reverse("login")
    assert response.cookies[THEME_COOKIE].value == "browser"
    # An explicit "Browser" beats the default theme.
    assert theme_attribute(client.get(reverse("login")).content.decode()) is None


def test_a_signed_in_users_choice_is_saved_to_the_account(client, alice, passcode):
    sign_in(client, "alice", passcode(1))
    client.post(reverse("theme"), {"theme": "light", "next": reverse("home")})
    assert User.objects.get(pk=alice.pk).theme == Theme.LIGHT
    other_browser = Client()
    sign_in(other_browser, "alice", passcode(2))
    html = other_browser.get(reverse("home")).content.decode()
    assert theme_attribute(html) == "light"
    assert '<button type="submit" name="theme" value="light" aria-pressed="true">' in html


@pytest.mark.parametrize("target", ["https://evil.example/", "//evil.example/", ""])
def test_theme_redirects_only_within_the_portal(client, db, target):
    response = client.post(reverse("theme"), {"theme": "dark", "next": target})
    assert response.headers["Location"] == "/"


def test_an_unknown_theme_is_ignored(client, db):
    response = client.post(reverse("theme"), {"theme": "sepia", "next": "/login/"})
    assert THEME_COOKIE not in response.cookies


def test_templates_have_no_inline_scripts_or_styles():
    """Addendum §4.4: a strict Content-Security-Policy must work. Scripts are files."""
    inline = re.compile(
        r"<script(?![^>]*\ssrc=)|<script[^>]*>[^<]+</script>|<style|\sstyle=|\son[a-z]+=",
        re.IGNORECASE,
    )
    templates = list(SRC.glob("*/templates/**/*.html"))
    assert templates
    for template in templates:
        assert not inline.search(template.read_text()), template


def test_no_table_cell_is_laid_out_as_flex():
    """A flex cell isn't a table cell: it doesn't take its row's height, so its border
    doesn't line up with the row's (the actions go in a div inside the cell)."""
    for template in SRC.glob("*/templates/**/*.html"):
        assert not re.search(r'<t[dh][^>]*class="[^"]*\bactions\b', template.read_text()), template


def test_pages_load_the_show_hide_script(client, db):
    html = client.get(reverse("login")).content.decode()
    assert '<script src="/static/web/reveal.js" defer></script>' in html
    assert (SRC / "web" / "static" / "web" / "reveal.js").is_file()


def masked_fields(html: str) -> set[str]:
    """Names of the inputs shown masked, with a show/hide button."""
    names = set()
    for tag in re.findall(r"<input [^>]*>", html):
        name = re.search(r'name="(\w+)"', tag)
        if name and 'type="password"' in tag and "data-reveal" in tag:
            names.add(name.group(1))
    return names


def test_the_passcode_is_masked_with_a_show_button(client, db):
    assert masked_fields(client.get(reverse("login")).content.decode()) == {"passcode"}


def test_provisioning_lockout_through_the_page(client, actor):
    account = services.create_user("nina", actor)
    for _ in range(3):
        sign_in(client, "nina", "wrong-temp-1")
    assert User.objects.get(pk=account.user.pk).state == AccountState.LOCKED
