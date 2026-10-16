from yk_portal.accounts.models import Theme
from yk_portal.authentication.sessions import PortalRequest

THEME_COOKIE = "yk_theme"


def theme_choice(request: PortalRequest) -> str:
    """The theme chosen: the signed-in user's, else this browser's last choice, else ""."""
    choice = request.account.theme if request.account else request.COOKIES.get(THEME_COOKIE, "")
    return choice if choice in Theme.values else ""


def portal(request: PortalRequest) -> dict[str, object]:
    """The run-time settings, the signed-in account and the theme, for every page.

    "theme" is light or dark, or empty to follow the browser (addendum §4.2).
    """
    portal_settings = request.portal_settings
    shown = theme_choice(request) or portal_settings.default_theme
    return {
        "portal": portal_settings,
        "account": request.account,
        "theme_shown": shown,
        "theme": shown if shown in (Theme.LIGHT, Theme.DARK) else "",
        "themes": Theme.choices,
    }
