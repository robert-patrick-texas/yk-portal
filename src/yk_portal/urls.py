from django.urls import URLPattern, URLResolver, path

from yk_portal.authentication import views as authentication
from yk_portal.web import views as web

urlpatterns: list[URLPattern | URLResolver] = [
    path("", web.home, name="home"),
    path("welcome/", web.welcome, name="welcome"),
    path("theme/", web.set_theme, name="theme"),
    path("login/", authentication.login, name="login"),
    path("logout/", authentication.logout, name="logout"),
]
