"""Middleware for health checks, forwarded headers and security headers (spec §32, §33,
§41)."""

from collections.abc import Callable

from django.http import HttpRequest, HttpResponse

from yk_portal.authentication.sessions import is_trusted_proxy

from . import health

type GetResponse = Callable[[HttpRequest], HttpResponse]

# Pages have no inline scripts or styles (addendum §4.4), so nothing else is allowed.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'; object-src 'none'"
)
# Browser features no page uses.
PERMISSIONS_POLICY = "camera=(), geolocation=(), microphone=(), payment=(), usb=()"


class HealthCheckMiddleware:
    """Answer /health/live and /health/ready first, before the host name is checked and
    without a session, so local monitoring can ask the application directly (spec
    §41)."""

    def __init__(self, get_response: GetResponse) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.path_info in health.PATHS:
            return health.respond(request)
        return self.get_response(request)


class ForwardedHeadersMiddleware:
    """Believe X-Forwarded-Proto only from a trusted proxy (spec §32).

    Django reads it for SECURE_PROXY_SSL_HEADER. From any other address it is
    dropped, so a client that reaches the application directly is redirected to
    HTTPS like any other plain-HTTP request. X-Forwarded-For is read only through
    the trusted proxies (sessions.client_ip).
    """

    def __init__(self, get_response: GetResponse) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if not is_trusted_proxy(request.META.get("REMOTE_ADDR", "")):
            request.META.pop("HTTP_X_FORWARDED_PROTO", None)
        return self.get_response(request)


class SecurityHeadersMiddleware:
    """Headers for every response: the Content-Security-Policy, and no caching unless
    the response says otherwise, since pages show accounts, YubiKeys and secrets
    (spec §33). Static files say they may be cached."""

    def __init__(self, get_response: GetResponse) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        response.headers.setdefault("Permissions-Policy", PERMISSIONS_POLICY)
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("Cache-Control", "no-store")
        return response
