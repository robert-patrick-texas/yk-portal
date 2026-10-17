"""Starting, finding, ending and revoking web sessions (spec §19).

SessionMiddleware attaches the signed-in account to each request. A session
ends when it has been idle longer than the idle timeout, is older than the
maximum session length, is revoked, or its account is no longer ACTIVE or
PROVISIONING. Concurrent sessions are allowed.
"""

import hashlib
import ipaddress
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from django.conf import settings
from django.db.models import Q
from django.http import HttpRequest, HttpResponse
from django.utils import timezone

from yk_portal.accounts.models import AccountState, User
from yk_portal.audit.service import Actor
from yk_portal.portal_settings.service import PortalSettings, current

from .models import Session

COOKIE = "yk_session"
# last_activity_at is written at most this often, not on every request.
ACTIVITY_RESOLUTION = timedelta(minutes=1)
SIGNED_IN_STATES = (AccountState.ACTIVE, AccountState.PROVISIONING)


class PortalRequest(HttpRequest):
    """A request after SessionMiddleware."""

    portal_settings: PortalSettings
    portal_session: Session | None
    account: User | None


@dataclass(frozen=True)
class Client:
    """Where a request comes from, for sessions and the audit log."""

    source_ip: str | None
    user_agent: str

    @classmethod
    def of(cls, request: HttpRequest) -> Client:
        return cls(client_ip(request), request.META.get("HTTP_USER_AGENT", "")[:255])


def client_ip(request: HttpRequest) -> str | None:
    """The client's address: REMOTE_ADDR, or behind a trusted proxy, X-Forwarded-For.

    X-Forwarded-For is read from the right, skipping trusted proxies, so a client
    can't choose its address by sending the header itself.
    """
    trusted = settings.YK_TRUSTED_PROXIES
    hops = [request.META.get("REMOTE_ADDR", "")]
    hops += reversed(request.META.get("HTTP_X_FORWARDED_FOR", "").split(","))
    address = None
    for hop in hops:
        try:
            address = ipaddress.ip_address(hop.strip())
        except ValueError:
            break
        if not any(address in network for network in trusted):
            break
    return str(address) if address else None


def start_session(user: User, client: Client) -> tuple[Session, str]:
    """A new session for USER, and the token for its cookie. Never reuses a session."""
    token = secrets.token_urlsafe(32)
    session = Session.objects.create(
        user=user,
        token_hash=_hash(token),
        last_activity_at=timezone.now(),
        source_ip=client.source_ip,
        user_agent=client.user_agent,
    )
    return session, token


def find_session(token: str, portal_settings: PortalSettings) -> Session | None:
    """The live session for TOKEN, or None. Records the activity."""
    now = timezone.now()
    session = (
        Session.objects.select_related("user")
        .filter(token_hash=_hash(token))
        .exclude(_ended(portal_settings, now))
        .first()
    )
    if session is None or session.user.state not in SIGNED_IN_STATES:
        return None
    if now - session.last_activity_at >= ACTIVITY_RESOLUTION:
        Session.objects.filter(pk=session.pk).update(last_activity_at=now)
        session.last_activity_at = now
    return session


def end_session(session: Session) -> None:
    """Sign out: revoke one session."""
    Session.objects.filter(pk=session.pk, revoked_at__isnull=True).update(revoked_at=timezone.now())


def purge_ended_sessions(portal_settings: PortalSettings) -> int:
    """Delete every user's ended sessions: revoked, idle past the timeout, or older than
    the maximum length. None of them can be used again, and the audit log keeps each
    sign-in. Run at each successful sign-in, so the table needs no scheduled cleanup.

    Returns:
        How many sessions were deleted.
    """
    deleted, _ = Session.objects.filter(_ended(portal_settings, timezone.now())).delete()
    return deleted


def revoke_sessions(user: User, keep: Session | None = None) -> int:
    """Revoke every session of USER but KEEP (spec §15, §18, §19). Returns how many were
    live."""
    sessions = Session.objects.filter(user=user, revoked_at__isnull=True)
    if keep is not None:
        sessions = sessions.exclude(pk=keep.pk)
    return sessions.update(revoked_at=timezone.now())


def request_actor(request: PortalRequest) -> Actor:
    """The signed-in account as the actor of an audited action."""
    account = request.account
    session = request.portal_session
    return Actor(
        user=account,
        name=account.username if account else "",
        source_ip=client_ip(request),
        session_id=session.pk if session else None,
    )


def set_session_cookie(response: HttpResponse, token: str) -> None:
    """A browser-session cookie: script can't read it, and it goes only over HTTPS."""
    response.set_cookie(COOKIE, token, secure=True, httponly=True, samesite="Strict")


class SessionMiddleware:
    """Attach the run-time settings, the session and the signed-in account to each request."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: PortalRequest) -> HttpResponse:
        request.portal_settings = current()
        token = request.COOKIES.get(COOKIE)
        session = find_session(token, request.portal_settings) if token else None
        request.portal_session = session
        request.account = session.user if session else None
        response = self.get_response(request)
        if token and session is None and COOKIE not in response.cookies:
            response.delete_cookie(COOKIE, samesite="Strict")
        return response


def _ended(portal_settings: PortalSettings, now: datetime) -> Q:
    """Sessions that have ended: revoked, idle past the timeout, or past the maximum length."""
    idle = timedelta(minutes=portal_settings.idle_timeout_minutes)
    longest = timedelta(hours=portal_settings.max_session_hours)
    return (
        Q(revoked_at__isnull=False)
        | Q(last_activity_at__lte=now - idle)
        | Q(created_at__lte=now - longest)
    )


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
