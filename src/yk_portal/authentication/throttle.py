"""The per-address limit on failed sign-ins (spec §18.2, §43 item 6; addendum §20.4).

The account lockout lets anyone who knows a username lock its account. An
address with too many failed sign-ins within the wait (settings) must wait:
its sign-ins are refused before any check, so they neither count against an
account nor spend a password check, until the oldest failure counted is
older than the wait. The failures are the audit log's, which records each
one with its address, so every worker, and both backends, count the same.

A refused sign-in is recorded once per address and wait, as LOGIN_THROTTLED,
so an address that keeps trying doesn't fill the audit log, which is never
purged.
"""

import logging
from datetime import timedelta

from django.utils import timezone

from yk_portal.audit.models import AuditEvent, EventType, Result
from yk_portal.audit.service import Actor, record
from yk_portal.portal_settings.service import PortalSettings

from .sessions import is_trusted_proxy

logger = logging.getLogger("yk_portal.authentication")

# The events that count: every failed sign-in, and attempts on locked accounts.
FAILURES = (EventType.LOGIN_FAILURE, EventType.LOGIN_LOCKED)

_warned = False


def wait(source_ip: str | None, portal_settings: PortalSettings) -> timedelta | None:
    """How long SOURCE_IP must still wait before it may sign in, or None if it may.

    A trusted proxy's address means the proxy didn't say whose request it is:
    every client would share one count, so none is kept (logged once).
    """
    if source_ip is None or _proxy(source_ip):
        return None
    now = timezone.now()
    window = timedelta(minutes=portal_settings.address_wait_minutes)
    limit = portal_settings.address_failure_limit
    recent = list(
        AuditEvent.objects.filter(
            source_ip=source_ip, event_type__in=FAILURES, timestamp__gt=now - window
        )
        .order_by("-timestamp")
        .values_list("timestamp", flat=True)[:limit]
    )
    if len(recent) < limit:
        return None
    # The count falls below the limit when the LIMIT-th latest failure leaves the window.
    return recent[-1] + window - now


def refused(source_ip: str, waiting: timedelta, portal_settings: PortalSettings) -> None:
    """Record LOGIN_THROTTLED for SOURCE_IP, unless it was recorded within the wait."""
    window = timedelta(minutes=portal_settings.address_wait_minutes)
    if AuditEvent.objects.filter(
        source_ip=source_ip,
        event_type=EventType.LOGIN_THROTTLED,
        timestamp__gt=timezone.now() - window,
    ).exists():
        return
    details = {
        "reason": "too many failed sign-ins from this address",
        "failed_logins": portal_settings.address_failure_limit,
        "wait_minutes": portal_settings.address_wait_minutes,
        "seconds_left": int(waiting.total_seconds()),
    }
    actor = Actor(user=None, name="", source_ip=source_ip)
    record(EventType.LOGIN_THROTTLED, actor, details=details, result=Result.FAILURE)


def _proxy(source_ip: str) -> bool:
    global _warned
    if not is_trusted_proxy(source_ip):
        return False
    if not _warned:
        _warned = True
        logger.warning(
            "a sign-in came from %s, a trusted proxy, without the client's address: "
            "failed sign-ins can't be limited per address. Set the proxy to send "
            "X-Forwarded-For (deployment guide).",
            source_ip,
        )
    return True
