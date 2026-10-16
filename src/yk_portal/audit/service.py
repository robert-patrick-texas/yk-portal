"""Recording audit events (spec §27).

Each event is stored in audit_events and, once the transaction commits,
copied to the yk_portal.audit logger, which production sends to the system
journal (addendum §13 item 15). Immutability and the admin viewer come with
spec Phase 7.
"""

import getpass
import json
import logging
import os
import uuid
from collections.abc import Mapping
from dataclasses import dataclass

from django.db import transaction

from yk_portal.accounts.models import User

from .models import AuditEvent, EventType, Result

logger = logging.getLogger("yk_portal.audit")

type Details = Mapping[str, str | int | bool | None | list[str]]


@dataclass(frozen=True)
class Actor:
    """Who performs an action: a signed-in user, or someone at the command line."""

    user: User | None
    name: str
    source_ip: str | None = None
    session_id: uuid.UUID | None = None

    @classmethod
    def for_user(cls, user: User) -> Actor:
        """A signed-in user. The web pages add the source IP and session in Phase 4."""
        return cls(user=user, name=user.username)

    @classmethod
    def cli(cls) -> Actor:
        """The command line: "cli:<os user>", plus the sudo caller when there is one."""
        name = f"cli:{getpass.getuser()}"
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            name += f" (sudo by {sudo_user})"
        return cls(user=None, name=name)


def record(
    event_type: EventType,
    actor: Actor,
    target: User | None = None,
    details: Details | None = None,
    result: Result = Result.SUCCESS,
) -> AuditEvent:
    """Store an audit event. DETAILS must never hold a secret or an email address.

    Args:
        event_type: What happened.
        actor: Who did it.
        target: The account it was done to, if any.
        details: Extra facts, such as old and new values.
        result: Whether it succeeded.

    Returns:
        The stored event.
    """
    event = AuditEvent.objects.create(
        event_type=event_type,
        actor_user_id=actor.user.pk if actor.user else None,
        actor_username_snapshot=actor.name,
        target_user_id=target.pk if target else None,
        target_username_snapshot=target.username if target else "",
        source_ip=actor.source_ip,
        session_id=actor.session_id,
        result=result,
        details=dict(details or {}),
    )
    line = (
        f"{event_type} actor={actor.name} target={event.target_username_snapshot or '-'} "
        f"result={result} details={json.dumps(event.details, sort_keys=True)}"
    )
    transaction.on_commit(lambda: logger.info("%s", line))
    return event
