"""The audit log's copy in the system journal (spec §40; addendum §17.6)."""

import logging
from logging.handlers import SysLogHandler

IDENTIFIER = "yk-portal-audit"


def journal_handler(address: str = "/dev/log") -> logging.Handler:
    """A handler that sends records to the local syslog socket, which journald reads, as
    IDENTIFIER with the authpriv facility: `journalctl -t yk-portal-audit` lists them,
    apart from the application's log, whether the web application or a command wrote
    them. If the socket is missing, each record is reported on standard error."""
    handler = SysLogHandler(address=address, facility=SysLogHandler.LOG_AUTHPRIV)
    handler.ident = f"{IDENTIFIER}: "
    return handler
