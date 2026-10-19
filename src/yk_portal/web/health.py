"""Health checks for local monitoring (spec §41).

/health/live answers as long as the application runs. /health/ready also
checks that it can serve requests: the database answers, its migrations are
the ones this version has, and the master key file still holds the key in
use. A response names the checks that failed, never a value from the
configuration; the operational log has the reasons.
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings
from django.db import DatabaseError, connection
from django.db.migrations.executor import MigrationExecutor
from django.http import HttpRequest, HttpResponse

from yk_portal.core.encryption import derived_keys
from yk_portal.core.master_key import MasterKeyError, derive_keys, load_master_key

logger = logging.getLogger("yk_portal.health")

PATHS = ("/health/live", "/health/ready")


@dataclass(frozen=True)
class Problem:
    check: str  # database, migrations or master key: shown to monitoring
    reason: str  # for the operational log only

    def __str__(self) -> str:
        return f"{self.check}: {self.reason}"


def readiness() -> list[Problem]:
    """What keeps the application from serving requests; empty when it is ready."""
    problems = []
    if connection.vendor == "sqlite" and not Path(connection.settings_dict["NAME"]).exists():
        # Connecting would create an empty database.
        problems.append(Problem("database", "there is no database yet; run yk-portal migrate"))
    else:
        problems += _database()
    try:
        in_use = derived_keys().key_id
        if derive_keys(load_master_key(Path(settings.YK_MASTER_KEY_PATH))).key_id != in_use:
            problems.append(Problem("master key", "the file holds another key; restart"))
    except MasterKeyError as e:
        problems.append(Problem("master key", str(e)))
    return problems


def _database() -> list[Problem]:
    problems = []
    try:
        executor = MigrationExecutor(connection)
        graph = executor.loader.graph
        pending = executor.migration_plan(graph.leaf_nodes())
        unknown = set(executor.loader.applied_migrations) - set(graph.nodes)
    except DatabaseError as e:
        problems.append(Problem("database", " ".join(str(e).split())))
    else:
        if pending:
            problems.append(Problem("migrations", "not all applied; run yk-portal migrate"))
        if unknown:
            problems.append(Problem("migrations", "the database is newer than this version"))
    return problems


def respond(request: HttpRequest) -> HttpResponse:
    """The response for one of PATHS."""
    if request.method not in ("GET", "HEAD"):
        response = HttpResponse(status=405)
        response["Allow"] = "GET, HEAD"
    elif request.path_info == "/health/live":
        response = _json({"status": "live"}, 200)
    else:
        problems = readiness()
        for problem in problems:
            logger.warning("not ready: %s", problem)
        if problems:
            failed = sorted({problem.check for problem in problems})
            response = _json({"status": "not ready", "failed": failed}, 503)
        else:
            response = _json({"status": "ready"}, 200)
    response["Cache-Control"] = "no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response


def _json(data: dict[str, object], status: int) -> HttpResponse:
    return HttpResponse(json.dumps(data), content_type="application/json", status=status)
