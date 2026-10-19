from django.apps import AppConfig
from django.db.backends.signals import connection_created


class CoreConfig(AppConfig):
    name = "yk_portal.core"

    def ready(self) -> None:
        from . import db

        db.register()
        connection_created.connect(db.add_sqlite_functions)
