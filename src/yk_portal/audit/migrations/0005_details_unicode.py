"""details is written with its non-ASCII characters, not as \\u escapes, so the audit
log's search finds them on SQLite as on PostgreSQL (addendum §18.3).

Only the model changes: the column stays the same. A plain AlterField would make
SQLite rebuild audit_events, dropping the immutability triggers of migration 0004.
Events written before keep their escapes.
"""

from django.db import migrations, models

import yk_portal.core.db


class Migration(migrations.Migration):
    dependencies = [
        ("audit", "0004_immutable"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AlterField(
                    model_name="auditevent",
                    name="details",
                    field=models.JSONField(
                        blank=True, default=dict, encoder=yk_portal.core.db.UnicodeJSONEncoder
                    ),
                ),
            ],
        ),
    ]
