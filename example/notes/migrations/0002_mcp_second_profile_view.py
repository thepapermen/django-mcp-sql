# Curated-view migration for the `second_profile` demonstrator profile.
# Creates `mcp_note_second_profile`, a row- AND column-limited VIEW over
# `notes_note`: only titles beginning with "S", projecting id/title/created_at
# (no body, no author_id). The `second_profile` role gets SELECT on this view via
# `mcp_sql_grants --apply` (the view is on that profile's ALLOWED_MODELS); it
# never gets SELECT on `notes_note`. Two mandatory invariants of the pattern
# (see source/mcp_sql/CLAUDE.md "Curated-view pattern"):
#   * forward SQL is CREATE OR REPLACE VIEW (retry-idempotent for additive
#     changes); reverse is DROP VIEW IF EXISTS;
#   * RunSQL carries state_operations=[CreateModel(..., managed=False)] so the
#     migration state graph knows the unmanaged model and makemigrations stays
#     quiet. The field set mirrors notes.MCPNoteSecondProfileView and the view's
#     column list exactly (grants._verify_view_parity enforces it).

from django.db import migrations
from django.db import models

CREATE_SQL = """
CREATE OR REPLACE VIEW mcp_note_second_profile AS
SELECT id, title, created_at
FROM notes_note
WHERE left(title, 1) = 'S';
"""

DROP_SQL = "DROP VIEW IF EXISTS mcp_note_second_profile;"


class Migration(migrations.Migration):
    dependencies = [
        ("notes", "0001_initial"),
    ]

    operations = [
        migrations.RunSQL(
            sql=CREATE_SQL,
            reverse_sql=DROP_SQL,
            state_operations=[
                migrations.CreateModel(
                    name="MCPNoteSecondProfileView",
                    fields=[
                        (
                            "id",
                            models.BigAutoField(primary_key=True, serialize=False),
                        ),
                        ("title", models.CharField(max_length=200)),
                        ("created_at", models.DateTimeField()),
                    ],
                    options={
                        "managed": False,
                        "db_table": "mcp_note_second_profile",
                    },
                ),
            ],
        ),
    ]
