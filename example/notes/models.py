from django.conf import settings
from django.db import models


class Note(models.Model):
    """A trivial demo model on the MCP whitelist.

    The point is to give `run_query` something visibly useful to read
    against an example app. No business meaning beyond demonstration.
    """

    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notes",
    )
    title = models.CharField(max_length=200)
    body = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self) -> str:
        return f"Note #{self.pk}: {self.title}"


class MCPNoteSecondProfileView(models.Model):
    """Curated `mcp_note_second_profile` VIEW — the demonstrator for TIC-585
    per-role row + column limiting.

    The `second_profile` tier's role (`mcp_ro_second_profile`) gets SELECT on
    this view ONLY, never on `notes_note`. The view's static
    `WHERE left(title, 1) = 'S'` is the row boundary, and its projection
    (no `body`, no `author_id`) is the column boundary — so this tier can
    read neither the rows nor the columns the `default` tier sees on the full
    table. `managed = False`: the view DDL lives in
    `notes/migrations/0002_mcp_second_profile_view.py` (the curated-view pattern;
    see `source/mcp_sql/CLAUDE.md`). Field set must match that migration's
    `state_operations` CreateModel and the view's column list exactly — the
    `grants._verify_view_parity` check enforces it.
    """

    id = models.BigAutoField(primary_key=True)
    title = models.CharField(max_length=200)
    created_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = "mcp_note_second_profile"

    def __str__(self) -> str:
        return f"Second-profile note #{self.pk}: {self.title}"
