"""Pure-stock models for the package's own cross-profile tests.

No consumer imports — the package suite must stay extractable. `Widget` is a
trivial managed table; `MCPWidgetSecondProfileView` is an unmanaged handle on a
row- and column-limited curated VIEW. The package ships no migrations for this
app: under the test harness's `--nomigrations --create-db`, the managed table
is built from model state, and the view is created by a fixture
(`CREATE VIEW`) only for the one test that needs the real view to exist.

`TestSession` is the stand-in for a consumer's session-with-user model so the
opt-in session-existence gate (`MCP_SQL["SESSION_MODEL"]`) is exercisable under
the package's standalone settings (stock `django.contrib.sessions.Session` has
no `user` FK and does not qualify).
"""

from django.conf import settings
from django.db import models


class Widget(models.Model):
    """A trivial managed model. `kind` is the row-limiting discriminator the
    second profile's curated view filters on (a stand-in for a consumer's
    per-tier row discriminator)."""

    name = models.CharField(max_length=100)
    kind = models.CharField(max_length=20, default="standard")

    class Meta:
        app_label = "mcp_sql_testapp"

    def __str__(self) -> str:
        return f"Widget #{self.pk}: {self.name} ({self.kind})"


class MCPWidgetSecondProfileView(models.Model):
    """Unmanaged handle on `mcp_widget_second_profile` — a curated VIEW projecting
    only id/name and only `kind = 'second_profile'` rows of `Widget`. Used by the
    cross-profile isolation tests as a second profile's whitelisted object."""

    id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=100)

    class Meta:
        app_label = "mcp_sql_testapp"
        managed = False
        db_table = "mcp_widget_second_profile"

    def __str__(self) -> str:
        return f"Second-profile widget #{self.pk}: {self.name}"


class TestSession(models.Model):
    """Minimal session-with-user model for the runtime session-existence gate.

    Carries exactly the fields the gate and `mcp_session_factory` touch:
    `session_key`, `session_data`, `expire_date`, `user`. The standalone test
    settings point `MCP_SQL["SESSION_MODEL"]` here; the in-tree consumer run
    points it at its own session model instead, so this model just sits unused
    there.
    """

    session_key = models.CharField(max_length=40, unique=True)
    session_data = models.TextField(blank=True)
    expire_date = models.DateTimeField(db_index=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    class Meta:
        app_label = "mcp_sql_testapp"

    def __str__(self) -> str:
        return f"TestSession {self.session_key} for user #{self.user_id}"
