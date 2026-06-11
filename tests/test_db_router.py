import pytest
from mcp_sql.db_router import McpSqlRouter
from mcp_sql.models import MCPQueryLog


@pytest.fixture
def router():
    return McpSqlRouter()


class TestMcpSqlRouter:
    def test_read_only_alias_is_never_migrated(self, router):
        # The one invariant the router owns: no app builds or tracks schema
        # on the read-only execution alias (a lens onto a DB `default` owns,
        # or a replica) — not mcp_sql's own tables, not the consumer's.
        assert router.allow_migrate("mcp_readonly", "mcp_sql") is False
        assert router.allow_migrate("mcp_readonly", "users") is False

    def test_abstains_everywhere_else(self, router):
        # None = "no opinion": Django allows the migration and uses `default`.
        # The router bakes in no consumer-topology assumption (no literal
        # "default" home for mcp_sql's own tables).
        assert router.allow_migrate("default", "mcp_sql") is None
        assert router.allow_migrate("default", "users") is None

    def test_audit_objects_create_lands_on_default(self, db):
        # With the router abstaining on writes, Django's fallback routes the
        # ORM write to `default`; the migrate ban keeps the table off the
        # read alias regardless.
        from mcp_sql.tests.factories import UserFactory

        user = UserFactory()
        log = MCPQueryLog.objects.create(
            user=user,
            decision=MCPQueryLog.DECISION_ALLOWED,
            raw_sql="SELECT 1",
            started_at="2026-05-10T00:00:00+00:00",
        )
        assert MCPQueryLog.objects.using("default").filter(pk=log.pk).exists()
