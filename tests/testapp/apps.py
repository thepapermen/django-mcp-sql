from django.apps import AppConfig


class McpSqlTestAppConfig(AppConfig):
    """Stock Django app used only by the mcp_sql package's own tests.

    Loaded into `config.settings.test`'s INSTALLED_APPS so the cross-profile
    tests can configure a multi-profile MCP_SQL against real, pure-stock
    models — without importing any consumer models, keeping the
    package's extraction seam real.
    """

    name = "mcp_sql.tests.testapp"
    label = "mcp_sql_testapp"
    default_auto_field = "django.db.models.BigAutoField"
