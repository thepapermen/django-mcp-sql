"""The hand-written `REVOKE SELECT ... FROM mcp_readonly_role` migrations.

The suite runs with `--nomigrations`, so nothing else executes these
`RunSQL` operations before a real `migrate`. Each package table must stay
unreadable to the read role even after a broad grant (the threat 0002 /
0008 / 0013 defend against: `GRANT SELECT ON ALL TABLES` or `ALTER DEFAULT
PRIVILEGES ... TO mcp_readonly_role`). Here the grant is issued, the
migration's own SQL is run, and the privilege is checked.
"""

import importlib

import pytest
from django.db import connection
from django.db import migrations

_ROLE = "mcp_readonly_role"


def _revoke_sql(module_name: str) -> list[str]:
    module = importlib.import_module(f"mcp_sql.migrations.{module_name}")
    return [
        op.sql
        for op in module.Migration.operations
        if isinstance(op, migrations.RunSQL) and "REVOKE SELECT" in op.sql
    ]


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("module_name", "table"),
    [
        ("0002_revoke_audit_grants", "mcp_sql_mcpquerylog"),
        ("0008_revoke_mcpauthrejectionlog_grants", "mcp_sql_mcpauthrejectionlog"),
        ("0013_refresh_token_family", "mcp_sql_mcprefreshtokenfamily"),
    ],
)
def test_migration_revokes_select_from_the_read_role(module_name, table):
    statements = _revoke_sql(module_name)
    assert len(statements) == 1, f"{module_name} lost its REVOKE RunSQL"
    with connection.cursor() as cur:
        cur.execute(f"GRANT SELECT ON {table} TO {_ROLE}")
        cur.execute("SELECT has_table_privilege(%s, %s, 'SELECT')", [_ROLE, table])
        assert cur.fetchone() == (True,)
        cur.execute(statements[0])
        cur.execute("SELECT has_table_privilege(%s, %s, 'SELECT')", [_ROLE, table])
        assert cur.fetchone() == (False,)
