"""Parity between `mcp_sql_role_setup --emit-sql` and the hand-written
`sql/role_setup.sql` (TIC-585 review #5).

Both render the same bootstrap shape independently: the command generates it
from `MCP_SQL["PROFILES"]` + `session.EXPECTED_SESSION_GUCS`, the static file
is hand-written. They overlap on the CREATE ROLE block, the GUC defaults, and
the membership-GRANT dance — and nothing keeps them in sync but discipline.
These tests pin that overlap so a change to one side (a new GUC default, a
renamed app_role mechanism) fails loudly instead of drifting silently.

No DB: the command only reads settings and prints SQL to stdout.
"""

import re
from io import StringIO
from pathlib import Path

from django.core.management import call_command

import mcp_sql
from mcp_sql.session import EXPECTED_SESSION_GUCS

# The package-default profile's role (config.settings.test ships only `default`).
_ROLE = "mcp_readonly_role"
_ROLE_SETUP_SQL = Path(mcp_sql.__file__).resolve().parent / "sql" / "role_setup.sql"

# `ALTER ROLE <role> SET <name> = <value>;` — value optionally quoted, since the
# static file writes booleans unquoted (`= on`) and intervals quoted (`= '5s'`)
# while the generated SQL quotes uniformly; both are valid SET syntax. The value
# class excludes whitespace (`[^\s';]`, not `[^';]`) so a match cannot span the
# newline into the next ALTER line and mis-pair name with value.
_GUC_RE = re.compile(rf"ALTER ROLE {_ROLE} SET (\w+) = '?([^\s';]+)'?;")


def _emit_sql() -> str:
    out = StringIO()
    call_command("mcp_sql_role_setup", emit_sql=True, stdout=out)
    return out.getvalue()


def _static_sql() -> str:
    return _ROLE_SETUP_SQL.read_text()


def test_guc_defaults_agree_across_both_sources():
    """The GUC defaults encoded by the generated SQL and by the hand-written
    file are each exactly `session.EXPECTED_SESSION_GUCS` — the single source
    both must track."""
    assert dict(_GUC_RE.findall(_emit_sql())) == EXPECTED_SESSION_GUCS
    assert dict(_GUC_RE.findall(_static_sql())) == EXPECTED_SESSION_GUCS


def test_create_role_block_shape_matches():
    """Both create the role idempotently (NOLOGIN, swallowing duplicate_object)."""
    emitted, static = _emit_sql(), _static_sql()
    for fragment in (f"CREATE ROLE {_ROLE} NOLOGIN;", "WHEN duplicate_object THEN"):
        assert fragment in emitted
        assert fragment in static


def test_membership_grant_shape_matches():
    """Both move the app role onto a LOCAL GUC and GRANT membership inside a DO
    block (psql can't substitute `:'app_role'` inside `DO $$`), with an
    undefined_object fallback NOTICE."""
    emitted, static = _emit_sql(), _static_sql()
    for fragment in (
        "SET LOCAL mcp_sql.app_role = :'app_role';",
        f"EXECUTE format('GRANT {_ROLE} TO %I', target_role);",
        "WHEN undefined_object THEN",
    ):
        assert fragment in emitted
        assert fragment in static
