"""Parity between `mcp_sql_role_setup --emit-sql` and the hand-written
`sql/role_setup.sql` (TIC-585 review #5).

Both render the same bootstrap shape independently: the command generates it
from `MCP_SQL["PROFILES"]` + `session.session_gucs()`, the static file
is hand-written. They overlap on the CREATE ROLE block, the GUC defaults, and
the membership-GRANT dance — and nothing keeps them in sync but discipline.
These tests pin that overlap so a change to one side (a new GUC default, a
renamed app_role mechanism) fails loudly instead of drifting silently.

The command only reads settings and prints SQL to stdout; one test runs the
values it writes through PostgreSQL.
"""

import re
from io import StringIO
from pathlib import Path

import mcp_sql
import pytest
from django.core.management import call_command
from django.db import connection
from mcp_sql.session import EXPECTED_SESSION_GUCS
from mcp_sql.session import PINNED_SEARCH_PATH

# The package-default profile's role (config.settings.test ships only `default`).
_ROLE = "mcp_readonly_role"
_ROLE_SETUP_SQL = Path(mcp_sql.__file__).resolve().parent / "sql" / "role_setup.sql"

# `ALTER ROLE <role> SET <name> = <value>;` — value optionally quoted, since the
# static file writes booleans unquoted (`= on`) and intervals quoted (`= '5s'`)
# while the generated SQL quotes uniformly (a list element by element:
# `search_path`); both are valid SET syntax. The value class excludes the
# newline so a match cannot span into the next ALTER line and mis-pair name
# with value. Anchored at a line start: the static file carries the
# `search_path` default commented out (`-- ALTER ROLE …`), for pin-enabled
# installs only.
_GUC_RE = re.compile(rf"^ALTER ROLE {_ROLE} SET (\w+) = ([^;\n]+);", re.MULTILINE)
_COMMENTED_GUC_RE = re.compile(
    rf"^-- ALTER ROLE {_ROLE} SET (\w+) = ([^;\n]+);", re.MULTILINE
)


def _gucs(sql: str, pattern: re.Pattern[str] = _GUC_RE) -> dict[str, str]:
    """`{name: value}`, a list value (`public, pg_temp` / `'public',
    'pg_temp'`) normalised to `public, pg_temp`."""
    return {
        name: ", ".join(item.strip().strip("'") for item in value.split(","))
        for name, value in pattern.findall(sql)
    }


@pytest.fixture(params=[False, True], ids=["unpinned", "pinned"])
def pin(request, settings):
    settings.MCP_SQL = {**settings.MCP_SQL, "PIN_SEARCH_PATH": request.param}
    return request.param


def _expected(*, pin: bool) -> dict[str, str]:
    return EXPECTED_SESSION_GUCS | PINNED_SEARCH_PATH if pin else EXPECTED_SESSION_GUCS


def _emit_sql() -> str:
    out = StringIO()
    call_command("mcp_sql_role_setup", emit_sql=True, stdout=out)
    return out.getvalue()


def _static_sql() -> str:
    return _ROLE_SETUP_SQL.read_text()


def test_guc_defaults_agree_across_both_sources(pin):
    """The GUC defaults the generated SQL encodes are exactly the guards the
    read path sets for the install's `PIN_SEARCH_PATH`; the hand-written
    file's active lines are the unpinned set (the default), and its one
    commented-out line is the pinned `search_path`."""
    assert _gucs(_emit_sql()) == _expected(pin=pin)
    assert _gucs(_static_sql()) == EXPECTED_SESSION_GUCS
    assert _gucs(_static_sql(), _COMMENTED_GUC_RE) == PINNED_SEARCH_PATH


def test_the_search_path_default_is_emitted_only_with_the_pin(pin):
    assert ("SET search_path" in _emit_sql()) is pin


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


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("source", "pattern", "expected"),
    [
        (_emit_sql, _GUC_RE, None),
        (_static_sql, _GUC_RE, EXPECTED_SESSION_GUCS),
        (_static_sql, _COMMENTED_GUC_RE, PINNED_SEARCH_PATH),
    ],
    ids=["emitted", "static", "static-commented"],
)
def test_each_default_means_the_guard_value_to_postgres(pin, source, pattern, expected):
    """Each role default, as written (not normalised), sets the value the
    runtime guard expects: `search_path` as a list of two schemas, not one
    schema named `public, pg_temp` (review round 17)."""
    expected = expected if expected is not None else _expected(pin=pin)
    written = dict(pattern.findall(source()))
    assert set(written) == set(expected)
    with connection.cursor() as cur:
        for name, value in written.items():
            cur.execute(f"SET LOCAL {name} = {value}")
            cur.execute(f"SHOW {name}")
            assert cur.fetchone() == (expected[name],), name
