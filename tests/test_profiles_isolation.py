"""Cross-profile isolation (TIC-585): a profile sees only its own whitelist.

Two layers:
  * logical/whitelist isolation (primary, pure-Python): each profile resolves
    only its own tables, and the parser rejects a table outside the bound
    profile's whitelist;
  * one DB-enforced integration test: a real read-only role lacking a SELECT
    grant is denied by Postgres (SQLSTATE 42501).
"""

import secrets

import pytest
from django.db import connection

from mcp_sql import grants
from mcp_sql.executor import pgcode
from mcp_sql.parser import QueryRejectedError
from mcp_sql.parser import parse_and_validate
from mcp_sql.schemas import OutcomeReason
from mcp_sql.session import enter_readonly_session

pytestmark = pytest.mark.django_db

_WIDGET_TABLE = "mcp_sql_testapp_widget"
_AUDIT_TABLE = "mcp_sql_mcpquerylog"


def test_profiles_resolve_disjoint_whitelists(two_profiles):
    default_tables = set(grants.declared_tables(two_profiles["default"]).values())
    second_tables = set(grants.declared_tables(two_profiles["second_profile"]).values())
    assert _WIDGET_TABLE in default_tables
    # The second profile sees the curated view, never the full Widget table.
    assert _WIDGET_TABLE not in second_tables
    assert "mcp_widget_second_profile" in second_tables


def test_parser_rejects_table_outside_bound_profile(two_profiles):
    """A query for the default tier's table, validated against the
    second profile's whitelist, is rejected DISALLOWED_TABLE — the per-profile
    whitelist plumbing the executor uses (`declared_tables(profile)`)."""
    allowed = set(grants.declared_tables(two_profiles["second_profile"]).values())
    with pytest.raises(QueryRejectedError) as exc:
        parse_and_validate(
            f"SELECT id FROM {_WIDGET_TABLE}",  # noqa: S608 — trusted test table name
            allowed_tables=allowed,
        )
    assert exc.value.reason == OutcomeReason.DISALLOWED_TABLE


def test_db_role_denied_ungranted_table():
    """DB-enforced: a read-only role granted SELECT on one table only is
    denied (42501) on a table it was not granted — the actual access boundary
    behind the whitelist. Requires a superuser test connection (kartoza); skips
    otherwise. The role is created inside the test's transaction and rolls back
    with it, so nothing leaks into the cluster-global role namespace."""
    with connection.cursor() as cur:
        cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        is_superuser = bool(cur.fetchone()[0])
    if not is_superuser:
        pytest.skip("test DB user is not a superuser; cannot create roles / SET ROLE")

    role = "mcp_iso_" + secrets.token_hex(6)
    with connection.cursor() as cur:
        cur.execute(f"CREATE ROLE {role} NOLOGIN")
        cur.execute(f'GRANT SELECT ON "{_WIDGET_TABLE}" TO {role}')
        # A superuser can SET ROLE into any role without explicit membership.
        enter_readonly_session(cur, role=role)
        # Granted table: readable.
        cur.execute(f'SELECT 1 FROM "{_WIDGET_TABLE}" LIMIT 0')  # noqa: S608
        # Ungranted table: Postgres denies with insufficient_privilege.
        with pytest.raises(Exception) as exc:  # noqa: PT011 — assert on pgcode below
            cur.execute(f'SELECT 1 FROM "{_AUDIT_TABLE}" LIMIT 0')  # noqa: S608
    assert pgcode(exc.value) == "42501"


@pytest.fixture
def second_profile_widget_view(db):
    """Create the row- + column-limited `mcp_widget_second_profile` VIEW the
    second profile's unmanaged model maps to (the package's stand-in for
    a consumer's curated per-role view). Dropped on teardown."""
    # Plain literal (no f-string) so ruff's S608 SQL-injection heuristic does
    # not trip — the table name is a fixed test constant equal to _WIDGET_TABLE.
    sql = (
        "CREATE OR REPLACE VIEW mcp_widget_second_profile AS "
        'SELECT id, name FROM "mcp_sql_testapp_widget" '
        "WHERE kind = 'second_profile'"
    )
    with connection.cursor() as cur:
        cur.execute(sql)
    yield
    with connection.cursor() as cur:
        cur.execute("DROP VIEW IF EXISTS mcp_widget_second_profile")


def test_second_profile_view_limits_rows_and_columns(second_profile_widget_view):
    """The curated view is the per-role boundary: it exposes only
    `kind='second_profile'` rows (row limit) and only id/name (column limit) of
    the underlying Widget table."""
    from mcp_sql.tests.testapp.models import MCPWidgetSecondProfileView
    from mcp_sql.tests.testapp.models import Widget

    Widget.objects.create(name="w1", kind="second_profile")
    Widget.objects.create(name="w2", kind="standard")

    visible = list(MCPWidgetSecondProfileView.objects.all())
    # Row limit: the standard-kind widget is invisible through the view.
    assert [w.name for w in visible] == ["w1"]
    # Column limit: the view (and its unmanaged model) expose only id + name —
    # no `kind`, no other base column.
    assert {f.column for f in MCPWidgetSecondProfileView._meta.fields} == {
        "id",
        "name",
    }


def test_executor_end_to_end_rejects_table_outside_bound_profile(
    two_profiles, monkeypatch
):
    """Integrated pipeline lock (the layer tests above each pass alone even
    if the wiring between them regresses): `run_query` bound to the NARROW
    profile, against a table only the default profile whitelists, must
    reject with `DISALLOWED_TABLE` and write one audit row attributed to the
    narrow profile. An executor that accidentally consulted the wrong
    profile's whitelist would slip through every per-layer test."""
    from unittest.mock import MagicMock

    from mcp_sql.executor import run_query
    from mcp_sql.models import MCPQueryLog
    from mcp_sql.tests.factories import UserFactory

    # The readonly alias is absent under test settings; satisfy the
    # alias-presence preflight only — the parser rejects before any cursor
    # would be opened, which the mock also pins (no execute calls).
    mock_conns = MagicMock()
    mock_conns.databases = {"default": {}, "mcp_readonly": {}}
    # Keep the alias defense satisfied too, so if the guarded regression ever
    # happens (parse passes against the wrong whitelist) this test fails on
    # the DISALLOWED_TABLE assertion below — not on an unrelated
    # ExecutorMisconfiguredError from the MagicMock's auto-attr alias.
    mock_conns.__getitem__.return_value.alias = "mcp_readonly"
    monkeypatch.setattr("mcp_sql.executor.connections", mock_conns)

    narrow = two_profiles["second_profile"]
    result = run_query(
        user=UserFactory(),
        profile=narrow,
        raw_sql=f"SELECT id FROM {_WIDGET_TABLE}",  # noqa: S608 — trusted test table name
    )

    assert result.rejection_reason == OutcomeReason.DISALLOWED_TABLE.value
    log = MCPQueryLog.objects.get()
    assert log.decision == MCPQueryLog.DECISION_REJECTED
    assert log.rejection_reason == OutcomeReason.DISALLOWED_TABLE.value
    assert log.profile == "second_profile"
    # The rejection happened at the parser layer — nothing reached a cursor.
    assert not mock_conns.__getitem__.return_value.cursor.called
