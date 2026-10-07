"""Acceptance test: the SQL surface stays fully functional for analytics.

Every query in `sql_functional_corpus.FUNCTIONAL` — aggregates, grouping
sets, window functions, CTEs, joins (LATERAL included), subqueries, CASE,
casts, date/time, string, pattern, JSON and array functions, set operations,
DISTINCT / ORDER BY / LIMIT, plus the reviewers' corpora — runs end to end
through `run_query` on real Postgres as the read role, against whitelisted
test tables, and must:

1. be accepted (no rejection reason, nothing truncated), and
2. return exactly the columns and rows Postgres returns for the original
   text run directly as the read role.

Both sides run inside the test's transaction, so `now()` is the same value.
Rows are compared by `repr` (so `2024` is not `2024.0`), in order when the
query has a top-level ORDER BY and as a multiset otherwise. The executor's
per-cell coercion (`_cap_cell`) is applied to the direct rows too, since
`run_query` returns JSON-ready cells. Entries in `MIN_SERVER_VERSION` are
skipped on an older Postgres.

`sql_functional_corpus.POSTGRES_REJECTS` must fail in Postgres through
`run_query` as they do when run directly (run as written, not translated
into something that runs). `sql_functional_corpus.REFUSED` pins the queries
from the same corpora the package refuses, with the reason, so the boundary
stays visible.
"""

import pytest
import sqlglot
from django.db import DatabaseError
from django.db import connection
from django.db import transaction
from mcp_sql.executor import _cap_cell
from mcp_sql.executor import run_query
from mcp_sql.parser import FaithfulPostgres
from mcp_sql.parser import QueryRejectedError
from mcp_sql.parser import parse_and_validate
from mcp_sql.parser import render_for_execution
from mcp_sql.schemas import OutcomeReason
from mcp_sql.session import enter_readonly_session
from mcp_sql.tests.factories import UserFactory
from mcp_sql.tests.sql_functional_corpus import FUNCTIONAL
from mcp_sql.tests.sql_functional_corpus import MIN_SERVER_VERSION
from mcp_sql.tests.sql_functional_corpus import POSTGRES_REJECTS
from mcp_sql.tests.sql_functional_corpus import REFUSED
from mcp_sql.tests.sql_functional_corpus import SETUP_SQL
from mcp_sql.tests.test_executor import _DEFAULT_PROFILE

_TABLES = {"t": "t", "u": "u"}
_ROW_LIMIT = 1000


@pytest.fixture(scope="module")
def corpus_tables(django_db_setup, django_db_blocker):
    """The corpus tables, readable by the read role, for this module."""
    with django_db_blocker.unblock(), connection.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS t, u")
        for statement in filter(str.strip, SETUP_SQL.split(";\n")):
            cur.execute(statement)
        cur.execute(f"GRANT SELECT ON t, u TO {_DEFAULT_PROFILE.role}")
    yield
    with django_db_blocker.unblock(), connection.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS t, u")


@pytest.fixture
def executor_on_corpus(settings, monkeypatch, corpus_tables):
    # Execute on the test database, with room for every corpus result.
    settings.MCP_SQL = {
        **settings.MCP_SQL,
        "DB_ALIAS": "default",
        "LIMITS": {
            "DEFAULT_LIMIT": _ROW_LIMIT,
            "HARD_LIMIT": _ROW_LIMIT,
            "BYTES_LIMIT": 16 * 1024 * 1024,
        },
    }
    monkeypatch.setattr("mcp_sql.executor.declared_tables", lambda _profile: _TABLES)


def _direct(sql: str) -> tuple[list[str], list[list[object]]]:
    """`sql` as written, run as the read role (rolled back)."""
    with transaction.atomic(), connection.cursor() as cur:
        enter_readonly_session(cur, role=_DEFAULT_PROFILE.role)
        cur.execute(sql)
        columns = [c.name for c in cur.description]
        rows = [[_cap_cell(v) for v in row] for row in cur.fetchall()]
        transaction.set_rollback(True)
    return columns, rows


def _is_ordered(sql: str) -> bool:
    return (
        sqlglot.parse_one(sql, dialect=FaithfulPostgres).args.get("order") is not None
    )


@pytest.mark.django_db
@pytest.mark.usefixtures("executor_on_corpus")
@pytest.mark.parametrize(
    "sql", [sql for _category, sql in FUNCTIONAL], ids=[c for c, _ in FUNCTIONAL]
)
def test_query_runs_unchanged(sql):
    _skip_if_server_too_old(sql)
    result = run_query(
        user=UserFactory(), profile=_DEFAULT_PROFILE, raw_sql=sql, limit=_ROW_LIMIT
    )
    assert result.rejection_reason == "", (result.rejection_reason, result.error)
    assert not result.truncated
    columns, rows = _direct(sql)
    assert result.columns == columns
    got, expected = list(map(repr, result.rows)), list(map(repr, rows))
    if _is_ordered(sql):
        assert got == expected
    else:
        assert sorted(got) == sorted(expected)


@pytest.mark.django_db
@pytest.mark.usefixtures("executor_on_corpus")
@pytest.mark.parametrize("sql", POSTGRES_REJECTS)
def test_query_postgres_rejects_fails_in_postgres(sql):
    result = run_query(
        user=UserFactory(), profile=_DEFAULT_PROFILE, raw_sql=sql, limit=_ROW_LIMIT
    )
    assert result.rejection_reason == OutcomeReason.EXECUTION_ERROR, (
        result.rejection_reason,
        result.error,
    )
    with pytest.raises(DatabaseError):
        _direct(sql)


def _skip_if_server_too_old(sql: str) -> None:
    needed = MIN_SERVER_VERSION.get(sql)
    if needed is not None and connection.pg_version < needed:
        pytest.skip(f"needs PostgreSQL {needed // 10000}+")


@pytest.mark.parametrize(
    ("reason", "sql"), REFUSED, ids=[reason for reason, _ in REFUSED]
)
def test_refused_query_stays_refused(reason, sql):
    # The parser refuses most; `roundtrip_mismatch` ones fail at rendering
    # (not Postgres SQL: sqlglot cannot express them in Postgres).
    with pytest.raises(QueryRejectedError) as exc:
        _parse_and_render(sql)
    assert exc.value.reason == reason


def _parse_and_render(sql: str) -> str:
    parsed = parse_and_validate(sql, allowed_tables=set(_TABLES))
    return render_for_execution(parsed.ast, _ROW_LIMIT, allowed_tables=set(_TABLES))
