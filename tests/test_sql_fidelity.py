"""The SQL the executor sends to Postgres is the SQL that was checked.

The executor runs sqlglot's re-serialization of the validated AST, not the
agent's text (ledger F32 and its variants). `parser.render_for_execution`
proves the re-serialization re-parses to exactly the validated tree, and
`parse_and_validate` rejects the input forms known to re-serialize wrongly.
These tests pin both on whichever sqlglot is installed (CI runs the 30.7
floor and the newest 30.x), and check literal values and column names
against Postgres itself: the rendered SQL must return what Postgres returns
for the original text.
"""

from unittest.mock import patch

import pytest
import sqlglot
from django.db import connection
from django.db import transaction
from django.utils import timezone
from mcp_sql.executor import run_query
from mcp_sql.models import MCPQueryLog
from mcp_sql.parser import QueryRejectedError
from mcp_sql.parser import parse_and_validate
from mcp_sql.parser import render_for_execution
from mcp_sql.schemas import OutcomeReason
from mcp_sql.session import enter_readonly_session
from mcp_sql.tests.factories import UserFactory
from mcp_sql.tests.test_executor import _DEFAULT_PROFILE
from mcp_sql.tests.test_executor import _stub_readonly_connections
from sqlglot import exp

# Inputs the parser accepts, whose values and column names must survive the
# round trip exactly: backslashes, quotes, Unicode, dollar quoting, quoted
# identifiers and dollar-quoted aliases (which sqlglot turns into plain
# identifiers).
FAITHFUL = [
    "SELECT 'a\\b' AS v",
    "SELECT 'a\\nb' AS v",
    "SELECT '\\' AS v, 'x' AS w",
    "SELECT 'it''s' AS v",
    "SELECT E'it''s' AS v",
    "SELECT E'tab' AS v",
    "SELECT $$it's \\ $$ AS v",
    "SELECT $t$a'b\\c$t$ AS v",
    "SELECT 'zażółć ✓ 𝄞' AS v",
    'SELECT 1 AS "a""b"',
    'SELECT 1 AS "x y -- z"',
    'SELECT 1 AS "MixedCase"',
    'SELECT v FROM (SELECT 1 AS v) AS "s""q"',
    "SELECT 1 AS v /* note */ -- trailing */ , 2 AS smuggled",
]


def _pg(sql: str) -> tuple[list[str], list[tuple]]:
    """Run `sql` the way the executor does (read-only session, rolled back)
    and return (column names, rows)."""
    with transaction.atomic(), connection.cursor() as cur:
        enter_readonly_session(cur, role="mcp_readonly_role")
        cur.execute(sql)
        result = [c.name for c in cur.description], cur.fetchall()
        transaction.set_rollback(True)
    return result


def _rendered(sql: str) -> str:
    parsed = parse_and_validate(sql, allowed_tables=set())
    return render_for_execution(parsed.ast, 11)


@pytest.mark.django_db
class TestValueRoundTrip:
    @pytest.mark.parametrize("sql", FAITHFUL)
    def test_rendered_sql_returns_what_postgres_reads_from_the_original(self, sql):
        assert _pg(_rendered(sql)) == _pg(sql)

    def test_comments_are_not_sent(self):
        # sqlglot rewrites `--` comments as `/* */`; none reach Postgres.
        rendered = _rendered("SELECT 1 AS v /* a */ -- b */ , 2 AS smuggled")
        assert "/*" not in rendered
        assert "smuggled" not in rendered

    def test_unicode_escape_string_never_changes_value(self):
        # `U&'d\0061t'`: sqlglot >= the newest 30.x keeps it as a Unicode
        # string; 30.7 reads it as `U & 'd\0061t'` (a column), which Postgres
        # then refuses. Either the value is exact or nothing runs.
        sql = "SELECT U&'d\\0061t' AS v"
        try:
            rendered = _rendered(sql)
        except QueryRejectedError:
            return
        try:
            got = _pg(rendered)
        except Exception:  # noqa: BLE001 — 30.7: Postgres refuses the column
            return
        assert got == _pg(sql) == (["v"], [("dat",)])


class TestParserRejectsUnfaithfulInput:
    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT E'\\\\' AS v, 'AS w, 1 AS x --' AS y",
            "SELECT E'a\\\\nb' AS v",
            "SELECT E'\\x27' AS v",
            "SELECT E'\\u0027' AS v",
            "SELECT 1 AS $$x, version() AS v$$",
            "SELECT 1 AS $$x; RESET ROLE; SELECT 1 --$$",
            # Plain-looking dollar-quoted aliases too: Postgres refuses them,
            # sqlglot would run them as `AS plain`.
            "SELECT 1 AS $$plain$$",
            "SELECT v FROM (SELECT 1 AS v) AS $t$sub$t$",
            "SELECT 1 AS 'lit'",
            "SELECT 1 AS e'lit'",
        ],
    )
    def test_rejected(self, sql):
        with pytest.raises(QueryRejectedError) as exc:
            parse_and_validate(sql, allowed_tables=set())
        assert exc.value.reason == OutcomeReason.UNSAFE_LITERAL


class TestRoundTripBackstop:
    """`render_for_execution` refuses a tree whose re-serialization does not
    re-parse to it, whatever the parser let through. These trees are built
    by hand, as a future sqlglot or parser gap could produce them."""

    @staticmethod
    def _select(projection: exp.Expression) -> exp.Select:
        return exp.select(projection)

    @pytest.mark.parametrize(
        "projection",
        [
            # An escape string holding one backslash: re-emits as e'\'.
            exp.alias_(exp.ByteString(this="\\"), "v"),
            # An unquoted alias carrying SQL: re-emits as two projections.
            exp.Alias(
                this=exp.Literal.number(1),
                alias=exp.Identifier(this="x, version() AS v", quoted=False),
            ),
            # ... or as a second statement.
            exp.Alias(
                this=exp.Literal.number(1),
                alias=exp.Identifier(this="x; RESET ROLE; SELECT 1", quoted=False),
            ),
        ],
        ids=["escape-string", "alias-projection", "alias-statement"],
    )
    def test_divergent_tree_is_refused(self, projection):
        with pytest.raises(QueryRejectedError) as exc:
            render_for_execution(self._select(projection), 11)
        assert exc.value.reason == OutcomeReason.ROUNDTRIP_MISMATCH

    def test_identifier_case_and_quoting_are_compared(self):
        # sqlglot's own `==` folds case; the check must not.
        tree = sqlglot.parse_one('SELECT 1 AS "Abc"', dialect="postgres")
        with (
            patch(
                "mcp_sql.parser.sqlglot.parse",
                return_value=[sqlglot.parse_one('SELECT 1 AS "abc" LIMIT 11')],
            ),
            pytest.raises(QueryRejectedError) as exc,
        ):
            render_for_execution(tree, 11)
        assert exc.value.reason == OutcomeReason.ROUNDTRIP_MISMATCH

    @pytest.mark.django_db
    def test_run_query_audits_the_refusal_and_runs_nothing(self, monkeypatch):
        cursor = _stub_readonly_connections(monkeypatch)
        monkeypatch.setattr("mcp_sql.parser._same_tree", lambda *_a: False)
        result = run_query(
            user=UserFactory(),
            profile=_DEFAULT_PROFILE,
            raw_sql="SELECT id FROM auth_permission",
        )
        assert result.rejection_reason == OutcomeReason.ROUNDTRIP_MISMATCH.value
        cursor.execute.assert_not_called()
        log = MCPQueryLog.objects.get()
        assert log.decision == MCPQueryLog.DECISION_REJECTED
        assert log.rejection_reason == OutcomeReason.ROUNDTRIP_MISMATCH.value
        assert log.started_at <= timezone.now()
