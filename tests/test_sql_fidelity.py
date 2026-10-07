"""The SQL the executor sends to Postgres is the SQL that was checked.

The executor runs sqlglot's rendering of the validated AST, not the agent's
text (ledger F32 and its variants). `parser.render_for_execution` runs the
full validation on the rendered text and requires it to re-render to the
same string, and `parse_and_validate` rejects the source forms sqlglot and
Postgres read differently. These tests pin both on whichever sqlglot is
installed (CI runs the 30.7 floor and the newest 30.x), and check values and
column names against Postgres itself: the rendered SQL must return what
Postgres returns for the original text. (The guarantee is about what
sqlglot reads; where its lexer and Postgres's disagree on a form, the
parser refuses that form — the cases below.)
"""

import pytest
import sqlglot
from django.db import DatabaseError
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
    # Function names keep the case they were written in.
    "SELECT Lower('AbC') AS v, UPPER('x') AS w, length('abc') AS n",
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
    return render_for_execution(parsed.ast, 11, allowed_tables=set())


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


def _pg_or_error(sql: str):
    """`_pg(sql)`, or the Postgres error text if it refuses the statement."""
    try:
        return _pg(sql)
    except DatabaseError as exc:
        return f"ERROR: {str(exc).splitlines()[0]}"


@pytest.mark.django_db
class TestPostgresReadsTheSourceDifferently:
    """Source text sqlglot reads (and would re-emit) differently from how
    Postgres reads it is refused before any check, on every sqlglot. Each
    case also shows, against Postgres itself, why: the original text and
    sqlglot's naive re-emission do not give the same answer."""

    @pytest.mark.parametrize(
        "sql",
        [
            # sqlglot folds a quoted name onto its builtin `LOWER`; Postgres
            # looks up the case-sensitive "Lower", which does not exist.
            "SELECT \"Lower\"('AbC') AS v",
            "SELECT \"Upper\"('AbC') AS v",
        ],
    )
    def test_quoted_function_name(self, sql):
        naive = sqlglot.parse_one(sql, dialect="postgres").sql(dialect="postgres")
        assert _pg_or_error(naive) != _pg_or_error(sql)
        with pytest.raises(QueryRejectedError) as exc:
            parse_and_validate(sql, allowed_tables=set())
        assert exc.value.reason == OutcomeReason.UNSAFE_LITERAL

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT name FROM (SELECT 0 AS name, 5 AS u) s WHERE name = U&'2'",
            "SELECT (U&'2' = '2') AS ok FROM (SELECT 5 AS u) s",
            "SELECT U&'d\\0061t' AS v",
            'SELECT U&"d\\0061t" AS v FROM (SELECT 1 AS dat, 2 AS u) s',
        ],
        ids=["where", "comparison", "value", "identifier"],
    )
    def test_unicode_escape(self, sql):
        naive = sqlglot.parse_one(sql, dialect="postgres").sql(dialect="postgres")
        if "U&" not in naive.replace("u&", "U&"):
            # sqlglot 30.7 splits it into `U & '...'`: a different query.
            assert _pg_or_error(naive) != _pg_or_error(sql)
        with pytest.raises(QueryRejectedError) as exc:
            parse_and_validate(sql, allowed_tables=set())
        assert exc.value.reason == OutcomeReason.UNSAFE_LITERAL


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


class TestRenderedTextIsValidated:
    """`render_for_execution` validates the rendered text itself and refuses
    an unstable rendering, whatever the parser let through. The trees are
    built by hand, as a future sqlglot or parser gap could produce them."""

    @staticmethod
    def _select(projection: exp.Expression) -> exp.Select:
        return exp.select(projection)

    @pytest.mark.parametrize(
        "projection",
        [
            # An escape string holding one backslash: renders as e'\', which
            # does not even tokenize.
            exp.alias_(exp.ByteString(this="\\"), "v"),
            # An unquoted alias carrying SQL: renders as a denied function...
            exp.Alias(
                this=exp.Literal.number(1),
                alias=exp.Identifier(this="x, version() AS v", quoted=False),
            ),
            # ... as a second statement ...
            exp.Alias(
                this=exp.Literal.number(1),
                alias=exp.Identifier(this="x; RESET ROLE; SELECT 1", quoted=False),
            ),
            # ... or as a read of a table off the whitelist.
            exp.Alias(
                this=exp.Literal.number(1),
                alias=exp.Identifier(this="x FROM secret_table --", quoted=False),
            ),
        ],
        ids=["escape-string", "denied-function", "second-statement", "table"],
    )
    def test_a_rendering_that_fails_validation_is_refused(self, projection):
        with pytest.raises(QueryRejectedError) as exc:
            render_for_execution(self._select(projection), 11, allowed_tables=set())
        assert exc.value.reason == OutcomeReason.ROUNDTRIP_MISMATCH

    def test_a_valid_rendering_runs_as_rendered(self):
        # What runs is the rendered text, and it is what was validated:
        # here a harmless extra projection, which passes every check.
        tree = self._select(
            exp.Alias(
                this=exp.Literal.number(1),
                alias=exp.Identifier(this="x, 2 AS y", quoted=False),
            )
        )
        assert (
            render_for_execution(tree, 11, allowed_tables=set())
            == "SELECT 1 AS x, 2 AS y LIMIT 11"
        )

    def test_an_unstable_rendering_is_refused(self, monkeypatch):
        renders = iter(f"SELECT {n} AS v LIMIT 11" for n in range(10))
        monkeypatch.setattr("mcp_sql.parser._render", lambda _tree: next(renders))
        tree = sqlglot.parse_one("SELECT 1 AS v", dialect="postgres")
        with pytest.raises(QueryRejectedError) as exc:
            render_for_execution(tree, 11, allowed_tables=set())
        assert exc.value.reason == OutcomeReason.ROUNDTRIP_MISMATCH
        assert "not stable" in exc.value.detail

    def test_a_rendering_that_settles_on_the_second_round_runs(self, monkeypatch):
        # The executed text is the settled one, and it passed validation.
        renders = iter(
            [
                "SELECT 1 AS v LIMIT 11",
                "SELECT 1 AS w LIMIT 11",
                "SELECT 1 AS w LIMIT 11",
            ]
        )
        monkeypatch.setattr("mcp_sql.parser._render", lambda _tree: next(renders))
        tree = sqlglot.parse_one("SELECT 1 AS v", dialect="postgres")
        assert (
            render_for_execution(tree, 11, allowed_tables=set())
            == "SELECT 1 AS w LIMIT 11"
        )

    @pytest.mark.parametrize(
        "sql",
        [
            # sqlglot cannot express these in Postgres; by default it would
            # drop the clause with a warning and run something else.
            "SELECT first_value(x) IGNORE NULLS OVER (ORDER BY x) AS f "
            "FROM (SELECT 1 AS x) s",
            "SELECT initcap('a-b', '-') AS v",
            # Not Postgres SQL: sqlglot rewrites QUALIFY into a subquery with
            # the LIMIT applied before the window filter.
            "SELECT x FROM (SELECT 1 AS x) s QUALIFY row_number() OVER "
            "(ORDER BY x) = 1",
        ],
        ids=["ignore-nulls", "initcap-delimiter", "qualify"],
    )
    def test_a_rendering_that_drops_meaning_is_refused(self, sql):
        parsed = parse_and_validate(sql, allowed_tables=set())
        with pytest.raises(QueryRejectedError) as exc:
            render_for_execution(parsed.ast, 11, allowed_tables=set())
        assert exc.value.reason == OutcomeReason.ROUNDTRIP_MISMATCH

    @pytest.mark.django_db
    def test_run_query_audits_the_refusal_and_runs_nothing(self, monkeypatch):
        cursor = _stub_readonly_connections(monkeypatch)
        monkeypatch.setattr(
            "mcp_sql.parser._render", lambda _tree: "SELECT 1 FROM pg_class"
        )
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


# Common analytic shapes over an inline VALUES table. Each must be accepted on
# both supported sqlglot versions, and its rendered SQL must return exactly
# what Postgres returns for the original text. Several are rewritten by
# sqlglot on the way (a CAST in ROUND(AVG(..), n), an expanded window frame,
# SOME -> ANY, date_part -> EXTRACT on 30.7), which the earlier exact-tree
# gate refused.
_DATA = (
    "WITH t AS ("
    "SELECT 1.5 AS x, 2 AS y, 'a' AS g, DATE '2024-01-01' AS d, "
    "'{\"k\": 1}'::jsonb AS j "
    "UNION ALL SELECT 2.5, 3, 'b', DATE '2024-02-15', '{\"k\": 2}'::jsonb "
    "UNION ALL SELECT 4.0, 5, 'a', DATE '2024-03-31', '{\"k\": 3}'::jsonb) "
)
ANALYTIC_CORPUS = [
    "SELECT ROUND(AVG(x), 2) AS a FROM t",
    "SELECT ROUND(STDDEV(x), 3) AS s, ROUND(VARIANCE(y)::numeric, 3) AS v FROM t",
    "SELECT g, SUM(y) OVER (ORDER BY d ROWS 1 PRECEDING) AS r FROM t ORDER BY d",
    "SELECT g, SUM(y) OVER (PARTITION BY g ORDER BY d ROWS BETWEEN UNBOUNDED "
    "PRECEDING AND CURRENT ROW) AS r FROM t ORDER BY d",
    "SELECT y FROM t WHERE y > SOME (SELECT y FROM t WHERE g = 'b') ORDER BY y",
    "SELECT y FROM t WHERE y = ANY (ARRAY[2, 5]) ORDER BY y",
    "SELECT date_part('year', d) AS yr, EXTRACT(MONTH FROM d) AS mo FROM t ORDER BY d",
    "SELECT date_trunc('month', d)::date AS m, COUNT(*) AS n FROM t GROUP BY 1 "
    "ORDER BY 1",
    "SELECT g, COUNT(*) FILTER (WHERE y > 2) AS n FROM t GROUP BY g ORDER BY g",
    "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY x) AS med FROM t",
    "SELECT string_agg(g, ',' ORDER BY d) AS gs, array_agg(DISTINCT g) AS a FROM t",
    "SELECT COALESCE(NULLIF(g, 'a'), '-') AS g2, GREATEST(x, y) AS m FROM t ORDER BY d",
    "SELECT CASE WHEN y > 2 THEN 'hi' ELSE 'lo' END AS c FROM t ORDER BY d",
    "SELECT j ->> 'k' AS k, j @> '{\"k\": 2}' AS has2 FROM t ORDER BY d",
    "SELECT DISTINCT ON (g) g, d FROM t ORDER BY g, d DESC",
    "SELECT g, y, rank() OVER (PARTITION BY g ORDER BY y DESC) AS r, lag(y) "
    "OVER (ORDER BY d) AS p FROM t ORDER BY d",
    "SELECT to_char(d, 'YYYY-MM') AS ym, d + INTERVAL '1 day' AS next FROM t "
    "ORDER BY d",
    "SELECT y % 2 AS odd, y ^ 2 AS sq, round(x::numeric, 1) AS r FROM t ORDER BY d",
    "SELECT g FROM t WHERE g ILIKE 'A%' AND x BETWEEN 1 AND 3 ORDER BY d",
    "SELECT g, MAX(y) AS m FROM t GROUP BY g HAVING MAX(y) > 2 ORDER BY g",
    "SELECT y FROM t UNION ALL SELECT y FROM t ORDER BY 1",
    "SELECT EXISTS (SELECT 1 FROM t WHERE y > 4) AS e",
    "SELECT d - DATE '2024-01-01' AS days, now() > d AS past FROM t ORDER BY d",
]


@pytest.mark.django_db
class TestAnalyticCorpus:
    @pytest.mark.parametrize("body", ANALYTIC_CORPUS)
    def test_accepted_and_returns_what_postgres_reads(self, body):
        sql = _DATA + body
        assert _pg(_rendered(sql)) == _pg(sql)
