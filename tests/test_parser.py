"""Unit tests for `mcp_sql.parser`.

Pure AST-layer tests: no DB, no Django fixtures. Every rejection path has
a representative SQL example so the `OutcomeReason` vocabulary stays
exercised; happy paths cover JOIN, CTE, aggregation, ORDER BY, subquery,
UNION, and qualified column references to prove the validator doesn't
over-reject normal SELECT shapes.
"""

import re

import pytest
from mcp_sql.parser import QueryRejectedError
from mcp_sql.parser import extract_limit
from mcp_sql.parser import inject_limit
from mcp_sql.parser import parse_and_validate
from mcp_sql.parser import render_for_execution
from mcp_sql.schemas import OutcomeReason
from sqlglot import exp

ALLOWED = {"auth_permission", "auth_group", "django_content_type"}
# What the executor passes for those tables (`executor._table_columns`).
COLUMNS = {
    "auth_permission": frozenset({"id", "name", "content_type_id", "codename"}),
    "auth_group": frozenset({"id", "name"}),
    "django_content_type": frozenset({"id", "app_label", "model"}),
}


def _expect_reject(sql: str, reason: OutcomeReason, **kwargs) -> QueryRejectedError:
    allowed = kwargs.pop("allowed", ALLOWED)
    ban = kwargs.pop("ban_select_star", True)
    columns = kwargs.pop("table_columns", None)
    assert not kwargs, kwargs
    with pytest.raises(QueryRejectedError) as exc:
        parse_and_validate(
            sql, allowed_tables=allowed, ban_select_star=ban, table_columns=columns
        )
    assert exc.value.reason == reason, (
        f"expected {reason.value} got {exc.value.reason.value} for: {sql!r}"
    )
    return exc.value


class TestHappyPaths:
    def test_simple_select(self):
        out = parse_and_validate(
            "SELECT id, codename FROM auth_permission ORDER BY id",
            allowed_tables=ALLOWED,
        )
        assert out.referenced_tables == {"auth_permission"}
        assert "SELECT" in out.normalized_sql
        assert "auth_permission" in out.normalized_sql

    def test_count_star_is_allowed(self):
        out = parse_and_validate(
            "SELECT COUNT(*) FROM auth_permission",
            allowed_tables=ALLOWED,
        )
        assert out.referenced_tables == {"auth_permission"}

    def test_group_by_with_count_star(self):
        parse_and_validate(
            "SELECT codename, COUNT(*) FROM auth_permission GROUP BY codename",
            allowed_tables=ALLOWED,
        )

    def test_join(self):
        out = parse_and_validate(
            (
                "SELECT p.id, g.name FROM auth_permission p "
                "JOIN auth_group g ON g.id = p.id"
            ),
            allowed_tables=ALLOWED,
        )
        assert out.referenced_tables == {"auth_permission", "auth_group"}

    def test_cte(self):
        out = parse_and_validate(
            ("WITH q AS (SELECT id FROM auth_permission) SELECT id FROM q ORDER BY id"),
            allowed_tables=ALLOWED,
        )
        assert out.referenced_tables == {"auth_permission"}

    def test_subquery(self):
        parse_and_validate(
            ("SELECT id FROM auth_permission WHERE id IN (SELECT id FROM auth_group)"),
            allowed_tables=ALLOWED,
        )

    def test_union(self):
        parse_and_validate(
            ("SELECT id FROM auth_permission UNION SELECT id FROM auth_group"),
            allowed_tables=ALLOWED,
        )

    def test_qualified_columns_not_select_star(self):
        parse_and_validate(
            "SELECT auth_permission.id FROM auth_permission",
            allowed_tables=ALLOWED,
        )

    def test_select_star_allowed_when_flag_off(self):
        out = parse_and_validate(
            "SELECT * FROM auth_permission",
            allowed_tables=ALLOWED,
            ban_select_star=False,
        )
        assert out.referenced_tables == {"auth_permission"}


class TestParseError:
    def test_garbage_input(self):
        _expect_reject("this is not sql at all", OutcomeReason.PARSE_ERROR)

    def test_empty_input(self):
        _expect_reject("", OutcomeReason.PARSE_ERROR)

    def test_whitespace_only(self):
        _expect_reject("   \n  ", OutcomeReason.PARSE_ERROR)

    def test_deeply_nested_input_is_audited_not_raised(self):
        # sqlglot's recursive-descent parser raises RecursionError (NOT
        # ParseError) on pathological nesting. The parser must convert it
        # to a PARSE_ERROR reject so `run_query` audits it like any other
        # bad input, instead of letting it escape as an unaudited 500.
        # 5000 nested parens is far past any reasonable recursion limit
        # (the default is 1000, and sqlglot burns multiple frames per level),
        # so this reliably trips RecursionError during parse while staying
        # ~10 KB. The depth is chosen for headroom, not boundary precision.
        sql = "SELECT " + "(" * 5000 + "1" + ")" * 5000
        _expect_reject(sql, OutcomeReason.PARSE_ERROR)


class TestMultiStatement:
    def test_two_selects(self):
        _expect_reject("SELECT 1; SELECT 2", OutcomeReason.MULTI_STATEMENT)

    def test_select_then_insert(self):
        # INSERT is bad on its own, but multi-statement fires first.
        sql = (
            "SELECT id FROM auth_permission; "
            "INSERT INTO auth_permission(name) VALUES ('x')"
        )
        _expect_reject(sql, OutcomeReason.MULTI_STATEMENT)

    def test_trailing_semicolon_is_not_multi_statement(self):
        # sqlglot emits an `exp.Semicolon` node for the trailing `;`; the parser
        # filters those out so common ergonomic shapes don't masquerade as a
        # multi-statement payload.
        parse_and_validate("SELECT id FROM auth_permission;", allowed_tables=ALLOWED)

    def test_trailing_comment_is_not_multi_statement(self):
        parse_and_validate(
            "SELECT id FROM auth_permission; -- trailing comment",
            allowed_tables=ALLOWED,
        )


class TestNonSelectRoot:
    @pytest.mark.parametrize(
        "sql",
        [
            "INSERT INTO auth_permission(name) VALUES ('x')",
            "UPDATE auth_permission SET name='x'",
            "DELETE FROM auth_permission",
            "EXPLAIN ANALYZE SELECT id FROM auth_permission",
            "CALL some_proc()",
            "DO $$ BEGIN SELECT 1; END $$",
            "BEGIN",
            "COMMIT",
            "SET search_path TO public",
        ],
    )
    def test_root_rejected(self, sql):
        _expect_reject(sql, OutcomeReason.NON_SELECT_ROOT)


class TestSelectStar:
    def test_bare_star(self):
        _expect_reject("SELECT * FROM auth_permission", OutcomeReason.SELECT_STAR)

    def test_qualified_star(self):
        _expect_reject(
            "SELECT auth_permission.* FROM auth_permission",
            OutcomeReason.SELECT_STAR,
        )

    def test_nested_select_star_in_subquery(self):
        # The outer SELECT names columns explicitly; the inner SELECT uses *.
        # Both must be rejected — Star anywhere in the tree fails.
        _expect_reject(
            "SELECT id FROM (SELECT * FROM auth_permission) sub",
            OutcomeReason.SELECT_STAR,
        )

    def test_select_star_in_cte_body(self):
        _expect_reject(
            "WITH q AS (SELECT * FROM auth_permission) SELECT id FROM q",
            OutcomeReason.SELECT_STAR,
        )

    def test_qualified_star_in_subquery(self):
        _expect_reject(
            "SELECT sub.id FROM (SELECT t.* FROM auth_permission t) sub",
            OutcomeReason.SELECT_STAR,
        )

    def test_parenthesised_qualified_star(self):
        # `SELECT (t.*) FROM ... t` — `Star → Column → Paren → Select`.
        # The previous parent-only check missed this; the ancestor walk
        # catches it.
        _expect_reject("SELECT (t.*) FROM auth_permission t", OutcomeReason.SELECT_STAR)

    def test_qualified_star_inside_to_jsonb(self):
        # `to_jsonb(t.*)` returns the entire row as JSON. Same defense
        # intent as the SELECT * ban.
        _expect_reject(
            "SELECT to_jsonb(t.*) FROM auth_permission t",
            OutcomeReason.SELECT_STAR,
        )

    def test_qualified_star_inside_json_agg(self):
        _expect_reject(
            "SELECT json_agg(t.*) FROM auth_permission t",
            OutcomeReason.SELECT_STAR,
        )

    def test_qualified_star_inside_array_agg(self):
        _expect_reject(
            "SELECT array_agg(t.*) FROM auth_permission t",
            OutcomeReason.SELECT_STAR,
        )

    def test_count_distinct_star_remains_allowed(self):
        # Carve-out for COUNT must extend to `COUNT(DISTINCT *)` /
        # `COUNT(DISTINCT t.*)` — both walk up through Count and break.
        parse_and_validate(
            "SELECT COUNT(DISTINCT t.*) FROM auth_permission t",
            allowed_tables=ALLOWED,
        )

    def test_count_star_with_window_remains_allowed(self):
        # `COUNT(*) OVER (...)` parses as `Window(this=Count(*))`. Walking
        # up from Star: Count → break. Window machinery never matters here.
        parse_and_validate(
            "SELECT id, COUNT(*) OVER () AS n FROM auth_permission",
            allowed_tables=ALLOWED,
        )


class TestWholeRowReferences:
    """The companion to SELECT_STAR — every shape that returns a whole row
    without using `*`. Single audit reason (SELECT_STAR) keeps the agent's
    hint consistent."""

    def test_bare_row_alias_in_projection(self):
        # `SELECT t FROM auth_permission t` — t is a bare Column reference
        # whose name matches the FROM alias; PG returns the entire row as
        # a text tuple.
        _expect_reject("SELECT t FROM auth_permission t", OutcomeReason.SELECT_STAR)

    def test_row_to_json_of_row_alias(self):
        _expect_reject(
            "SELECT row_to_json(t) FROM auth_permission t",
            OutcomeReason.SELECT_STAR,
        )

    def test_to_jsonb_of_row_alias(self):
        _expect_reject(
            "SELECT to_jsonb(t) FROM auth_permission t",
            OutcomeReason.SELECT_STAR,
        )

    def test_json_agg_of_row_alias(self):
        _expect_reject(
            "SELECT json_agg(t) FROM auth_permission t",
            OutcomeReason.SELECT_STAR,
        )

    def test_array_agg_of_row_alias(self):
        _expect_reject(
            "SELECT array_agg(t) FROM auth_permission t",
            OutcomeReason.SELECT_STAR,
        )

    def test_cast_row_alias_to_text(self):
        _expect_reject(
            "SELECT CAST(t AS TEXT) FROM auth_permission t",
            OutcomeReason.SELECT_STAR,
        )

    def test_row_alias_in_joined_query(self):
        # JOIN alias counts too: `JOIN auth_group g` makes `g` a row alias
        # — bare `g` in projection is the whole-row reference.
        _expect_reject(
            ("SELECT g FROM auth_permission p JOIN auth_group g ON g.id = p.id"),
            OutcomeReason.SELECT_STAR,
        )

    def test_qualified_column_not_treated_as_whole_row(self):
        # `t.id` has `table='t'` — qualified column, not a whole-row ref.
        # Same shape PG users write daily; must not be a false positive.
        parse_and_validate("SELECT t.id FROM auth_permission t", allowed_tables=ALLOWED)

    def test_regular_column_named_after_no_alias(self):
        # `SELECT id FROM auth_permission t` — `id` doesn't match `t`,
        # and the table-name itself isn't in the projection.
        parse_and_validate("SELECT id FROM auth_permission t", allowed_tables=ALLOWED)

    def test_table_name_used_as_qualifier_not_whole_row(self):
        # `SELECT auth_permission.id FROM auth_permission` — qualified
        # column. The Column has `table='auth_permission'`; not a bare
        # reference to a row alias.
        parse_and_validate(
            "SELECT auth_permission.id FROM auth_permission",
            allowed_tables=ALLOWED,
        )

    def test_cte_alias_in_outer_projection_is_safe(self):
        # `SELECT q.id FROM q` is a qualified column; not a whole-row ref.
        # The CTE alias `q` is just a table alias for the outer scope.
        parse_and_validate(
            ("WITH q AS (SELECT id FROM auth_permission) SELECT q.id FROM q"),
            allowed_tables=ALLOWED,
        )

    def test_bare_cte_alias_reference_is_rejected(self):
        # `SELECT q FROM q` returns the whole-row of the CTE; same shape
        # as `SELECT t FROM auth_permission t`.
        _expect_reject(
            "WITH q AS (SELECT id FROM auth_permission) SELECT q FROM q",
            OutcomeReason.SELECT_STAR,
        )


class TestCTEs:
    def test_writeable_cte_with_delete(self):
        _expect_reject(
            ("WITH a AS (DELETE FROM auth_permission RETURNING id) SELECT id FROM a"),
            OutcomeReason.WRITEABLE_CTE,
        )

    def test_writeable_cte_with_insert(self):
        _expect_reject(
            (
                "WITH a AS (INSERT INTO auth_permission(name) VALUES ('x') "
                "RETURNING id) SELECT id FROM a"
            ),
            OutcomeReason.WRITEABLE_CTE,
        )

    def test_writeable_cte_with_update(self):
        _expect_reject(
            (
                "WITH a AS (UPDATE auth_permission SET name='x' RETURNING id) "
                "SELECT id FROM a"
            ),
            OutcomeReason.WRITEABLE_CTE,
        )

    def test_cte_alias_not_treated_as_disallowed_table(self):
        # The outer SELECT references `q`, which is a CTE alias, not a real table.
        # Whitelist check must skip it.
        parse_and_validate(
            "WITH q AS (SELECT id FROM auth_permission) SELECT id FROM q",
            allowed_tables=ALLOWED,
        )

    def test_inner_cte_does_not_shadow_outer_real_table(self):
        # Scope hole: an inner-scoped CTE named like a NON-whitelisted real
        # table must NOT mask an OUTER-scope reference to that real table.
        # The outer `FROM secret_table` is a real (non-whitelisted) table; the
        # inner CTE only shadows the name inside the subquery. Whitelist check
        # must still reject the outer reference (a flat global cte-name set
        # would wrongly skip it).
        _expect_reject(
            "SELECT s.x FROM secret_table s "
            "JOIN (WITH secret_table AS (SELECT 1 AS x) SELECT x FROM secret_table) q "
            "ON TRUE",
            OutcomeReason.DISALLOWED_TABLE,
        )

    def test_cte_may_legitimately_shadow_whitelisted_name(self):
        # A CTE that shadows a WHITELISTED table name is fine: the CTE body
        # touches no real table, and the outer FROM resolves to the in-scope
        # CTE. Scope-aware resolution must allow this.
        parse_and_validate(
            "WITH auth_permission AS (SELECT 1 AS id) SELECT id FROM auth_permission",
            allowed_tables=ALLOWED,
        )

    def test_nested_cte_referencing_earlier_sibling_is_allowed(self):
        # `b` references earlier sibling CTE `a`; both resolve in-scope.
        parse_and_validate(
            "WITH a AS (SELECT id FROM auth_permission), "
            "b AS (SELECT id FROM a) SELECT id FROM b",
            allowed_tables=ALLOWED,
        )


class TestSetReturningFunctions:
    """Set-returning / table functions in the PROJECTION (not FROM) must be
    rejected: they escape the empty-name `exp.Table` FROM guard and the
    name-based function deny-list (sqlglot maps them to typed nodes). The
    documented amplifier is `generate_series`."""

    def test_generate_series_in_projection_rejected(self):
        _expect_reject(
            "SELECT generate_series(1, 1000000000)",
            OutcomeReason.DISALLOWED_CONSTRUCT,
        )

    def test_generate_series_in_subquery_projection_rejected(self):
        _expect_reject(
            "SELECT count(*) FROM (SELECT generate_series(1, 1000000000)) t",
            OutcomeReason.DISALLOWED_CONSTRUCT,
        )

    def test_unnest_in_projection_rejected(self):
        _expect_reject(
            "SELECT unnest(ARRAY[1, 2, 3])",
            OutcomeReason.DISALLOWED_CONSTRUCT,
        )

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT regexp_split_to_table(codename, ',') FROM auth_permission",
            "SELECT json_array_elements('[1,2]'::json)",
            "SELECT jsonb_array_elements('[1,2]'::jsonb)",
            "SELECT json_to_recordset('[]'::json)",
            "SELECT generate_subscripts(ARRAY[1], 1)",
        ],
    )
    def test_anonymous_mapped_srfs_in_projection_rejected(self, sql):
        # SRFs that sqlglot parses as `exp.Anonymous` (the json/regexp
        # expanders) are caught by name via DENIED_SRF_FUNCTIONS, not the
        # typed-node isinstance check.
        _expect_reject(sql, OutcomeReason.DISALLOWED_CONSTRUCT)

    def test_legit_aggregates_not_misflagged(self):
        # Guard against false positives: ordinary aggregates over a whitelisted
        # table must still pass.
        for sql in (
            "SELECT count(*) FROM auth_permission",
            "SELECT array_agg(id) FROM auth_permission",
            "SELECT max(id), min(id) FROM auth_permission",
        ):
            parse_and_validate(sql, allowed_tables=ALLOWED)


class TestSelectInto:
    def test_select_into(self):
        _expect_reject(
            "SELECT id INTO new_table FROM auth_permission",
            OutcomeReason.SELECT_INTO,
        )


class TestRecursiveCTE:
    """`WITH RECURSIVE` is structurally rejected because it enables a
    parameterless DoS shape that references no whitelisted table — the
    recursive-CTE-no-table-reference DoS in the security review."""

    def test_recursive_cte_string_doubling_rejected(self):
        # Canonical recursive-DoS shape from the review: doubles a string
        # 30 times under work_mem until statement_timeout fires; references
        # only the CTE alias `t`, so the whitelist check would not catch it.
        sql = (
            "WITH RECURSIVE t(n, s) AS ("
            "VALUES (1, repeat('a', 4000)) UNION ALL "
            "SELECT n+1, s || s FROM t WHERE n < 30"
            ") SELECT n, s FROM t"
        )
        exc = _expect_reject(sql, OutcomeReason.DISALLOWED_CONSTRUCT)
        assert "RECURSIVE" in exc.detail

    def test_recursive_cte_over_whitelisted_table_also_rejected(self):
        # Even when a recursive CTE references real data, the strict reject
        # stands — agents that need recursion should restructure. Closing
        # one bypass class beats permitting use cases that don't exist yet.
        sql = (
            "WITH RECURSIVE p AS ("
            "SELECT id FROM auth_permission WHERE id = 1 "
            "UNION ALL SELECT id+1 FROM p WHERE id < 5"
            ") SELECT id FROM p"
        )
        _expect_reject(sql, OutcomeReason.DISALLOWED_CONSTRUCT)

    def test_non_recursive_cte_remains_allowed(self):
        # Ordinary WITH is the workhorse of LLM-written SQL. Must not
        # false-positive on the non-recursive flag.
        parse_and_validate(
            "WITH q AS (SELECT id FROM auth_permission) SELECT id FROM q",
            allowed_tables=ALLOWED,
        )


class TestOffset:
    def test_root_offset_rejected(self):
        _expect_reject(
            "SELECT id FROM auth_permission ORDER BY id LIMIT 5 OFFSET 10",
            OutcomeReason.DISALLOWED_CONSTRUCT,
        )

    def test_offset_only_no_limit(self):
        _expect_reject(
            "SELECT id FROM auth_permission ORDER BY id OFFSET 100",
            OutcomeReason.DISALLOWED_CONSTRUCT,
        )

    def test_offset_inside_subquery_also_rejected(self):
        _expect_reject(
            "SELECT id FROM (SELECT id FROM auth_permission OFFSET 5) sub",
            OutcomeReason.DISALLOWED_CONSTRUCT,
        )


class TestFetch:
    """SQL-standard pagination via `FETCH FIRST N ROWS` is the OFFSET cousin —
    same agent-friendly-but-server-hostile shape; same closed rejection."""

    def test_fetch_first_n_rows_only(self):
        exc = _expect_reject(
            "SELECT id FROM auth_permission ORDER BY id FETCH FIRST 10 ROWS ONLY",
            OutcomeReason.DISALLOWED_CONSTRUCT,
        )
        assert "FETCH" in exc.detail

    def test_fetch_next_n_rows_only(self):
        _expect_reject(
            "SELECT id FROM auth_permission ORDER BY id FETCH NEXT 5 ROWS ONLY",
            OutcomeReason.DISALLOWED_CONSTRUCT,
        )

    def test_fetch_inside_subquery(self):
        _expect_reject(
            (
                "SELECT id FROM (SELECT id FROM auth_permission ORDER BY id "
                "FETCH FIRST 10 ROWS ONLY) sub"
            ),
            OutcomeReason.DISALLOWED_CONSTRUCT,
        )


class TestLockingReads:
    """Locking-read clauses (`FOR UPDATE`, `FOR SHARE`, …) require write
    privileges PG won't grant to mcp_readonly_role. Catching at parser layer
    yields a clearer audit reason than `EXECUTION_ERROR` would."""

    @pytest.mark.parametrize(
        "clause",
        ["FOR UPDATE", "FOR SHARE", "FOR NO KEY UPDATE", "FOR KEY SHARE"],
    )
    def test_locking_read_rejected(self, clause):
        exc = _expect_reject(
            f"SELECT id FROM auth_permission {clause}",  # noqa: S608
            OutcomeReason.DISALLOWED_CONSTRUCT,
        )
        assert "Locking" in exc.detail or "FOR" in exc.detail


class TestSystemSchema:
    def test_pg_underscore_no_schema(self):
        _expect_reject("SELECT relname FROM pg_class", OutcomeReason.SYSTEM_SCHEMA)

    def test_pg_catalog_schema(self):
        _expect_reject(
            "SELECT relname FROM pg_catalog.pg_class",
            OutcomeReason.SYSTEM_SCHEMA,
        )

    def test_information_schema(self):
        _expect_reject(
            "SELECT table_name FROM information_schema.tables",
            OutcomeReason.SYSTEM_SCHEMA,
        )

    def test_pg_namespace_under_pg_catalog(self):
        _expect_reject(
            "SELECT nspname FROM pg_catalog.pg_namespace",
            OutcomeReason.SYSTEM_SCHEMA,
        )


class TestDisallowedTable:
    def test_unknown_table(self):
        _expect_reject("SELECT id FROM users_user", OutcomeReason.DISALLOWED_TABLE)

    def test_case_insensitive_whitelist_match(self):
        # auth_permission in whitelist as lowercase; SQL uses lowercase too.
        # Pretend user typed mixed case.
        parse_and_validate(
            "SELECT id FROM Auth_Permission",
            allowed_tables=ALLOWED,
        )

    # Review round 9: names match as Postgres matches them — a quoted name
    # exactly, an unquoted one folded to lowercase — for whitelist entries
    # (exact `db_table` spellings) and CTE names alike.
    @pytest.mark.parametrize(
        "sql",
        [
            'SELECT id FROM "auth_permission"',
            'SELECT id FROM "Mixed_Table"',
            "SELECT id FROM public.auth_permission",
            'WITH "Users_User" AS (SELECT 1 AS id) SELECT id FROM "Users_User"',
            "WITH users_user AS (SELECT 1 AS id) SELECT id FROM Users_User",
            "WITH b AS (SELECT 1 AS id), a AS (SELECT id FROM b) SELECT id FROM a",
        ],
    )
    def test_names_match_as_postgres_matches_them(self, sql):
        parse_and_validate(sql, allowed_tables=ALLOWED | {"Mixed_Table"})

    @pytest.mark.parametrize(
        "sql",
        [
            # Not the relations on the whitelist.
            'SELECT id FROM "Auth_Permission"',
            "SELECT id FROM mixed_table",
            "SELECT id FROM Mixed_Table",
            # A quoted CTE name is not the folded table name.
            'WITH "Users_User" AS (SELECT 1 AS id) SELECT id FROM users_user',
            # A CTE body sees only the CTEs before it, never itself.
            "WITH users_user AS (SELECT id FROM users_user) SELECT id FROM users_user",
            "WITH a AS (SELECT id FROM users_user), users_user AS (SELECT 1 AS id) "
            "SELECT id FROM a",
            # A schema-qualified name is the table, not the CTE.
            "WITH users_user AS (SELECT 1 AS id) SELECT id FROM public.users_user",
        ],
    )
    def test_a_name_postgres_resolves_elsewhere_is_refused(self, sql):
        _expect_reject(sql, OutcomeReason.DISALLOWED_TABLE)


class TestDisallowedFunction:
    @pytest.mark.parametrize(
        "fn",
        [
            "current_setting('app.secret')",
            "set_config('a', 'b', false)",
        ],
    )
    def test_exact_match_denylist(self, fn):
        _expect_reject(f"SELECT {fn}", OutcomeReason.DISALLOWED_FUNCTION)

    @pytest.mark.parametrize(
        "fn",
        [
            # Server-state / identity leaks. The Anonymous-only walk used
            # to miss typed Func subclasses (`exp.Version`, `exp.CurrentUser`,
            # …). Walking `exp.Func` covers both.
            "version()",
            "current_database()",
            "current_schema()",
            "current_schemas(true)",
            "current_user()",
            "session_user()",
            "current_role()",
            "current_catalog()",
            "inet_server_addr()",
            "inet_server_port()",
            "inet_client_addr()",
            "inet_client_port()",
            "txid_current()",
            "row_security_active('auth_permission')",
            # Sequence introspection (mutation already rejected at PG; this
            # makes the audit reason clean).
            "nextval('auth_permission_id_seq')",
            "setval('auth_permission_id_seq', 1)",
            "currval('auth_permission_id_seq')",
            # `dblink` — bare two-arg overload; the `_*` prefix did not cover it.
            "dblink('host=evil', 'SELECT 1')",
            # XML family — accepts arbitrary SQL as text, bypassing the parser.
            "query_to_xml('SELECT 1', false, false, '')",
            "table_to_xml('auth_permission', false, false, '')",
        ],
    )
    def test_typed_and_anonymous_server_state_leaks(self, fn):
        _expect_reject(f"SELECT {fn}", OutcomeReason.DISALLOWED_FUNCTION)

    @pytest.mark.parametrize(
        "bare",
        [
            # `SELECT current_user` (no parens) parses as exp.Column. The
            # function-deny-list walk would miss it; the bare-keyword check
            # closes that gap.
            "current_user",
            "session_user",
            "user",
            "current_role",
            "current_catalog",
            "current_schema",
            "current_database",
        ],
    )
    def test_bare_keyword_identifiers_rejected(self, bare):
        _expect_reject(f"SELECT {bare}", OutcomeReason.DISALLOWED_FUNCTION)

    def test_qualified_keyword_is_column_or_denied(self):
        # sqlglot ≤30.7 parses qualified `auth_permission.current_user` with
        # `current_user` as `exp.CurrentUser` (reserved-word precedence over
        # a column read), so the function deny-list rejects it. Later 30.x
        # releases follow PG grammar instead: a QUALIFIED name is a plain
        # column reference (only the bare keyword is the identity function),
        # so the query passes the parser and can only ever read a real
        # column of a whitelisted table. Both outcomes are safe; pinning
        # both keeps this a tripwire — any third behaviour (e.g. the
        # function surviving as a typed node in an accepted parse) still
        # fails here. Bare `current_user` stays rejected on every version
        # (test_bare_keyword_identifiers_rejected above).
        sql = "SELECT auth_permission.current_user FROM auth_permission"
        parsed, rejection = None, None
        try:
            parsed = parse_and_validate(sql, allowed_tables=ALLOWED)
        except QueryRejectedError as exc:
            rejection = exc
        if rejection is not None:
            assert rejection.reason == OutcomeReason.DISALLOWED_FUNCTION
        else:
            projection = parsed.ast.selects[0]
            assert isinstance(projection, exp.Column)
            assert not list(parsed.ast.find_all(exp.CurrentUser))

    def test_copy_statement_rejected_as_non_select(self):
        # `COPY tab TO '/path'` parses as a Postgres COPY statement, not a
        # SELECT — caught by the root-shape check, not the function deny-list.
        # `copy` stays in DENIED_FUNCTIONS_EXACT as belt-and-braces in case
        # any dialect / extension surfaces a `copy()` function call later.
        _expect_reject(
            "COPY auth_permission TO '/tmp/x'", OutcomeReason.NON_SELECT_ROOT
        )

    @pytest.mark.parametrize(
        "fn",
        [
            "dblink_open('s', 'q')",
            "dblink_connect('s', 'c')",
            "lo_import('/etc/passwd')",
            "lo_export(1, '/tmp/x')",
            # pg_* prefix — every Postgres-internal function leaks server state
            # or table metadata (size, ownership, privileges, type info).
            "pg_read_file('/etc/passwd')",
            "pg_read_binary_file('/etc/passwd')",
            "pg_ls_dir('/tmp')",
            "pg_ls_logdir()",
            "pg_ls_waldir()",
            "pg_database_size('postgres')",
            "pg_total_relation_size('auth_permission')",
            "pg_relation_size('auth_permission')",
            "has_table_privilege('auth_permission', 'select')",
            "pg_typeof(1)",
            "pg_size_pretty(1024)",
        ],
    )
    def test_prefix_denylist(self, fn):
        _expect_reject(f"SELECT {fn}", OutcomeReason.DISALLOWED_FUNCTION)


class TestInjectLimit:
    def test_appends_to_query_without_limit(self):
        ast = parse_and_validate(
            "SELECT id FROM auth_permission",
            allowed_tables=ALLOWED,
        ).ast
        out = inject_limit(ast, 11)
        sql = out.sql(dialect="postgres")
        assert "LIMIT 11" in sql

    def test_replaces_existing_limit(self):
        ast = parse_and_validate(
            "SELECT id FROM auth_permission LIMIT 5",
            allowed_tables=ALLOWED,
        ).ast
        out = inject_limit(ast, 11)
        sql = out.sql(dialect="postgres")
        # Existing LIMIT 5 must be gone; new LIMIT 11 must be present.
        assert "LIMIT 11" in sql
        assert "LIMIT 5" not in sql

    def test_preserves_order_by(self):
        ast = parse_and_validate(
            "SELECT id FROM auth_permission ORDER BY id DESC",
            allowed_tables=ALLOWED,
        ).ast
        sql = inject_limit(ast, 11).sql(dialect="postgres")
        assert "ORDER BY id DESC" in sql
        assert "LIMIT 11" in sql

    @pytest.mark.parametrize(
        ("limit", "capped"),
        [
            ("3.5", "LIMIT LEAST(CAST(3.5 AS BIGINT), 11)"),
            ("2 + 3", "LIMIT LEAST(CAST(2 + 3 AS BIGINT), 11)"),
            ("-1", "LIMIT LEAST(CAST(-1 AS BIGINT), 11)"),
            (
                "'NaN'::float8",
                "LIMIT LEAST(CAST(CAST('NaN' AS DOUBLE PRECISION) AS BIGINT), 11)",
            ),
            (
                "99999999999999999999",
                "LIMIT LEAST(CAST(99999999999999999999 AS BIGINT), 11)",
            ),
            # A scalar subquery selecting a numeric value is numeric as
            # written: `LEAST` over a float would turn its NaN into n (review
            # round 9).
            ("(SELECT 3)", "LIMIT LEAST(CAST((SELECT 3) AS BIGINT), 11)"),
            (
                "(SELECT 'NaN'::float8 AS x)",
                "LIMIT LEAST(CAST((SELECT CAST('NaN' AS DOUBLE PRECISION) AS x) "
                "AS BIGINT), 11)",
            ),
            (
                "((SELECT 'Infinity'::float8))",
                "LIMIT LEAST(CAST(((SELECT CAST('Infinity' AS DOUBLE PRECISION))) "
                "AS BIGINT), 11)",
            ),
            # Not numeric as written: left to Postgres's type resolution (an
            # explicit cast would run `'3'::text`, an error in a LIMIT).
            ("(SELECT '3')", "LIMIT LEAST((SELECT '3'), 11)"),
            (
                "((SELECT 1) UNION (SELECT 2))",
                "LIMIT LEAST(((SELECT 1) UNION (SELECT 2)), 11)",
            ),
            (
                "(SELECT id FROM auth_permission)",
                "LIMIT LEAST((SELECT id FROM auth_permission), 11)",
            ),
            ("'3'::text", "LIMIT LEAST(CAST('3' AS TEXT), 11)"),
            ("'3 apples'", "LIMIT LEAST('3 apples', 11)"),
            ("('3 apples')", "LIMIT LEAST(('3 apples'), 11)"),
        ],
    )
    def test_keeps_a_limit_that_is_not_a_plain_integer(self, limit, capped):
        # Review round 4: replacing it with the cap returned more rows than
        # Postgres would (`LIMIT 3.5` is 4 rows), or rows where Postgres
        # raises (`LIMIT -1`). Kept as written and capped, Postgres
        # evaluates it exactly as it would have.
        assert _executed(f"LIMIT {limit}").endswith(capped)

    @pytest.mark.parametrize(
        "limit",
        [
            "NULL",
            "5",
            "'5'",
            "' +5 '",
            "'9223372036854775807'",
            # Parentheses change nothing: `('5000000000')` is still the
            # bigint, not an int4 for `LEAST` (review round 9).
            "(5)",
            "('5000000000')",
            "(('5'))",
        ],
    )
    def test_replaces_no_limit_or_a_plain_integer(self, limit):
        # `LIMIT '5'` is the bigint 5 to Postgres; `LEAST('…', n)` would read
        # the string as int4 and overflow (review round 7).
        assert _executed(f"LIMIT {limit}").endswith(" LIMIT 11")

    def test_unwraps_a_parenthesised_query(self):
        # `(SELECT ... LIMIT 5) LIMIT 11` is an error in Postgres.
        ast = parse_and_validate(
            "(SELECT id FROM auth_permission ORDER BY id LIMIT 5)",
            allowed_tables=ALLOWED,
        ).ast
        assert extract_limit(ast) == 5
        sql = render_for_execution(ast, 6, allowed_tables=ALLOWED)
        assert sql == "SELECT id FROM auth_permission ORDER BY id LIMIT 6"


def _executed(limit: str) -> str:
    """The SQL the executor would send for `SELECT ... <limit>` with a cap
    of 11 — through `FaithfulPostgres`, as production does."""
    sql = f"SELECT id FROM auth_permission {limit}"  # noqa: S608
    parsed = parse_and_validate(sql, allowed_tables=ALLOWED)
    return render_for_execution(parsed.ast, 11, allowed_tables=ALLOWED)


class TestExtractLimit:
    """`extract_limit` reads the user's `LIMIT N` so the executor can apply
    the most-restrictive-wins rule. Pin each shape we expect to see in the
    wild plus the "give up cleanly" path for shapes we can't reason about."""

    def test_no_limit_returns_none(self):
        ast = parse_and_validate(
            "SELECT id FROM auth_permission", allowed_tables=ALLOWED
        ).ast
        assert extract_limit(ast) is None

    def test_integer_limit_returned(self):
        ast = parse_and_validate(
            "SELECT id FROM auth_permission LIMIT 7", allowed_tables=ALLOWED
        ).ast
        assert extract_limit(ast) == 7

    def test_with_cte_limit_returned(self):
        ast = parse_and_validate(
            "WITH p AS (SELECT id FROM auth_permission) SELECT id FROM p LIMIT 4",
            allowed_tables=ALLOWED,
        ).ast
        assert extract_limit(ast) == 4

    def test_inject_then_extract_round_trips(self):
        ast = parse_and_validate(
            "SELECT id FROM auth_permission", allowed_tables=ALLOWED
        ).ast
        injected = inject_limit(ast, 11)
        assert extract_limit(injected) == 11

    @pytest.mark.parametrize(
        ("limit", "value"),
        [
            ("'3 apples'", None),  # Postgres's error: kept for it to raise
            ("2 + 3", None),  # an expression: kept for Postgres to evaluate
            ("'12'", 12),
            ("' +12 '", 12),
            ("9223372036854775808", None),  # beyond bigint: Postgres's error
            ("('5000000000')", 5000000000),  # parentheses: the same literal
            ("((7))", 7),
            ("(SELECT 7)", None),  # a query: kept for Postgres to evaluate
        ],
    )
    def test_reads_only_what_postgres_reads_as_a_bigint(self, limit, value):
        ast = parse_and_validate(
            f"SELECT id FROM auth_permission LIMIT {limit}",  # noqa: S608
            allowed_tables=ALLOWED,
        ).ast
        assert extract_limit(ast) == value


class TestAttributeNotation:
    """Review round 5: Postgres reads `x.f` / `(expr).f` as the call `f(x)`
    when `x` has no column `f`, so a qualified name can call a function."""

    @pytest.mark.parametrize(
        ("sql", "reason"),
        [
            (
                "SELECT ('server_version'::text).current_setting AS v",
                OutcomeReason.DISALLOWED_FUNCTION,
            ),
            ("SELECT (true).current_schemas AS v", OutcomeReason.DISALLOWED_FUNCTION),
            ("SELECT (0.1::float8).pg_sleep AS v", OutcomeReason.DISALLOWED_FUNCTION),
            (
                "SELECT (424242::bigint).pg_try_advisory_lock AS v",
                OutcomeReason.DISALLOWED_FUNCTION,
            ),
            (
                "SELECT auth_permission.pg_column_size AS v FROM auth_permission",
                OutcomeReason.DISALLOWED_FUNCTION,
            ),
            (
                "SELECT (codename).current_setting AS v FROM auth_permission",
                OutcomeReason.DISALLOWED_FUNCTION,
            ),
            ("SELECT (ARRAY[1, 2]).unnest AS v", OutcomeReason.DISALLOWED_CONSTRUCT),
            (
                "SELECT ('a,b'::text).regexp_split_to_table AS v",
                OutcomeReason.DISALLOWED_CONSTRUCT,
            ),
            (
                "SELECT p.to_jsonb AS v FROM auth_permission p",
                OutcomeReason.SELECT_STAR,
            ),
            (
                "SELECT (p).row_to_json AS v FROM auth_permission p",
                OutcomeReason.SELECT_STAR,
            ),
        ],
    )
    def test_denied_function_written_as_a_field(self, sql, reason):
        _expect_reject(sql, reason)

    @pytest.mark.parametrize(
        "sql",
        [
            # Review round 6: qualified names that ARE columns are columns,
            # whatever function they are named like (owner rule: never
            # refuse a column that exists).
            "SELECT s.lo_bound FROM (SELECT min(id) AS lo_bound "
            "FROM auth_permission) s",
            "SELECT s.array_agg FROM (SELECT array_agg(id) FROM auth_permission) s",
            "WITH c AS (SELECT count(*) AS currval FROM auth_permission) "
            "SELECT c.currval FROM c",
            "WITH c(pg_x) AS (SELECT 1) SELECT c.pg_x FROM c",
            "SELECT x.pg_sleep FROM (SELECT 0.1::float8 AS v) AS x(pg_sleep)",
            "SELECT x.pg_sleep FROM auth_permission AS x(pg_sleep)",
            "SELECT '0/0'::pg_catalog.pg_lsn AS v",
            "SELECT p.id, p.codename FROM auth_permission p",
            # Denied functions attribute notation cannot reach (no argument,
            # or two or more): ordinary column names.
            "SELECT p.version, p.user, p.has_access FROM auth_permission p",
            "SELECT (codename).upper AS v FROM auth_permission",
        ],
    )
    def test_ordinary_qualified_names_are_accepted(self, sql):
        parse_and_validate(sql, allowed_tables=ALLOWED, table_columns=COLUMNS)

    @pytest.mark.parametrize(
        "sql",
        [
            # Review round 8 (regression from round 6): a bare `(x)` is the
            # column `x` when a FROM item has one, so `(x).f` is `f(x)` —
            # whatever columns the FROM item `x` has.
            "SELECT (x).current_setting AS v FROM (SELECT 'server_version'::text "
            "AS x, 1 AS current_setting) x",
            "SELECT (x).pg_sleep AS v FROM (SELECT 0.1::float8 AS x, 1 AS pg_sleep) x",
            # The column `x` from a sibling FROM item.
            "SELECT (x).current_setting AS v FROM (SELECT 1 AS current_setting) x, "
            "(SELECT 'server_version'::text AS x) y",
            # An alias column list.
            "SELECT (x).current_setting AS v FROM (SELECT 'server_version'::text, "
            "1) x(x, current_setting)",
            "SELECT (x).current_setting AS v FROM auth_permission x",
            # `x` is also a column in scope: not provably the FROM item.
            "SELECT x.current_setting AS v FROM (SELECT 'server_version'::text "
            "AS x, 1 AS current_setting) x",
            # A FROM item whose column names are not all known may have a
            # column `s` (here `'x'::text` is named `text` by its type).
            "SELECT (s).pg_sleep FROM (SELECT 1 AS pg_sleep) s, (SELECT 'x'::text) q",
            "SELECT (text).current_setting FROM (SELECT 'server_version'::text) q, "
            "(SELECT 1 AS current_setting) text",
            "SELECT (s).pg_sleep FROM (SELECT * FROM (SELECT 1 AS pg_sleep) z) s",
            # (A whitelisted table whose columns the caller did not pass.)
            "SELECT (s).pg_sleep FROM (SELECT 1 AS pg_sleep) s, auth_permission",
            # A column `s` in scope wins over the row: `pg_sleep(s)`.
            "SELECT (s).pg_sleep FROM (SELECT 1 AS pg_sleep, 2 AS s) s",
            "SELECT (s).pg_sleep FROM (SELECT 1 AS pg_sleep) s, (SELECT 2 AS S) q",
            "SELECT (s).pg_sleep FROM (SELECT 1 AS pg_sleep) s, (SELECT 2) q(s)",
            "SELECT (SELECT (s).pg_sleep FROM (SELECT 1 AS pg_sleep) s) "
            "FROM (SELECT 1 AS s) o",
            # A scalar subquery's column is named by its own: `x`, not
            # `pg_column_size`.
            "SELECT s.pg_column_size FROM (SELECT (SELECT 1 AS x)) s",
            # Quoted names compare case-sensitively: no column `pg_sleep`.
            'SELECT s.pg_sleep FROM (SELECT 1 AS "Pg_Sleep") s',
        ],
    )
    def test_parenthesised_name_or_undecidable_is_a_call(self, sql):
        _expect_reject(sql, OutcomeReason.DISALLOWED_FUNCTION)

    @pytest.mark.parametrize(
        "sql",
        [
            'SELECT s."Pg_Sleep" FROM (SELECT 1 AS "Pg_Sleep") s',
            'SELECT s.pg_sleep FROM (SELECT 1 AS "pg_sleep") s',
            'SELECT s."pg_sleep" FROM (SELECT 1 AS pg_sleep) s',
        ],
    )
    def test_quoted_column_names_match_as_postgres_matches_them(self, sql):
        parse_and_validate(sql, allowed_tables=ALLOWED)

    @pytest.mark.parametrize(
        "sql",
        [
            # Review round 9: Postgres reads these as the column, provably.
            "SELECT (s).copy FROM (SELECT 1 AS copy) s",
            "SELECT (s).pg_sleep FROM (SELECT 1 AS pg_sleep) s",
            'SELECT (s).pg_sleep FROM (SELECT 1 AS pg_sleep) s, (SELECT 2 AS "S") q',
            "SELECT (s).pg_sleep FROM (SELECT 1 AS pg_sleep) s, auth_permission",
            "SELECT (s).pg_sleep FROM (SELECT 1 AS pg_sleep UNION SELECT 2) s",
            "SELECT (s).pg_sleep FROM (VALUES (1, 2)) s(pg_sleep)",
            "SELECT (s).column1 FROM (VALUES (1, 2)) s",
            # A VALUES list's columns are `column1`, ...: no column `p`.
            "SELECT p.pg_sleep FROM (SELECT 9 AS pg_sleep) p, (VALUES (1)) v",
            # A scalar subquery's column is named by its own.
            "SELECT s.pg_column_size FROM (SELECT (SELECT 1 AS pg_column_size)) s",
        ],
    )
    def test_provable_field_reads_are_accepted(self, sql):
        parse_and_validate(sql, allowed_tables=ALLOWED, table_columns=COLUMNS)

    @pytest.mark.parametrize(
        ("sql", "reason"),
        [
            # Review round 9 (fixed in round 8): a quoted alias is no column
            # `to_jsonb` / `pg_typeof`, so `s.to_jsonb` is `to_jsonb(s)`.
            (
                'SELECT s.to_jsonb FROM (SELECT id, name AS "To_Jsonb" '
                "FROM auth_permission) s",
                OutcomeReason.SELECT_STAR,
            ),
            (
                'SELECT s.to_jsonb FROM auth_permission AS s("To_Jsonb")',
                OutcomeReason.SELECT_STAR,
            ),
            (
                'SELECT s.pg_typeof FROM auth_permission AS s("Pg_Typeof")',
                OutcomeReason.DISALLOWED_FUNCTION,
            ),
            # A quoted CTE is not the table: `to_jsonb(auth_permission)`.
            (
                'WITH "Auth_Permission" AS (SELECT 1 AS to_jsonb) '
                "SELECT auth_permission.to_jsonb FROM auth_permission",
                OutcomeReason.SELECT_STAR,
            ),
        ],
    )
    def test_a_quoted_alias_is_not_the_folded_name(self, sql, reason):
        _expect_reject(sql, reason)

    def test_a_mixed_case_base_column_is_kept_exact(self):
        # `p.to_jsonb` is the row when the table's column is `"To_Jsonb"`.
        columns = {"auth_permission": frozenset({"id", "To_Jsonb"})}
        parse_and_validate(
            'SELECT p."To_Jsonb" FROM auth_permission p',
            allowed_tables=ALLOWED,
            table_columns=columns,
        )
        with pytest.raises(QueryRejectedError) as exc:
            parse_and_validate(
                "SELECT p.to_jsonb FROM auth_permission p",
                allowed_tables=ALLOWED,
                table_columns=columns,
            )
        assert exc.value.reason == OutcomeReason.SELECT_STAR

    def test_a_base_table_column_is_a_column(self):
        # The executor passes each whitelisted table's columns.
        sql = "SELECT p.pg_x, p.to_jsonb FROM auth_permission p"
        columns = {"auth_permission": frozenset({"id", "pg_x", "to_jsonb"})}
        parse_and_validate(sql, allowed_tables=ALLOWED, table_columns=columns)
        _expect_reject(sql, OutcomeReason.DISALLOWED_FUNCTION)  # columns unknown

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT p.concat FROM auth_permission p",
            "SELECT p.quote_literal FROM auth_permission p",
            "SELECT p.quote_nullable FROM auth_permission p",
            "SELECT p.record_out FROM auth_permission p",
            "SELECT p.record_send FROM auth_permission p",
        ],
    )
    def test_whole_row_through_attribute_notation(self, sql):
        _expect_reject(sql, OutcomeReason.SELECT_STAR)


class TestDeniedCallsTheTreeDoesNotShow:
    @pytest.mark.parametrize(
        ("sql", "reason"),
        [
            # sqlglot reads `copy(x)` here as a column `copy` with `AS (x)`.
            (
                "SELECT (SELECT copy(id)) AS c FROM auth_permission",
                OutcomeReason.DISALLOWED_FUNCTION,
            ),
            (
                "SELECT c FROM (VALUES (copy(x))) AS v(c)",
                OutcomeReason.DISALLOWED_FUNCTION,
            ),
            # Schema-qualified, sqlglot keeps these as plain calls.
            (
                "SELECT pg_catalog.generate_series(1, 3) AS v",
                OutcomeReason.DISALLOWED_CONSTRUCT,
            ),
            ("SELECT public.unnest(ARRAY[1]) AS v", OutcomeReason.DISALLOWED_CONSTRUCT),
        ],
    )
    def test_refused(self, sql, reason):
        _expect_reject(sql, reason)

    def test_an_alias_named_like_a_denied_function_is_not_a_call(self):
        parse_and_validate(
            "SELECT copy.a FROM (SELECT 1) AS copy(a)", allowed_tables=ALLOWED
        )

    def test_count_star_qualified_is_count(self):
        parse_and_validate(
            "SELECT pg_catalog.count(*) AS n FROM auth_permission",
            allowed_tables=ALLOWED,
        )


class TestOperatorSigns:
    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT 2 %-3 AS v",
            "SELECT ~-1 AS v",
            # Review round 7: operators sqlglot reads that Postgres lacks.
            "SELECT id FROM auth_permission WHERE id ==1",
            "SELECT id FROM auth_permission WHERE id <=> 1",
            "SELECT id FROM auth_permission WHERE codename ?? 'a'",
            "SELECT id FROM auth_permission WHERE codename ~~~ 'a'",
            # Review round 6: `=~`, `-~`, `*~` are one operator to Postgres.
            "SELECT id=~1 AS v FROM auth_permission",
            "SELECT -~id AS v FROM auth_permission",
            "SELECT id*~1 AS v FROM auth_permission",
        ],
    )
    def test_sign_postgres_reads_into_the_operator(self, sql):
        # Postgres: the operators `%-` / `~-` (none exist); sqlglot: `% -3`.
        _expect_reject(sql, OutcomeReason.UNSAFE_LITERAL)

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT id >=-1 AS v FROM auth_permission",
            "SELECT 1 <<-1 AS v",
            # sqlglot reads these from several tokens, as one operator.
            "SELECT codename !~ 'a' AS v, codename !~~ 'a%' AS w FROM auth_permission",
        ],
    )
    def test_sign_postgres_reads_apart_is_accepted(self, sql):
        parse_and_validate(sql, allowed_tables=ALLOWED)

    @pytest.mark.parametrize(
        ("sql", "rendered"),
        [
            # Review round 10: `^@` (starts with) was read as `^ (@ b)`; `!!`
            # (tsquery negation) and `!` were read as `NOT`.
            ("SELECT '10' ^@ '1' AS v", "'10' ^@ '1' AS v"),
            (
                "SELECT codename ^@'a'::text AS v FROM auth_permission",
                "codename ^@ CAST",
            ),
            ("SELECT 'x' || 'abc' ^@ 'a' AS v", "'x' || 'abc' ^@ 'a' AS v"),
            ("SELECT NOT 'abc' ^@ 'b' AS v", "NOT 'abc' ^@ 'b' AS v"),
            ("SELECT 2 ^ @ -3 AS v", "2 ^ @ -3 AS v"),
            (
                "SELECT !! to_tsquery('simple', 'a') AS v",
                "!! to_tsquery('simple', 'a')",
            ),
            ("SELECT !!'a'::tsquery AS v", "!! CAST('a' AS tsquery)"),
            ("SELECT ! true AS v", "! TRUE AS v"),
            ("SELECT NOT true AS v", "NOT TRUE AS v"),
        ],
    )
    def test_operator_kept_as_written(self, sql, rendered):
        parsed = parse_and_validate(sql, allowed_tables=ALLOWED)
        assert rendered in render_for_execution(parsed.ast, 11, allowed_tables=ALLOWED)

    @pytest.mark.parametrize(
        ("sql", "rendered"),
        [
            # Review round 9: a parameter stays one (Postgres: "there is no
            # parameter $1"); it was read as the prefix operator `@ 1`.
            ("SELECT id FROM auth_permission WHERE id = $1", "id = $1"),
            ("SELECT id FROM auth_permission WHERE id = $1::int", "CAST($1 AS INT)"),
            ("SELECT id FROM auth_permission WHERE codename = $name", "= $name"),
            ("SELECT @ -5 AS a, @x AS b FROM auth_permission", "@ -5 AS a, @ x AS b"),
        ],
    )
    def test_parameter_is_not_the_at_operator(self, sql, rendered):
        parsed = parse_and_validate(sql, allowed_tables=ALLOWED)
        assert rendered in render_for_execution(parsed.ast, 11, allowed_tables=ALLOWED)


class TestQualify:
    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT id FROM auth_permission QUALIFY row_number() OVER "
            "(ORDER BY id) = 1",
            # Review round 4: inside a subquery the injected LIMIT does not
            # reach it, so the old end-of-render check let it through.
            "SELECT id FROM auth_permission WHERE id IN (SELECT id FROM "
            "auth_permission QUALIFY row_number() OVER (ORDER BY id) <= 2 "
            "LIMIT 5)",
            "WITH c AS (SELECT id FROM auth_permission QUALIFY row_number() "
            "OVER (ORDER BY id) > 3 LIMIT 2) SELECT id FROM c",
        ],
        ids=["root", "subquery", "cte"],
    )
    def test_refused_anywhere(self, sql):
        _expect_reject(sql, OutcomeReason.PARSE_ERROR)
        # The clause is what is refused: the same query without it passes.
        without = re.sub(
            r" ?QUALIFY row_number\(\) OVER \(ORDER BY id( DESC)?\) [<>=]+ \d+",
            "",
            sql,
        )
        assert "QUALIFY" not in without
        parse_and_validate(without, allowed_tables=ALLOWED)

    def test_qualify_is_an_ordinary_name(self):
        # Review round 5: `qualify` is a name to Postgres (`FROM t qualify`).
        parse_and_validate(
            "SELECT qualify.id FROM auth_permission qualify", allowed_tables=ALLOWED
        )


class TestTableValuedFunctionsInFrom:
    """A FROM-clause table-valued function parses as `exp.Table(name="")`, so
    the whitelist check would pass it trivially and the function deny-list
    (which it reaches only AFTER `_check_tables`) never sees it. `_check_tables`
    rejects the empty-name Table first — `dblink` is an egress channel,
    `generate_series` a DoS amplifier."""

    def test_dblink_in_from_rejected(self):
        exc = _expect_reject(
            "SELECT 1 FROM dblink('host=evil', 'SELECT 1') AS t(a int)",
            OutcomeReason.DISALLOWED_CONSTRUCT,
        )
        assert "Table-valued functions in FROM" in str(exc)

    def test_generate_series_in_from_rejected(self):
        exc = _expect_reject(
            "SELECT 1 FROM generate_series(1, 1000000000) g",
            OutcomeReason.DISALLOWED_CONSTRUCT,
        )
        assert "Table-valued functions in FROM" in str(exc)


class TestNoTableQuery:
    def test_tableless_select_passes(self):
        # No FROM → no table aliases; the whole-row-ref guard returns early
        # (nothing to compare against) and the query is accepted.
        out = parse_and_validate("SELECT 1", allowed_tables=set())
        assert out.referenced_tables == set()


class TestLexicalFidelity:
    """Input whose sqlglot re-serialization would not mean the same thing to
    Postgres is rejected as UNSAFE_LITERAL (ledger F32 and variants)."""

    @pytest.mark.parametrize(
        "sql",
        [
            # E'\\' (one backslash) re-emits as e'\', swallowing its quote.
            "SELECT E'\\\\' AS v, 'AS w, codename FROM auth_group --' AS x "
            "FROM auth_permission",
            "SELECT e'a\\nb' AS v FROM auth_permission",
            "SELECT E'\\x27' AS v FROM auth_permission",
            "SELECT E'\\u0027' AS v FROM auth_permission",
            "SELECT E'\\'' AS v FROM auth_permission",
            "SELECT id FROM auth_permission WHERE codename = E'a\\\\nb'",
        ],
        ids=["quote-swallow", "newline", "hex", "unicode", "escaped-quote", "where"],
    )
    def test_escape_string_with_backslash(self, sql):
        _expect_reject(sql, OutcomeReason.UNSAFE_LITERAL)

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT 1 AS $$x, version() AS v$$ FROM auth_permission",
            "SELECT 1 AS $t$x FROM pg_class --$t$ FROM auth_permission",
            "SELECT 1 AS $$x; RESET ROLE; SELECT 1 --$$ FROM auth_permission",
            "SELECT 1 AS $$plain$$ FROM auth_permission",
            "SELECT id FROM auth_permission AS $t$p$t$",
            "SELECT 1 AS 'lit' FROM auth_permission",
        ],
        ids=[
            "extra-projection",
            "comment-tail",
            "multi-statement",
            "plain-dollar",
            "table-alias",
            "string",
        ],
    )
    def test_identifier_written_as_a_string_constant(self, sql):
        _expect_reject(sql, OutcomeReason.UNSAFE_LITERAL)

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT U&'d\\0061t' AS v FROM auth_permission",
            "SELECT u&'x' AS v FROM auth_permission",
            'SELECT U&"x" AS v FROM auth_permission',
            "SELECT id FROM auth_permission WHERE codename = U&'2'",
        ],
    )
    def test_unicode_escape(self, sql):
        _expect_reject(sql, OutcomeReason.UNSAFE_LITERAL)

    @pytest.mark.parametrize(
        "sql",
        [
            # Names sqlglot still folds onto its own nodes (typed functions
            # and keyword-syntax functions): they would run unquoted.
            'SELECT "count" (*) AS n FROM auth_permission',
            'SELECT "Count"(id) AS n FROM auth_permission',
            "SELECT \"Extract\"(year FROM DATE '2024-01-01') AS v",
            "SELECT \"substring\"('abc' FROM 2) AS v",
            # Wherever it appears (review round 4: after AS, ZONE, BOTH, ...).
            'SELECT "Count"(id) AS (c) FROM auth_permission',
            'SELECT now() AT TIME ZONE "Extract"(year FROM now()) AS v',
            "SELECT trim(BOTH \"Count\"(id)::text FROM 'x') AS v FROM auth_permission",
        ],
    )
    def test_quoted_function_name(self, sql):
        _expect_reject(sql, OutcomeReason.UNSAFE_LITERAL)

    @pytest.mark.parametrize(
        "sql",
        [
            'SELECT "Lower"(codename) AS v FROM auth_permission',
            'SELECT "public"."lower"(codename) AS v FROM auth_permission',
            "SELECT \"Lower\"('AbC') AS (c)",
            "SELECT now() AT TIME ZONE \"Lower\"('UTC') AS v",
        ],
    )
    def test_quoted_function_name_kept_as_written(self, sql):
        # Every other call is kept as written (`FaithfulPostgres`), quotes
        # included, so Postgres resolves the name exactly as in the source.
        parsed = parse_and_validate(sql, allowed_tables=ALLOWED)
        rendered = render_for_execution(parsed.ast, 5, allowed_tables=ALLOWED)
        quoted = sql[sql.index('"') : sql.index("(", sql.index('"'))]
        assert quoted in rendered

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT 'a' 'b' AS v FROM auth_permission",
            "SELECT 'a'\n'b' AS v FROM auth_permission",
            "SELECT id FROM auth_permission WHERE codename = 'a' /* c */\n'b'",
        ],
        ids=["same-line", "newline", "comment-newline"],
    )
    def test_adjacent_string_constants(self, sql):
        _expect_reject(sql, OutcomeReason.UNSAFE_LITERAL)

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT $u&$a, 2 AS y$u&$ AS v FROM auth_permission",
            "SELECT $1t$x$1t$ AS v FROM auth_permission",
        ],
        ids=["ampersand", "leading-digit"],
    )
    def test_dollar_tag_postgres_rejects(self, sql):
        _expect_reject(sql, OutcomeReason.UNSAFE_LITERAL)

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT id & 3 AS v FROM auth_permission",
            'SELECT c1 FROM (SELECT 1) AS "s"(c1)',
            'SELECT c1 FROM (SELECT 1) "s"(c1)',
            'SELECT c FROM auth_permission "p"(c)',
            'WITH "q"(c1) AS (SELECT 1) SELECT c1 FROM "q"',
            'WITH a AS (SELECT 1 AS x), "q"(c1) AS NOT MATERIALIZED (SELECT 1) '
            'SELECT c1 FROM "q"',
            'SELECT id::"numeric"(10, 2) AS v FROM auth_permission',
            'SELECT CAST(id AS "Numeric"(10, 2)) AS v FROM auth_permission',
            'SELECT codename AS "Lower" FROM auth_permission',
            "SELECT 'a' || 'b' AS v FROM auth_permission",
            "SELECT $t1$x$t1$ AS v, $$y$$ AS w FROM auth_permission",
        ],
        ids=[
            "bitwise-and",
            "derived-column-list",
            "derived-column-list-no-as",
            "table-alias-column-list",
            "cte-column-list",
            "later-cte-column-list",
            "quoted-type-modifiers",
            "quoted-type-modifiers-cast",
            "quoted-alias",
            "concat-operator",
            "dollar-tags",
        ],
    )
    def test_near_misses_are_accepted(self, sql):
        parse_and_validate(sql, allowed_tables=ALLOWED)

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT E'it''s' AS v FROM auth_permission",
            "SELECT 'a\\b' AS v FROM auth_permission",
            "SELECT $$it's$$ AS v FROM auth_permission",
            'SELECT codename AS "a b"" c" FROM auth_permission',
            "SELECT codename AS é_x$1 FROM auth_permission",
        ],
        ids=[
            "escape-string-no-backslash",
            "standard-string",
            "dollar-string",
            "quoted-alias",
            "unicode-alias",
        ],
    )
    def test_faithful_forms_are_accepted(self, sql):
        parse_and_validate(sql, allowed_tables=ALLOWED)

    def test_before_every_ast_check(self):
        # The checked tree cannot be trusted to be what runs, so this names
        # the problem ahead of the table / system-schema checks.
        _expect_reject("SELECT E'\\\\' FROM pg_class", OutcomeReason.UNSAFE_LITERAL)


class TestIntervalsAndSubscriptsAsWritten:
    """Review round 9: interval qualifiers and array subscripts, rendered as
    Postgres reads them."""

    @staticmethod
    def _rendered(sql: str) -> str:
        parsed = parse_and_validate(sql, allowed_tables=ALLOWED)
        return render_for_execution(parsed.ast, 11, allowed_tables=ALLOWED)

    @pytest.mark.parametrize(
        ("sql", "rendered"),
        [
            # A quoted word is an alias, not a field: 25 hours, not 0 days.
            ("""SELECT INTERVAL '25 hours' "DAY\"""", 'AS "DAY"'),
            ("""SELECT INTERVAL '1' "day\"""", """INTERVAL '1' AS "day\""""),
            ("""SELECT INTERVAL '1' DAY "TO\"""", """INTERVAL '1' DAY AS "TO\""""),
            # The precision of a seconds field (1.23 s, not a parse error).
            ("SELECT INTERVAL '1.234' SECOND(2)", "INTERVAL '1.234' SECOND(2)"),
            ("SELECT INTERVAL '1.234' SECOND (2)", "INTERVAL '1.234' SECOND(2)"),
            ("SELECT INTERVAL '1' DAY TO SECOND(3)", "INTERVAL '1' DAY TO SECOND(3)"),
            # The precision form: 1.235 s, not `INTERVAL '3' + INTERVAL ...`.
            ("SELECT INTERVAL(3) '1.23456'", "INTERVAL(3) '1.23456'"),
            (
                """SELECT INTERVAL(3) '1.5' "SECOND\"""",
                """INTERVAL(3) '1.5' AS "SECOND\"""",
            ),
        ],
    )
    def test_interval(self, sql, rendered):
        assert rendered in self._rendered(sql)

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT INTERVAL(3) '1.5' SECOND",
            # Postgres takes a precision on a seconds field only.
            "SELECT INTERVAL '1' DAY(3)",
            # A quoted alias, then a second one: Postgres's syntax error too.
            """SELECT INTERVAL '1' "Day" AS v""",
        ],
    )
    def test_interval_syntax_postgres_rejects(self, sql):
        _expect_reject(sql, OutcomeReason.PARSE_ERROR)

    @pytest.mark.parametrize(
        "sql",
        [
            # A column named `array` / `list`, subscripted: sqlglot replaced
            # it with the constructor `ARRAY[1]`.
            'SELECT s."array"[1] FROM (SELECT ARRAY[5, 6] AS "array") AS s',
            'SELECT "array"[1] FROM (SELECT ARRAY[5, 6] AS "array") AS s',
            'SELECT s.array[1] FROM (SELECT ARRAY[5, 6] AS "array") AS s',
            "SELECT list[1] FROM (SELECT ARRAY[5, 6] AS list) AS s",
            "SELECT (ARRAY[1, 2])[1]",
            "SELECT (ARRAY(SELECT 1))[1]",
        ],
    )
    def test_subscript_kept(self, sql):
        assert self._rendered(sql) == f"{sql} LIMIT 11"

    @pytest.mark.parametrize(
        "sql",
        [
            # Postgres subscripts an array constructor only in parentheses;
            # sqlglot added them, or dropped the query of `ARRAY(SELECT ...)`.
            "SELECT ARRAY[1, 2][1]",
            "SELECT ARRAY[[1, 2], [3, 4]][1][2]",
            "SELECT json_object(ARRAY['a', 'b'][1:2]) AS a",
            "SELECT ARRAY(SELECT 1)[1]",
        ],
    )
    def test_unparenthesised_constructor_subscript_is_a_parse_error(self, sql):
        _expect_reject(sql, OutcomeReason.PARSE_ERROR)


class TestPinnedBehaviour:
    """Review round 10: behaviour no test pinned (its mutant survived)."""

    _PG_SLEEP_COLUMN = {"auth_permission": frozenset({"pg_sleep", "id"})}

    @pytest.mark.parametrize(
        ("sql", "columns"),
        [
            # An alias column list renames the first columns; the old name
            # is gone, so `s.pg_sleep` is `pg_sleep(s)` to Postgres.
            ("SELECT s.pg_sleep FROM (SELECT 1 AS pg_sleep) s(a)", None),
            # The same for a whitelisted table's model columns.
            ("SELECT x.pg_sleep FROM auth_permission AS x(a)", _PG_SLEEP_COLUMN),
            ("SELECT x.pg_sleep FROM auth_permission AS x(a, b)", _PG_SLEEP_COLUMN),
        ],
    )
    def test_a_renamed_column_is_gone(self, sql, columns):
        _expect_reject(sql, OutcomeReason.DISALLOWED_FUNCTION, table_columns=columns)

    @pytest.mark.parametrize(
        ("sql", "columns"),
        [
            ("SELECT s.a FROM (SELECT 1 AS pg_sleep) s(a)", None),
            ("SELECT x.pg_sleep FROM auth_permission AS x", _PG_SLEEP_COLUMN),
            # Output names through a cast and a subscript.
            (
                "SELECT s.pg_sleep FROM (SELECT x.pg_sleep::text "
                "FROM (SELECT 1 AS pg_sleep) x) s",
                None,
            ),
            (
                "SELECT s.pg_sleep FROM (SELECT (x.pg_sleep)[1] "
                "FROM (SELECT ARRAY[1] AS pg_sleep) x) s",
                None,
            ),
            # Postgres ends an operator at `--` / `/*`.
            ("SELECT 2 +-- c\n3 AS v", None),
            ("SELECT 2 */*c*/3 AS v", None),
            # `qualify` as a window name.
            (
                "SELECT sum(id) OVER qualify AS s FROM auth_permission "
                "WINDOW qualify AS (ORDER BY id)",
                None,
            ),
        ],
    )
    def test_accepted(self, sql, columns):
        parse_and_validate(sql, allowed_tables=ALLOWED, table_columns=columns)

    def test_select_star_columns_are_not_known(self):
        # With the `SELECT *` ban off, a `*` item's columns are unknown, so
        # `(s).pg_sleep` may be `pg_sleep(s)` on a column `s`.
        _expect_reject(
            "SELECT (s).pg_sleep FROM (SELECT 1 AS pg_sleep, * FROM auth_permission) s",
            OutcomeReason.DISALLOWED_FUNCTION,
            ban_select_star=False,
        )

    def test_star_field_is_a_column(self):
        parse_and_validate(
            "SELECT (s.*).pg_sleep FROM (SELECT 1 AS pg_sleep) s",
            allowed_tables=ALLOWED,
            ban_select_star=False,
        )


class TestCheckOrdering:
    """Order of checks matters for the audit reason. Security-relevant
    reasons must win over ergonomic ones so the audit row names the actual
    problem, not an incidental one."""

    def test_system_schema_with_qualify_as_a_name(self):
        # Review round 7: `qualify` is an ordinary name, so the tree is
        # built and the catalog reference is what the audit row names.
        _expect_reject("SELECT id FROM pg_class qualify", OutcomeReason.SYSTEM_SCHEMA)

    def test_text_postgres_cannot_parse_is_a_parse_error_first(self):
        # A QUALIFY clause is a syntax error to Postgres as to the parser:
        # there is no tree to run the other checks on.
        _expect_reject(
            "SELECT id FROM pg_class QUALIFY row_number() OVER () = 1",
            OutcomeReason.PARSE_ERROR,
        )

    def test_writeable_cte_before_returning(self):
        # DELETE RETURNING inside a CTE: the WRITEABLE_CTE name is the real
        # problem; the RETURNING is a side-effect of the DELETE.
        _expect_reject(
            ("WITH a AS (DELETE FROM auth_permission RETURNING id) SELECT id FROM a"),
            OutcomeReason.WRITEABLE_CTE,
        )

    def test_system_schema_before_select_star(self):
        # `SELECT * FROM pg_class` could fire SELECT_STAR or SYSTEM_SCHEMA;
        # the catalog access is the more severe of the two.
        _expect_reject("SELECT * FROM pg_class", OutcomeReason.SYSTEM_SCHEMA)
