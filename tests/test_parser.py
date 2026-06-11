"""Unit tests for `mcp_sql.parser`.

Pure AST-layer tests: no DB, no Django fixtures. Every rejection path has
a representative SQL example so the `OutcomeReason` vocabulary stays
exercised; happy paths cover JOIN, CTE, aggregation, ORDER BY, subquery,
UNION, and qualified column references to prove the validator doesn't
over-reject normal SELECT shapes.
"""

import pytest
from mcp_sql.parser import QueryRejectedError
from mcp_sql.parser import extract_limit
from mcp_sql.parser import inject_limit
from mcp_sql.parser import parse_and_validate
from mcp_sql.schemas import OutcomeReason
from sqlglot import exp
from sqlglot import parse_one

ALLOWED = {"auth_permission", "auth_group", "django_content_type"}


def _expect_reject(sql: str, reason: OutcomeReason, **kwargs) -> QueryRejectedError:
    allowed = kwargs.pop("allowed", ALLOWED)
    ban = kwargs.pop("ban_select_star", True)
    with pytest.raises(QueryRejectedError) as exc:
        parse_and_validate(sql, allowed_tables=allowed, ban_select_star=ban)
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

    def test_non_integer_literal_limit_gives_up_cleanly(self):
        # A string-literal LIMIT can't be reasoned about at parse time;
        # `extract_limit` returns None and the executor falls back to its clamp.
        ast = parse_one("SELECT id FROM auth_permission LIMIT '3 apples'")
        assert extract_limit(ast) is None

    def test_non_literal_limit_expression_gives_up_cleanly(self):
        # A LIMIT that is an expression (not a bare literal) is also opaque at
        # parse time — same clean give-up path.
        ast = parse_one("SELECT id FROM auth_permission LIMIT 2 + 3")
        assert extract_limit(ast) is None


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


class TestCheckOrdering:
    """Order of checks matters for the audit reason. Security-relevant
    reasons must win over ergonomic ones so the audit row names the actual
    problem, not an incidental one."""

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
