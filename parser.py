"""sqlglot AST validators for the MCP read-only SQL surface. Pure (no DB,
no Django imports). See `docs/architecture.md` for design /
"Watch out" / parser-check ordering rules."""

from dataclasses import dataclass

import sqlglot
import sqlglot.errors
from sqlglot import exp

from mcp_sql.schemas import OutcomeReason

DENIED_FUNCTIONS_EXACT: frozenset[str] = frozenset(
    {
        "copy",
        "current_setting",
        "set_config",
        # `dblink(text, text)` — bare two-arg overload — opens a one-shot
        # PG connection to an arbitrary remote host and ships SQL there.
        # The `dblink_*` prefix below catches `dblink_open` /
        # `dblink_connect` / `dblink_exec`, but the bare `dblink` is an
        # exact-name function. If the extension is installed, an MCP token
        # holder could exfiltrate through the DB host's network.
        "dblink",
        # `query_to_xml(text, ...)`, `table_to_xml(regclass, ...)`,
        # `cursor_to_xml(...)` and their `_schema` / `_and_xmlschema`
        # variants accept SQL as a text argument and EXECUTE it under
        # `mcp_readonly_role`. The inner SQL never enters this parser, so
        # every whitelist / SELECT_* / deny-list check is bypassed for the
        # nested query. The outer query also returns one XML scalar, so
        # per-row truncation is meaningless and per-cell byte cap is the
        # only remaining brake. Reject at the wrapper layer.
        "query_to_xml",
        "query_to_xmlschema",
        "query_to_xml_and_xmlschema",
        "table_to_xml",
        "table_to_xmlschema",
        "table_to_xml_and_xmlschema",
        "cursor_to_xml",
        "cursor_to_xmlschema",
        # Server-state / identity leaks. PG returns version banners, role
        # names, and network topology via these built-ins — useful for an
        # attacker doing reconnaissance about what role the executor runs
        # as (the post-`SET LOCAL ROLE` view is `mcp_readonly_role`, but
        # `session_user` still leaks the underlying app login role) or
        # what PG version / patchset is deployed (CVE targeting).
        # None of these are needed by an LLM-driven business-table query.
        # Both spellings are listed where sqlglot maps the user-facing
        # form to a different canonical SQL name (e.g. `version()` parses
        # as `exp.CurrentVersion` whose `sql_name()` is `CURRENT_VERSION`).
        "version",
        "current_version",
        "current_database",
        "current_schema",
        "current_schemas",
        "current_user",
        "session_user",
        "user",
        "current_role",
        "current_catalog",
        "inet_server_addr",
        "inet_server_port",
        "inet_client_addr",
        "inet_client_port",
        "txid_current",
        "txid_current_snapshot",
        "row_security_active",
        # Sequence introspection / mutation. `mcp_readonly_role` has no
        # UPDATE grants so `setval` / `nextval` already 42501 at PG; the
        # parser-layer reject yields a clearer audit reason and stops
        # `currval`-style introspection too.
        "nextval",
        "setval",
        "currval",
    }
)
# Bare-keyword PG built-ins parse as `exp.Column(name=<keyword>, table=None)`
# when written without parentheses (`SELECT current_user` not
# `SELECT current_user()`). The function-deny-list walk doesn't see Column
# nodes, so the bare form would otherwise leak right past it.
DENIED_BARE_KEYWORDS: frozenset[str] = frozenset(
    {
        "current_user",
        "session_user",
        "user",
        "current_role",
        "current_catalog",
        "current_schema",
        "current_database",
    }
)
# `pg_*` covers `pg_read_file`, `pg_ls_dir`, `pg_database_size`,
# `pg_relation_size`, `pg_get_userbyid`, `pg_typeof`, … — many leak server
# state or table metadata even when direct catalog reads are blocked at the
# role-grant layer. `has_*` covers `has_table_privilege` /
# `has_database_privilege` / … — those return per-(role, object) privilege
# bits and are introspection tools, not query helpers. Both prefixes are
# opt-out: there is no allowlist today, since an agent doing exploration of
# whitelisted business tables does not need any of them. Revisit if a
# legitimate use case appears.
DENIED_FUNCTIONS_PREFIX: tuple[str, ...] = ("dblink_", "lo_", "pg_", "has_")
# Set-returning functions (SRFs). In a FROM clause these are caught by the
# empty-name `exp.Table` guard in `_check_tables`; in the PROJECTION they are
# not, and they fan one input row out to many — `generate_series` is the
# unbounded DoS amplifier, the json/regexp expanders fan out by their input
# size. sqlglot maps `generate_series`/`unnest` to TYPED nodes
# (`exp.GenerateSeries` / `exp.UDTF`, matched structurally in
# `_check_no_denied_functions`); every other PG SRF parses as `exp.Anonymous`
# and is matched here by name. The LIMIT-injection + 5s `statement_timeout`
# already bound these — rejecting them at the parser yields a clean
# `DISALLOWED_CONSTRUCT` audit reason instead of a wasted backend slot, and an
# LLM business-table query never legitimately needs row-expansion built-ins.
# Not exhaustive of every PG SRF (extensions add more); the timeout/LIMIT
# backstop covers anything unlisted. Revisit if a legitimate use case appears.
DENIED_SRF_FUNCTIONS: frozenset[str] = frozenset(
    {
        "generate_subscripts",
        "regexp_split_to_table",
        "regexp_matches",
        "json_array_elements",
        "json_array_elements_text",
        "jsonb_array_elements",
        "jsonb_array_elements_text",
        "json_each",
        "json_each_text",
        "jsonb_each",
        "jsonb_each_text",
        "json_object_keys",
        "jsonb_object_keys",
        "json_to_recordset",
        "jsonb_to_recordset",
        "json_populate_recordset",
        "jsonb_populate_recordset",
    }
)
SYSTEM_SCHEMAS: frozenset[str] = frozenset({"pg_catalog", "information_schema"})


class QueryRejectedError(Exception):
    """Raised by `parse_and_validate` on any AST-layer reject.

    `reason` is the closed `OutcomeReason` value that goes into
    `MCPQueryLog.rejection_reason`. `detail` is the human message that
    surfaces in the `hint` field returned to the agent and in the audit
    row's `error` field for triage.
    """

    def __init__(self, reason: OutcomeReason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class ParsedQuery:
    """Immutable parser output. Frozen so executor never mutates the AST or
    normalised SQL between parsing and audit-row write."""

    ast: exp.Expression
    normalized_sql: str
    referenced_tables: set[str]


def parse_and_validate(
    raw_sql: str,
    *,
    allowed_tables: set[str],
    ban_select_star: bool = True,
) -> ParsedQuery:
    """Parse `raw_sql` and run every AST-layer check.

    `allowed_tables` is the set of `db_table` names the agent may read,
    pre-resolved by the caller (`mcp_sql.grants.declared_tables`).
    Matching is case-insensitive on the table name only (schema is rejected
    unconditionally when it's a system schema).
    """
    try:
        parsed = sqlglot.parse(raw_sql, dialect="postgres")
    except sqlglot.errors.ParseError as exc:
        raise QueryRejectedError(OutcomeReason.PARSE_ERROR, str(exc)) from exc
    except RecursionError as exc:
        # sqlglot's parser is recursive descent; a deeply-nested SELECT
        # (thousands of parens / subqueries, well within the auth-layer
        # 64 KiB body cap) overflows Python's recursion limit. RecursionError
        # is NOT a ParseError, so without this it escapes `run_query`'s
        # `except QueryRejectedError`, surfaces as an unaudited 500, and
        # tears down the per-request FastMCP lifespan mid-dispatch. Convert
        # it to a normal PARSE_ERROR reject so every adversarial input still
        # writes exactly one audit row. The handler does minimal work (a
        # short constant message) so it stays within the stack headroom
        # Python restores after the RecursionError.
        msg = "SQL nesting is too deep to parse"
        raise QueryRejectedError(OutcomeReason.PARSE_ERROR, msg) from exc

    # sqlglot emits `exp.Semicolon` nodes for trailing `;` and similar
    # whitespace artefacts. Filtering on `is not None` alone would treat
    # `SELECT 1;` as a two-statement payload and reject as MULTI_STATEMENT.
    statements = [
        p for p in parsed if p is not None and not isinstance(p, exp.Semicolon)
    ]
    if not statements:
        msg = "Empty SQL input"
        raise QueryRejectedError(OutcomeReason.PARSE_ERROR, msg)
    if len(statements) > 1:
        msg = f"Got {len(statements)} statements; only one is allowed"
        raise QueryRejectedError(OutcomeReason.MULTI_STATEMENT, msg)

    ast = statements[0]

    # Root must be a SELECT-shaped query (Select / Union / Intersect / Except).
    # exp.Query is the sqlglot base class for these; INSERT/UPDATE/DELETE and
    # Command-shaped statements (EXPLAIN, CALL, DO, SET, BEGIN, ...) are not.
    if not isinstance(ast, exp.Query):
        msg = f"Root is {type(ast).__name__}, not a SELECT-shaped query"
        raise QueryRejectedError(OutcomeReason.NON_SELECT_ROOT, msg)

    # Order matters: security-relevant checks fire before ergonomic ones so
    # the audit reason names the actual problem. WRITEABLE_CTE before any
    # RETURNING-bearing construct so a `WITH a AS (DELETE ... RETURNING ...)`
    # attributes to the writeable CTE, not the incidentally-present
    # RETURNING (which the bare top-level path can't reach anyway —
    # `exp.Returning` only appears under write nodes, which NON_SELECT_ROOT
    # rejects first). Tables before SELECT_STAR so `SELECT * FROM pg_class`
    # attributes to the system schema, not the ergonomic star rule.
    _check_ctes_read_only(ast)
    _check_no_recursive_cte(ast)
    _check_no_select_into(ast)
    _check_no_offset(ast)
    _check_no_fetch(ast)
    _check_no_locking_reads(ast)
    referenced_tables = _check_tables(ast, allowed_tables=allowed_tables)
    _check_no_denied_functions(ast)
    _check_no_bare_keyword_columns(ast)
    if ban_select_star:
        _check_no_select_star(ast)
        _check_no_whole_row_refs(ast)

    # The AST-walk checks above are iterative (sqlglot's `find_all` uses an
    # explicit stack), so they can't overflow. `Generator.sql()` recurses by
    # tree depth, though — a parseable-but-pathologically-deep AST can survive
    # `sqlglot.parse` yet overflow here. Convert that to a PARSE_ERROR reject
    # so `parse_and_validate` NEVER leaks `RecursionError` to its callers.
    try:
        normalized_sql = ast.sql(dialect="postgres", normalize=True)
    except RecursionError as exc:
        msg = "SQL nesting is too deep to serialize"
        raise QueryRejectedError(OutcomeReason.PARSE_ERROR, msg) from exc
    return ParsedQuery(
        ast=ast,
        normalized_sql=normalized_sql,
        referenced_tables=referenced_tables,
    )


def inject_limit(ast: exp.Expression, n: int) -> exp.Expression:
    """Replace any LIMIT on the root with `n`. Returns the modified AST.

    Uses sqlglot's `Expression.limit(n)`, which clobbers an existing LIMIT
    rather than appending. Idempotent; safe to re-emit via `.sql()`.
    """
    return ast.limit(n)


def extract_limit(ast: exp.Expression) -> int | None:
    """Return the integer LIMIT on the root expression, or `None` if absent
    or non-integer-literal.

    Used by the executor to honor a user-supplied `LIMIT N` smaller than
    the server's `DEFAULT_LIMIT` / `HARD_LIMIT`. Without this, the
    executor would clobber the user's `LIMIT 3` with `LIMIT 11` and the
    user gets 10 rows + `truncated=True` instead of 3 rows. The
    most-restrictive-wins resolution lives in `executor.run_query`; this
    function just reads what the user wrote.

    A `WITH ... SELECT ... LIMIT N` construct stores the LIMIT on the
    body `Select`, not on the wrapping `With`; this unwraps that case so
    the executor sees the user's intent. Non-literal LIMITs (parameter
    placeholders, expressions) return `None` — we can't reason about
    them at parse time, so the executor falls back to its own clamp.
    """
    body = ast.this if isinstance(ast, exp.With) else ast
    limit_node = body.args.get("limit") if hasattr(body, "args") else None
    if limit_node is None:
        return None
    expr = getattr(limit_node, "expression", None)
    if isinstance(expr, exp.Literal):
        try:
            return int(expr.this)
        except (TypeError, ValueError):
            return None
    return None


def _check_no_select_into(ast: exp.Expression) -> None:
    for sel in ast.find_all(exp.Select):
        if sel.args.get("into") is not None:
            msg = "SELECT INTO writes a new table and is not allowed"
            raise QueryRejectedError(OutcomeReason.SELECT_INTO, msg)


def _check_no_offset(ast: exp.Expression) -> None:
    """Reject OFFSET — there is no server-side pagination tool surface.

    The truncation `hint` already steers the agent toward keyset pagination
    (`WHERE id > <last_seen_id> ORDER BY id LIMIT N`); OFFSET would push
    them toward unstable, slow OFFSET pagination. Caught at parser layer so
    the audit row carries the right reason.
    """
    if ast.find(exp.Offset) is not None:
        msg = (
            "OFFSET is not supported. Use keyset pagination "
            "(WHERE id > <last_seen_id> ORDER BY id LIMIT N) instead."
        )
        raise QueryRejectedError(OutcomeReason.DISALLOWED_CONSTRUCT, msg)


def _check_no_fetch(ast: exp.Expression) -> None:
    """Reject `FETCH FIRST/NEXT N ROWS ONLY` — SQL-standard pagination.

    Cousin of OFFSET: same agent-friendly-but-server-hostile pattern. Use
    LIMIT N (which `inject_limit` clamps server-side anyway). Caught at
    parser layer so the closed "no pagination" promise in the truncation
    hint doesn't lie to the agent.
    """
    if ast.find(exp.Fetch) is not None:
        msg = (
            "FETCH FIRST/NEXT ROWS is not supported. Use LIMIT N instead; "
            "the server clamps it to the configured cap."
        )
        raise QueryRejectedError(OutcomeReason.DISALLOWED_CONSTRUCT, msg)


def _check_no_locking_reads(ast: exp.Expression) -> None:
    """Reject `FOR UPDATE` / `FOR SHARE` / `FOR NO KEY UPDATE` / `FOR KEY SHARE`.

    The `mcp_readonly_role` has no UPDATE / DELETE grants, so PG would
    reject these at execution. Catching at parser layer is defense in depth
    and yields a clearer audit reason than `EXECUTION_ERROR` would.
    """
    if ast.find(exp.Lock) is not None:
        msg = (
            "Locking reads (FOR UPDATE / FOR SHARE) are not supported on the "
            "read-only MCP surface."
        )
        raise QueryRejectedError(OutcomeReason.DISALLOWED_CONSTRUCT, msg)


def _check_ctes_read_only(ast: exp.Expression) -> None:
    for cte in ast.find_all(exp.CTE):
        body = cte.this
        if not isinstance(body, exp.Query):
            alias = cte.alias or "<unnamed>"
            msg = (
                f"CTE '{alias}' body is {type(body).__name__}; "
                "INSERT/UPDATE/DELETE inside WITH is not allowed"
            )
            raise QueryRejectedError(OutcomeReason.WRITEABLE_CTE, msg)


def _check_no_select_star(ast: exp.Expression) -> None:
    """Reject every `Star` that reaches a `Select` projection.

    Looking at `Star.parent` alone is not enough — three real bypass
    shapes nest the `Star` deeper than the direct parent:

    - `SELECT (t.*) FROM ... t`            — `Star → Column → Paren → Select`
    - `SELECT to_jsonb(t.*) FROM ... t`    — `Star → Column → Anonymous → Select`
    - `SELECT json_agg(t.*) FROM ... t`    — `Star → Column → Anonymous → Select`

    All three land every column of the referenced row in one scalar and
    would render the "agents must enumerate columns explicitly" defense
    cosmetic. The companion `_check_no_whole_row_refs` catches the
    no-Star variants (`row_to_json(t)`, `SELECT t`, `CAST(t AS TEXT)`,
    `json_agg(t)`).

    Walk the ancestor chain of every `Star`. If we hit `exp.Count` first,
    accept (the only PG aggregate that legitimately takes `*`). If we hit
    a `Select` first, reject — the Star is in a projection. Walking the
    chain (rather than picking specific node classes) is intentionally
    structural: any wrapper sqlglot introduces between projection and
    Star (Paren, Anonymous, Cast, …) is treated the same way.
    """
    for star in ast.find_all(exp.Star):
        cur = star.parent
        while cur is not None:
            if isinstance(cur, exp.Count):
                # COUNT(*) (and COUNT(DISTINCT *)) are the only typed
                # aggregate where `*` is the canonical argument. Every
                # other aggregate (SUM/AVG/MIN/MAX/...) takes a column
                # expression — `*` is either a parser-ambiguous shape
                # or a wrapped-row attempt. Restricting the carve-out
                # to Count keeps the rule narrow.
                break
            if isinstance(cur, exp.Select):
                qualifier = star.parent
                if isinstance(qualifier, exp.Column):
                    name = (
                        qualifier.args.get("table") and qualifier.args["table"].name
                    ) or "?"
                    msg = (
                        f"Qualified '{name}.*' is rejected; enumerate "
                        "columns explicitly"
                    )
                else:
                    msg = "Bare SELECT * is rejected; enumerate columns explicitly"
                raise QueryRejectedError(OutcomeReason.SELECT_STAR, msg)
            cur = cur.parent


def _check_no_whole_row_refs(ast: exp.Expression) -> None:
    """Reject bare-table-alias columns in any Select's projection list.

    The Star check above catches every shape with an `exp.Star` node, but
    several PG expressions return whole-row tuples without using `*`:

    - `SELECT t FROM ... t`              — bare row alias as a Column
    - `SELECT row_to_json(t) FROM ... t` — alias inside an Anonymous func
    - `SELECT to_jsonb(t) FROM ... t`
    - `SELECT json_agg(t) FROM ... t`
    - `SELECT array_agg(t) FROM ... t`
    - `SELECT CAST(t AS TEXT) FROM ... t` — PG renders the row as text

    All five land every column of the row in a single value. Same
    defense intent as the SELECT * ban; same audit reason
    (`SELECT_STAR`) so the agent's hint is consistent.

    Approach: build the set of every `Table.alias_or_name` anywhere in
    the AST (covers FROM and JOIN aliases plus CTE references), then for
    each `Select`'s projection list, recursively find every `exp.Column`
    that has no `table` qualifier and whose name matches a known alias.
    The match is conservative — a real column whose name collides with a
    FROM alias would be a false positive, but in practice curated-view
    columns do not collide with their own FROM aliases.
    """
    table_aliases: set[str] = set()
    for table in ast.find_all(exp.Table):
        alias_or_name = (table.alias_or_name or "").lower()
        if alias_or_name:
            table_aliases.add(alias_or_name)
    if not table_aliases:
        return

    for sel in ast.find_all(exp.Select):
        for projection in sel.expressions:
            for col in projection.find_all(exp.Column):
                if col.args.get("table") is not None:
                    # Qualified column (`t.id`, `auth_permission.codename`).
                    # The qualifier is the table alias; the column itself
                    # is not a whole-row reference.
                    continue
                col_name = (col.name or "").lower()
                if col_name in table_aliases:
                    msg = (
                        f"Bare reference to row alias '{col_name}' returns "
                        "the whole row; enumerate columns explicitly"
                    )
                    raise QueryRejectedError(OutcomeReason.SELECT_STAR, msg)


def _check_no_denied_functions(ast: exp.Expression) -> None:
    """Walk every function-call node and reject anything on the deny list.

    `exp.Func` is sqlglot's base class for both typed function nodes
    (`Count`, `Sum`, `CurrentUser`, `Version`, …) and `exp.Anonymous`
    (functions sqlglot has no canonical class for). The previous walk
    over `Anonymous` only missed typed nodes — `SELECT version()`,
    `SELECT current_user`, `SELECT inet_server_addr()` all parse as
    typed Func subclasses and bypassed the Anonymous-only check entirely.
    Walking `Func` covers both.

    Match on `.sql_name()` lowercased: sqlglot renders the canonical PG
    identifier regardless of how the user wrote it (camelCase, mixed
    case, dialect-quirky variants). For Anonymous nodes `.sql_name()`
    falls back to the `name` attribute.
    """
    for func in ast.find_all(exp.Func):
        # Set-returning / table functions used in the PROJECTION (not FROM)
        # escape the empty-name `exp.Table` guard in `_check_tables` (which
        # only sees them in a FROM clause). `generate_series` / `unnest` map to
        # TYPED sqlglot nodes whose `sql_name()` is an internal token, not the
        # user-facing name, so the name deny-list below cannot catch them —
        # match them on the public base classes instead (robust across sqlglot
        # versions). The remaining PG SRFs (json/regexp expanders) parse as
        # `exp.Anonymous` and fall through to `DENIED_SRF_FUNCTIONS` in the
        # name check below. `SELECT generate_series(1, 1e9)` is the documented
        # DoS-amplifier shape; the LIMIT-injection + 5s `statement_timeout`
        # already bound it, but rejecting it here yields a clean
        # `DISALLOWED_CONSTRUCT` audit reason instead of a wasted backend slot.
        if isinstance(func, (exp.GenerateSeries, exp.UDTF)):
            msg = (
                "Set-returning / table functions (e.g. generate_series, "
                "unnest) are not supported on the MCP surface; query a "
                "whitelisted table instead."
            )
            raise QueryRejectedError(OutcomeReason.DISALLOWED_CONSTRUCT, msg)
        # `exp.Anonymous` keeps the actual function name in `.name` (the
        # `this` arg); its `sql_name()` returns the useless "ANONYMOUS"
        # default. Typed Func subclasses (Count, CurrentUser, Version,
        # InetServerAddr, ...) put the canonical SQL identifier in
        # `sql_name()`; their `.name` is often the FIRST ARGUMENT (e.g.
        # `Count.name == '*'` for `COUNT(*)`), not the function name.
        # Pick the right attribute per node kind.
        name = (
            (func.name if isinstance(func, exp.Anonymous) else func.sql_name()) or ""
        ).lower()
        if not name:
            continue
        if name in DENIED_SRF_FUNCTIONS:
            # Anonymous-mapped set-returning functions (json/regexp expanders);
            # the typed SRFs are caught by the isinstance check above. Same
            # closed-construct audit reason so the two paths read alike.
            msg = (
                f"Set-returning function '{name}' is not supported on the MCP "
                "surface; query a whitelisted table instead."
            )
            raise QueryRejectedError(OutcomeReason.DISALLOWED_CONSTRUCT, msg)
        if name in DENIED_FUNCTIONS_EXACT:
            msg = f"Function '{name}' is on the deny list"
            raise QueryRejectedError(OutcomeReason.DISALLOWED_FUNCTION, msg)
        for prefix in DENIED_FUNCTIONS_PREFIX:
            if name.startswith(prefix):
                msg = f"Function '{name}' (prefix '{prefix}*') is on the deny list"
                raise QueryRejectedError(OutcomeReason.DISALLOWED_FUNCTION, msg)


def _check_no_bare_keyword_columns(ast: exp.Expression) -> None:
    """Reject parenthesis-less PG built-ins (`SELECT current_user FROM ...`).

    PG accepts several built-ins as bare identifiers — no parentheses.
    sqlglot parses these as `exp.Column(name='current_user', table=None)`,
    which the function-deny-list walk above cannot see (it only walks
    `exp.Func` nodes). The companion check here closes that gap by
    looking at unqualified Column nodes whose name matches a known
    server-identity keyword.

    Qualified Columns (`t.current_user` — i.e. an actual column happening
    to share a name with a PG keyword) are ignored: the qualifier proves
    the reference is to a table column, not the bare keyword form.
    """
    for col in ast.find_all(exp.Column):
        if col.args.get("table") is not None:
            continue
        name = (col.name or "").lower()
        if name in DENIED_BARE_KEYWORDS:
            msg = (
                f"Built-in '{name}' leaks server identity; the "
                "function-deny-list rejects both bare and parenthesised forms."
            )
            raise QueryRejectedError(OutcomeReason.DISALLOWED_FUNCTION, msg)


def _check_no_recursive_cte(ast: exp.Expression) -> None:
    """Reject `WITH RECURSIVE ...` queries.

    Recursive CTEs are a power-user feature unnecessary for the LLM-driven
    read-only use case. They also enable a parameterless DoS shape — the
    minimal `WITH RECURSIVE t(n,s) AS (VALUES (1, repeat('a', 4000))
    UNION ALL SELECT n+1, s||s FROM t WHERE n<30) SELECT n, s FROM t`
    burns memory exponentially up to `work_mem` x the statement_timeout
    window without ever referencing a whitelisted table (the only `Table`
    in the AST is the CTE alias `t`, which the table-whitelist check
    correctly skips). The recursive-CTE-no-table bypass cannot be closed
    by tightening the table check alone — it needs a structural reject
    here. Agents that need recursive aggregation should be rewritten as
    iterative GROUP BY / window functions.
    """
    for with_node in ast.find_all(exp.With):
        if with_node.args.get("recursive"):
            msg = (
                "WITH RECURSIVE is not supported on the MCP surface. "
                "Use iterative aggregation (GROUP BY, window functions) "
                "or escalate to operators."
            )
            raise QueryRejectedError(OutcomeReason.DISALLOWED_CONSTRUCT, msg)


def _resolves_to_cte(table: exp.Expression, name: str) -> bool:
    """True if `table`'s name resolves to a CTE that is IN SCOPE for it.

    CTE names are lexically scoped, so a flat "is this name a CTE anywhere
    in the statement" test is unsound: an inner-scoped CTE that happens to
    share a real table's name would mask an OUTER-scope reference to that
    real table, letting a non-whitelisted table slip past the whitelist
    check (the role grants still reject it, but the parser layer must not
    blindly defer). Confirmed bypass shape:

        SELECT s.x FROM secret_table s
        JOIN (WITH secret_table AS (SELECT 1 AS x) SELECT x FROM secret_table) q
        ON TRUE

    The outer `FROM secret_table` is a real table; the inner CTE only
    shadows the name *inside the subquery*. So resolve scope explicitly:
    walk the node's ancestors and treat `name` as a CTE reference only when
    an enclosing query defines a CTE of that name. sqlglot attaches a `WITH`
    to the query it decorates (a sibling of that query's `FROM`, not an
    ancestor of the table), so we read each ancestor query's `.ctes` — the
    public accessor that stays correct across sqlglot versions (the internal
    arg key for the `WITH` has changed between releases). Walking to the root
    query also covers a table inside a later CTE body referencing an earlier
    sibling CTE, since the owning query's `.ctes` lists both.
    """
    node = table.parent
    while node is not None:
        for cte in getattr(node, "ctes", ()):
            if cte.alias and cte.alias.lower() == name:
                return True
        node = node.parent
    return False


def _check_tables(
    ast: exp.Expression,
    *,
    allowed_tables: set[str],
) -> set[str]:
    """Validate every table reference and return the set of touched tables.

    References that resolve to an IN-SCOPE CTE are skipped (they look like
    `exp.Table(name='q')` but resolve to the CTE body, which has already
    been walked) — see `_resolves_to_cte` for why scope matters. System
    catalogs (`pg_catalog`, `information_schema`, anything in the `pg_*`
    namespace) are rejected even when nominally on the whitelist.
    """
    allowed_lower = {t.lower() for t in allowed_tables}
    referenced: set[str] = set()

    for table in ast.find_all(exp.Table):
        schema = (table.db or "").lower()
        name = (table.name or "").lower()
        if not name:
            # sqlglot represents table-valued constructs in FROM clauses
            # as `exp.Table(name="")` — `FROM generate_series(1, N)`,
            # `FROM unnest(...)`, `FROM json_to_recordset(...)`, and the
            # bare `FROM dblink(text, text)`. An empty-name Table would
            # satisfy the whitelist check trivially (no name to compare),
            # and the function deny-list only walks `exp.Anonymous` so
            # functions used as table-valued constructs in FROM never reach
            # it. Without this guard, `generate_series(1, 10_000_000)` is a
            # DoS amplifier and `dblink` is an egress channel. Reject as a
            # closed construct so the audit row carries `DISALLOWED_CONSTRUCT`
            # rather than a "table not on whitelist" misattribution.
            msg = (
                "Table-valued functions in FROM (e.g. generate_series, "
                "unnest, dblink, json_to_recordset) are not supported on "
                "the MCP surface; query a whitelisted table instead."
            )
            raise QueryRejectedError(OutcomeReason.DISALLOWED_CONSTRUCT, msg)
        if schema in SYSTEM_SCHEMAS or schema.startswith("pg_"):
            msg = f"Schema '{schema}' is off limits"
            raise QueryRejectedError(OutcomeReason.SYSTEM_SCHEMA, msg)
        if not schema and name.startswith("pg_"):
            msg = f"Table '{name}' is in the pg_* namespace"
            raise QueryRejectedError(OutcomeReason.SYSTEM_SCHEMA, msg)
        if _resolves_to_cte(table, name):
            continue
        if name not in allowed_lower:
            msg = f"Table '{name}' is not on the MCP whitelist"
            raise QueryRejectedError(OutcomeReason.DISALLOWED_TABLE, msg)
        referenced.add(name)
    return referenced
