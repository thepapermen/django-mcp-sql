"""Closed-vocabulary outcome codes + agent-facing hint map + the executor's
return type. Imported by parser and executor; deliberately Django-free so
the closed enum stays usable from any MCP adapter."""

from dataclasses import dataclass
from dataclasses import field
from enum import StrEnum

# Kept in sync with `session.EXPECTED_SESSION_GUCS["statement_timeout"]` via
# `test_constants.py`. Hardcoded so this module stays Django-free.
_STATEMENT_TIMEOUT_TEXT = "5s"


class AuthRejectionReason(StrEnum):
    """Closed vocabulary written to `MCPAuthRejectionLog.reason`.

    Mirrors `OutcomeReason`'s shape (`StrEnum`, bare values — the
    `auth_` semantic is carried by the table name, not by the values).
    Phase 4's revoked-credential / removed-MFA / dead-session alert
    filters by these short codes.

    **Anonymous probing is deliberately NOT in this enum.** Bad / expired
    / unknown bearer tokens (DOT's `result is None` path) are high-volume
    and resolve to no user — auditing them to the default DB would write-
    amplify under sustained bot probing and bloat the audit table without
    adding signal that the request-edge layer can't carry. Phase 4 wires
    that signal through django-axes-on-Redis (already configured in the
    project for password-login throttling: `AXES_FAILURE_LIMIT=8`,
    `AXES_COOLOFF_TIME=1h`, `AXES_CACHE='default'`). This table records
    **resolved-user access-ending events** — every row names a real user
    and is one of: a per-request gate denial (revoked perm, removed MFA,
    dead session, rogue-Application token, scope drift) or a logout-driven
    token revocation (`SESSION_LOGOUT`). Both answer "when/why did this
    user lose MCP access?"; both are keyed to a real user, so anonymous
    probing stays out of the enum and the table.
    """

    BAD_APPLICATION = "bad_application"
    BAD_SCOPE = "bad_scope"
    INACTIVE_OR_NON_STAFF = "inactive_or_non_staff"
    NO_MFA = "no_mfa"
    NO_PERM = "no_perm"
    # User holds >1 MCP profile permission, so the single-profile bind is
    # ambiguous. Fail-closed deny (never guess a tier) — `conf.resolve_profile`
    # returns `ResolutionOutcome.AMBIGUOUS_PROFILE`. The paging signal fires
    # once at ASSIGNMENT time (`signals.py`), not per request.
    AMBIGUOUS_PROFILE = "ambiguous_profile"
    NO_SESSION = "no_session"
    # Not a denial: the `user_logged_out` signal revoked the user's MCP
    # tokens. Recorded here alongside the gate denials so the audit table
    # carries a complete access-ending timeline — see
    # `signals.revoke_mcp_tokens_on_logout`.
    SESSION_LOGOUT = "session_logout"


class OutcomeReason(StrEnum):
    """Closed vocabulary written to `MCPQueryLog.rejection_reason`.

    The set covers non-rejection outcomes too (`EXECUTION_ERROR`,
    `TIMEOUT`, `MISCONFIGURED` fire after the parser passed and the SELECT
    actually ran), so "outcome" is the accurate noun. The audit-table field
    keeps the name `rejection_reason` to avoid the migration cost of
    renaming a column.
    """

    PARSE_ERROR = "parse_error"
    MULTI_STATEMENT = "multi_statement"
    NON_SELECT_ROOT = "non_select_root"
    SELECT_STAR = "select_star"
    DISALLOWED_TABLE = "disallowed_table"
    DISALLOWED_FUNCTION = "disallowed_function"
    DISALLOWED_CONSTRUCT = "disallowed_construct"
    SYSTEM_SCHEMA = "system_schema"
    WRITEABLE_CTE = "writeable_cte"
    SELECT_INTO = "select_into"
    EXECUTION_ERROR = "execution_error"
    TIMEOUT = "timeout"
    MISCONFIGURED = "misconfigured"


class ToolName(StrEnum):
    """Closed vocabulary written to `MCPQueryLog.tool` — the MCP tool that
    produced the audit row.

    Values match the FastMCP tool function names registered in
    `views.mcp_endpoint._build_mcp_server` (`tools/list` reports the same
    strings). `RUN_QUERY` is the executor's path and the model-field default
    (every pre-`tool`-field row was an executor write); `LIST_TABLES` /
    `DESCRIBE_TABLE` are the metadata tools, which record via
    `executor.audit_tool_call` since they never enter the readonly executor.
    """

    RUN_QUERY = "run_query"
    LIST_TABLES = "list_tables"
    DESCRIBE_TABLE = "describe_table"


# `truncated` is not an outcome — kept under the same map for one-stop lookup.
HINTS: dict[str, str] = {
    OutcomeReason.PARSE_ERROR: (
        "SQL did not parse. Submit a single Postgres-dialect SELECT statement."
    ),
    OutcomeReason.MULTI_STATEMENT: (
        "Only one statement per query. Submit them separately."
    ),
    OutcomeReason.NON_SELECT_ROOT: (
        "Only SELECT (or a read-only CTE wrapping a SELECT) is allowed. "
        "DDL, DML, EXPLAIN, CALL, DO, and SELECT INTO are rejected."
    ),
    OutcomeReason.SELECT_STAR: (
        "SELECT * is rejected. Enumerate the columns you need explicitly."
    ),
    OutcomeReason.DISALLOWED_TABLE: (
        "Query references a table that is not on the MCP whitelist. "
        "Use `list_tables` to see what is reachable."
    ),
    OutcomeReason.DISALLOWED_FUNCTION: (
        "Query uses a denied function (e.g. pg_read_file, dblink_*, lo_*, "
        "copy, current_setting). Those bypass the read-only contract."
    ),
    OutcomeReason.SYSTEM_SCHEMA: (
        "Catalogs (pg_catalog, information_schema, pg_*) are off limits. "
        "Use `list_tables` to see what is reachable."
    ),
    OutcomeReason.WRITEABLE_CTE: (
        "CTEs must be read-only. INSERT/UPDATE/DELETE inside a WITH clause is "
        "rejected even when the outer statement is a SELECT."
    ),
    OutcomeReason.SELECT_INTO: "SELECT INTO writes a new table. Use SELECT only.",
    OutcomeReason.DISALLOWED_CONSTRUCT: (
        "The SQL uses a construct that is not supported on the MCP surface. "
        "See `error` for the specific construct and the recommended "
        "alternative."
    ),
    OutcomeReason.EXECUTION_ERROR: (
        "Postgres rejected the query at execution time. See `error` for detail."
    ),
    OutcomeReason.TIMEOUT: (
        f"Statement exceeded the {_STATEMENT_TIMEOUT_TEXT} timeout. "
        "Add filters or aggregate."
    ),
    OutcomeReason.MISCONFIGURED: (
        "The MCP read-only surface is misconfigured server-side. This is an "
        "operator issue, not a query issue. Notify the operators; retrying "
        "will not help until they fix it."
    ),
    "truncated": (
        "Result truncated. Prefer aggregation (COUNT/GROUP BY/MAX/MIN) over "
        "pagination. For genuine result-set walking, use keyset pagination in "
        "your SQL: WHERE id > <last_seen_id> ORDER BY id LIMIT N. There is no "
        "OFFSET / FETCH / cursor / fetch_next; those are intentionally absent."
    ),
}


@dataclass(frozen=True)
class QueryResult:
    """Immutable result returned by the executor.

    Frozen so callers cannot mutate audit-relevant fields after the
    executor has computed them; FastMCP's `asdict(result)` does not need
    mutation. Field semantics: successful → `rejection_reason==''` and
    `error==''`; parser/AST rejection → `rejection_reason` set + empty
    rows; execution error → `rejection_reason in {'execution_error',
    'timeout'}` + `error` set + empty rows. `hint` always carries an
    agent-facing message (possibly empty).
    """

    columns: list[str] = field(default_factory=list)
    rows: list[list] = field(default_factory=list)
    row_count: int = 0
    truncated: bool = False
    duration_ms: int = 0
    hint: str = ""
    rejection_reason: str = ""
    error: str = ""
