"""MCP read-only SQL executor. `run_query` is the only public entry point;
every code path writes exactly one `MCPQueryLog` row via `_audit_safely`.
See `docs/architecture.md` for the audit-invariant, the
limit-clamp / truncation contract, and the raw-PG-error policy."""

import json
import logging
from time import perf_counter_ns
from typing import TYPE_CHECKING

from django.conf import settings
from django.db import DatabaseError
from django.db import connections
from django.db import transaction
from django.utils import timezone

from mcp_sql import observability
from mcp_sql.conf import Profile
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.grants import declared_tables
from mcp_sql.models import MCPQueryLog
from mcp_sql.parser import QueryRejectedError
from mcp_sql.parser import extract_limit
from mcp_sql.parser import inject_limit
from mcp_sql.parser import parse_and_validate
from mcp_sql.schemas import HINTS
from mcp_sql.schemas import OutcomeReason
from mcp_sql.schemas import QueryResult
from mcp_sql.session import enter_readonly_session
from mcp_sql.session import validate_session_context

if TYPE_CHECKING:
    import datetime

    from django.contrib.auth.models import AbstractBaseUser

logger = logging.getLogger(__name__)

PG_QUERY_CANCELED_SQLSTATE = "57014"
PER_CELL_BYTE_CAP = 4096
TRUNCATION_MARK = "…[truncated]"


class ExecutorMisconfiguredError(RuntimeError):
    """The mcp_readonly alias is not configured / resolves to the wrong alias.

    Operator error, not a query failure — but a `MCPQueryLog` row is written
    before raising so the daily-volume alert and incident triage have one
    place to look. The row is `decision='rejected'`, `rejection_reason=
    'execution_error'`, `error=<misconfig reason>`."""


def run_query(  # noqa: PLR0913, PLR0915 — linear audited pipeline by design
    *,
    user: "AbstractBaseUser",
    profile: Profile,
    raw_sql: str,
    limit: int | None = None,
    token_id: str = "",
    client_ip: str | None = None,
) -> QueryResult:
    """Validate, execute, and audit a single read-only SQL query.

    `user` is required (audit FK is `on_delete=PROTECT`); `profile` is the
    bound access tier (its `ALLOWED_MODELS` become the table whitelist, its
    `role` is entered via `SET LOCAL ROLE`, its optional `SESSION_CONTEXT`
    hook sets per-row GUCs, and its name is recorded on the audit row).
    `token_id` and `client_ip` are optional. `limit` is clamped to
    `[DEFAULT_LIMIT, HARD_LIMIT]` from `MCP_SQL["LIMITS"]`.
    """
    started_at = timezone.now()
    db_alias = mcp_sql_settings.DB_ALIAS
    if db_alias not in connections.databases:
        msg = f"MCP_READONLY_DATABASE_URL is not configured; {db_alias} alias absent"
        _audit_misconfig(
            user=user,
            profile=profile,
            token_id=token_id,
            raw_sql=raw_sql,
            started_at=started_at,
            client_ip=client_ip,
            error=msg,
        )
        raise ExecutorMisconfiguredError(msg)

    limits = settings.MCP_SQL["LIMITS"]
    ban_select_star = settings.MCP_SQL["BAN_SELECT_STAR"]
    allowed = set(declared_tables(profile).values())

    try:
        parsed = parse_and_validate(
            raw_sql,
            allowed_tables=allowed,
            ban_select_star=ban_select_star,
        )
    except QueryRejectedError as exc:
        _audit_safely(
            user=user,
            profile=profile.name,
            token_id=token_id,
            decision=MCPQueryLog.DECISION_REJECTED,
            rejection_reason=exc.reason,
            raw_sql=raw_sql,
            started_at=started_at,
            client_ip=client_ip,
            error=exc.detail,
        )
        return QueryResult(
            rejection_reason=exc.reason,
            hint=HINTS.get(exc.reason, ""),
            error=exc.detail,
        )

    # Effective row cap = min(kwarg, SQL LIMIT, HARD_LIMIT), defaulting
    # to DEFAULT_LIMIT when neither caller-supplied source is set.
    # `limit=0` is the "metadata only" short-circuit; see `docs/architecture.md`
    # "Watch out: limit=0 is a valid metadata-only request".
    sql_limit = extract_limit(parsed.ast)
    explicit_limits = [n for n in (limit, sql_limit) if n is not None]
    min_explicit_limit = (
        min(explicit_limits) if explicit_limits else limits["DEFAULT_LIMIT"]
    )
    effective_limit = max(0, min(min_explicit_limit, limits["HARD_LIMIT"]))
    if effective_limit == 0:
        _audit_safely(
            user=user,
            profile=profile.name,
            token_id=token_id,
            decision=MCPQueryLog.DECISION_ALLOWED,
            rejection_reason="",
            raw_sql=raw_sql,
            normalized_sql=parsed.normalized_sql,
            wrapped_sql="",  # no SQL hit the DB
            started_at=started_at,
            duration_ms=0,
            row_count=0,
            truncated=False,
            result_bytes=0,
            client_ip=client_ip,
        )
        return QueryResult(row_count=0, duration_ms=0)
    # LIMIT-injection re-serializes (and may copy) the AST. `parse_and_validate`
    # already serialized this tree once for `normalized_sql`, so an overflow
    # here is a razor-thin edge (the +1 LIMIT node tipping a tree that barely
    # cleared the parser). Audit it as a parse-class reject anyway so the
    # "every code path writes exactly one audit row" invariant holds with no
    # `RecursionError` escaping to the agent as an unaudited 500.
    try:
        wrapped_sql = inject_limit(parsed.ast, effective_limit + 1).sql(
            dialect="postgres"
        )
    except RecursionError:
        msg = "SQL nesting is too deep to serialize"
        _audit_safely(
            user=user,
            profile=profile.name,
            token_id=token_id,
            decision=MCPQueryLog.DECISION_REJECTED,
            rejection_reason=OutcomeReason.PARSE_ERROR,
            raw_sql=raw_sql,
            normalized_sql=parsed.normalized_sql,
            started_at=started_at,
            client_ip=client_ip,
            error=msg,
        )
        return QueryResult(
            rejection_reason=OutcomeReason.PARSE_ERROR,
            hint=HINTS.get(OutcomeReason.PARSE_ERROR, ""),
            error=msg,
        )

    # Defense-in-depth alias assertion: the router pins audit writes back to
    # `default`, but it can't intercept a stale `connections[...]` reference,
    # and a misconfigured DATABASES dict could remap the readonly alias to a
    # writeable connection. The role grants are still the real boundary, but
    # surfacing the wrong alias loudly here beats silently exfiltrating
    # through a connection that lacks the readonly session GUCs.
    if connections[db_alias].alias != db_alias:
        msg = f"connections[{db_alias!r}] resolved to a different alias"
        _audit_misconfig(
            user=user,
            profile=profile,
            token_id=token_id,
            raw_sql=raw_sql,
            started_at=started_at,
            client_ip=client_ip,
            error=msg,
        )
        raise ExecutorMisconfiguredError(msg)

    # Dormant by default: only profiles that wire a SESSION_CONTEXT hook
    # produce GUCs here. The resolved callable is consumer code — ANY
    # exception it raises, and any malformed result it returns (non-Mapping,
    # GUC name outside `mcp_sql.*`), must still produce exactly one audit
    # row (this module's invariant), never escape to the MCP transport as an
    # unaudited 500. The result is validated EAGERLY here, before any DB
    # work, so hook problems can never raise from inside the read
    # transaction — where a broad except would also catch agent-triggerable
    # driver exceptions (psycopg2 typecasters raise bare ValueError from
    # `fetchall` for values PG accepts but Python types don't, e.g.
    # `'24:00'::time`) and misclassify them as misconfiguration.
    try:
        session_ctx = (
            profile.session_context(user, profile) if profile.session_context else None
        )
        if session_ctx is not None:
            validate_session_context(session_ctx)
    except Exception as exc:  # noqa: BLE001 — consumer hook; audit then structure
        return _hook_failure(
            user=user,
            profile=profile,
            token_id=token_id,
            raw_sql=raw_sql,
            normalized_sql=parsed.normalized_sql,
            wrapped_sql=wrapped_sql,
            started_at=started_at,
            client_ip=client_ip,
            exc=exc,
        )
    t0 = perf_counter_ns()
    try:
        with (
            transaction.atomic(using=db_alias),
            connections[db_alias].cursor() as cur,
        ):
            enter_readonly_session(cur, role=profile.role, session_context=session_ctx)
            cur.execute(wrapped_sql)
            raw_rows = cur.fetchall()
            columns = [c.name for c in cur.description] if cur.description else []
    except DatabaseError as exc:
        duration_ms = (perf_counter_ns() - t0) // 1_000_000
        reason = _classify_db_error(exc)
        _audit_safely(
            user=user,
            profile=profile.name,
            token_id=token_id,
            decision=MCPQueryLog.DECISION_ALLOWED,
            rejection_reason=reason,
            raw_sql=raw_sql,
            normalized_sql=parsed.normalized_sql,
            wrapped_sql=wrapped_sql,
            started_at=started_at,
            duration_ms=duration_ms,
            client_ip=client_ip,
            error=str(exc),
        )
        return QueryResult(
            rejection_reason=reason,
            hint=HINTS.get(reason, ""),
            duration_ms=duration_ms,
            error=str(exc),
        )
    duration_ms = (perf_counter_ns() - t0) // 1_000_000

    # `truncated_by_count` fires only when the SERVER cap was binding;
    # see `docs/architecture.md` "Truncation has two axes, one flag" for the
    # rationale (user-set caps don't raise the aggregation hint).
    # When `explicit_limits` is non-empty, `min_explicit_limit` already holds
    # `min(explicit_limits)` (it falls back to DEFAULT_LIMIT only when empty,
    # which the `bool(explicit_limits)` guard excludes here).
    user_constrained = (
        bool(explicit_limits) and min_explicit_limit <= limits["HARD_LIMIT"]
    )
    truncated_by_count = (not user_constrained) and len(raw_rows) > effective_limit
    kept_rows = raw_rows[:effective_limit]
    capped_rows, result_bytes, truncated_by_bytes = _cap_rows(kept_rows)
    truncated = truncated_by_count or truncated_by_bytes

    _audit_safely(
        user=user,
        profile=profile.name,
        token_id=token_id,
        decision=MCPQueryLog.DECISION_ALLOWED,
        rejection_reason="",
        raw_sql=raw_sql,
        normalized_sql=parsed.normalized_sql,
        wrapped_sql=wrapped_sql,
        started_at=started_at,
        duration_ms=duration_ms,
        row_count=len(capped_rows),
        truncated=truncated,
        result_bytes=result_bytes,
        client_ip=client_ip,
    )
    return QueryResult(
        columns=columns,
        rows=capped_rows,
        row_count=len(capped_rows),
        truncated=truncated,
        duration_ms=duration_ms,
        hint=HINTS["truncated"] if truncated else "",
    )


def audit_tool_call(  # noqa: PLR0913
    *,
    user: "AbstractBaseUser",
    profile: Profile,
    tool: str,
    token_id: str = "",
    client_ip: str | None = None,
    detail: str = "",
) -> None:
    """Write one `MCPQueryLog` row for a metadata tool call.

    `list_tables` / `describe_table` never touch the readonly executor, so
    they record their usage here directly: `decision='allowed'`, the SQL
    fields empty, `tool` set (a `schemas.ToolName` value), and `detail`
    (e.g. the `describe_table` target) stored in `raw_sql` as the raw
    request representation — the `tool` field disambiguates it from an
    actual SQL string. Routes through `_audit_safely` so a `default`-DB
    blip is logged rather than surfaced to the agent.
    """
    _audit_safely(
        user=user,
        profile=profile.name,
        token_id=token_id,
        decision=MCPQueryLog.DECISION_ALLOWED,
        tool=tool,
        rejection_reason="",
        raw_sql=detail,
        started_at=timezone.now(),
        client_ip=client_ip,
    )


def _hook_failure(  # noqa: PLR0913
    *,
    user: "AbstractBaseUser",
    profile: Profile,
    token_id: str,
    raw_sql: str,
    normalized_sql: str,
    wrapped_sql: str,
    started_at: "datetime.datetime",
    client_ip: str | None,
    exc: Exception,
) -> QueryResult:
    """Audit + structure a SESSION_CONTEXT-hook failure.

    Covers a hook that raises, returns a non-Mapping, or returns a GUC name
    outside the `mcp_sql.*` namespace (all surfaced by the eager
    `validate_session_context` call in `run_query`, before any DB work).
    The hook is consumer code resolved from a settings dotted path, so this
    is operator misconfiguration: one audit row + Sentry ERROR, then a
    structured `QueryResult` (closed `MISCONFIGURED` reason) instead of the
    raw exception escaping to the MCP transport unaudited. Unlike the
    pre-parse alias misconfig, parsing and LIMIT-wrapping have already
    succeeded here, so the row carries `normalized_sql` / `wrapped_sql` for
    triage against the consumer's hook code.
    """
    error = f"SESSION_CONTEXT hook failure: {exc}"
    logger.error("MCP executor misconfigured: %s", error)
    _audit_safely(
        user=user,
        profile=profile.name,
        token_id=token_id,
        decision=MCPQueryLog.DECISION_REJECTED,
        rejection_reason=OutcomeReason.MISCONFIGURED,
        raw_sql=raw_sql,
        normalized_sql=normalized_sql,
        wrapped_sql=wrapped_sql,
        started_at=started_at,
        client_ip=client_ip,
        error=error,
    )
    return QueryResult(
        rejection_reason=OutcomeReason.MISCONFIGURED,
        hint=HINTS.get(OutcomeReason.MISCONFIGURED, ""),
        error=error,
    )


def _audit_misconfig(  # noqa: PLR0913
    *,
    user: "AbstractBaseUser",
    profile: Profile,
    token_id: str,
    raw_sql: str,
    started_at: "datetime.datetime",
    client_ip: str | None,
    error: str,
) -> None:
    """Write a `decision='rejected'` audit row for an operator-error path.

    Misconfiguration of the `mcp_readonly` alias is not a query failure, but
    the "every code path writes one row" invariant lets the daily-volume
    alert and incident triage see the attempt without checking Python logs.
    Also logs at ERROR level so Sentry catches it — the audit row alone
    would not page anyone; misconfig in prod needs to escalate immediately.
    """
    logger.error("MCP executor misconfigured: %s", error)
    _audit_safely(
        user=user,
        profile=profile.name,
        token_id=token_id,
        decision=MCPQueryLog.DECISION_REJECTED,
        rejection_reason=OutcomeReason.MISCONFIGURED,
        raw_sql=raw_sql,
        started_at=started_at,
        client_ip=client_ip,
        error=error,
    )


def _audit_safely(**fields) -> None:
    """Best-effort wrapper for every `MCPQueryLog.objects.create` call site.

    Audit-row writes happen on the `default` alias after the readonly tx
    (or the parser-reject path) has already produced its side effects.
    Letting a transient `default`-DB blip propagate `DatabaseError` out of
    the executor would surface as a 500 to the agent — without writing the
    audit row either way — coupling audit-success to response-success with
    no audit-quality gain.

    So the two stay decoupled. If the audit insert fails, log loud (Sentry
    captures `logger.exception` as an event) and continue. The PG access
    boundary held at the role-grant layer; whether we record the event
    or only log it is a side channel. The audit gap is recoverable
    out-of-band via the Sentry alert.

    No retry: a `default`-DB outage usually lasts longer than any
    reasonable retry budget. The Sentry signal is the actionable channel.
    """
    try:
        MCPQueryLog.objects.create(**fields)
    except DatabaseError:
        # Pull out the reason so the log message stays grep-friendly even
        # if the full payload is dropped by the structured logging layer.
        reason = fields.get("rejection_reason") or "<allowed>"
        logger.exception(
            "MCP audit row write failed (reason=%s); response returned anyway",
            reason,
        )
        return
    # Single chokepoint for the per-user volume tripwire: every audited row
    # — run_query and the metadata tools, allowed and rejected — flows
    # through here, so counting on success keeps one counter per query. Only
    # the id + decision cross into observability (no PII, no SQL). Broad
    # guard because the tripwire is non-critical: a bug in it must never turn
    # a query that already ran + audited into a 500.
    try:
        user = fields["user"]
        observability.record_query_volume(
            user_id=user.pk,
            decision=fields["decision"],
            user_label=user.get_username(),
        )
    except Exception:
        logger.exception("MCP volume tripwire failed; query response unaffected")


def pgcode(exc: BaseException) -> str | None:
    """Return PG's SQLSTATE code for a `DatabaseError`, or None.

    Public helper (also imported by `mcp_sql_smoke` and `_classify_db_error`):
    Django populates `exc.pgcode` directly for the common case, but psycopg
    wrappers sometimes nest the SQLSTATE in `exc.__cause__.diag.sqlstate`.
    Falls back through both shapes.
    """
    code = getattr(exc, "pgcode", None)
    if code:
        return code
    diag = getattr(getattr(exc, "__cause__", None), "diag", None)
    return getattr(diag, "sqlstate", None)


def _classify_db_error(exc: BaseException) -> OutcomeReason:
    """Map a Postgres DatabaseError to an OutcomeReason code.

    `statement_timeout` raises SQLSTATE 57014 (query canceled); the
    `EXECUTION_ERROR` bucket covers every other DB-side failure.

    Agent-facing error-text policy: the executor surfaces `str(exc)`
    verbatim in `QueryResult.error`. PG includes literal data values in
    its messages for cast / range / constraint errors (e.g.
    `invalid input syntax for type integer: "alice@example.com"`), which
    means the error path can expose values for columns the agent did not
    request in its projection. This is accepted by design:

    - The curated-view pattern is the structural mitigation. Cast errors
      can only reference columns PG can evaluate — i.e. columns in the
      view's projection. Passwords, encrypted credentials, and OAuth
      secrets are excluded from the curated views, so the leak is bounded
      to columns the agent can already SELECT legitimately.
    - The agent's self-correction loop needs PG error text to recognise
      and retry on cast / type errors; sanitising would force it to
      debug blind and degrade the legitimate-use case.
    - `MCPQueryLog.error` keeps the full PG text for operator triage
      even when the agent-facing path bypasses `row_count` accounting.

    Phase 4's daily-volume Sentry signal will flag anomalous cast-error
    rates as the external observability channel for this trade-off.
    """
    if pgcode(exc) == PG_QUERY_CANCELED_SQLSTATE:
        return OutcomeReason.TIMEOUT
    return OutcomeReason.EXECUTION_ERROR


def _cap_rows(rows: list[tuple]) -> tuple[list[list], int, bool]:
    """Per-cell ≤4 KiB string cap + total ≤BYTES_LIMIT payload cap.

    Returns `(capped_rows, total_bytes, truncated_by_bytes)`. Non-string,
    non-primitive cell types (datetime, Decimal, UUID, bytes) are coerced
    to their `str()` form so `QueryResult.rows` is JSON-storable. Byte
    accounting uses `json.dumps(default=str)` which mirrors that coercion.

    First row is always kept even if it alone exceeds BYTES_LIMIT — caller
    can't see the truncation hint until at least one row lands.
    """
    total_cap = settings.MCP_SQL["LIMITS"]["BYTES_LIMIT"]
    out: list[list] = []
    total = 0
    truncated = False
    for row in rows:
        capped = [_cap_cell(v) for v in row]
        row_bytes = len(json.dumps(capped, default=str).encode("utf-8"))
        if out and total + row_bytes > total_cap:
            truncated = True
            break
        out.append(capped)
        total += row_bytes
    return out, total, truncated


def _cap_cell(value: object) -> str | bool | int | float | None:
    """Truncate per-cell strings to 4 KiB; coerce non-primitives to str()."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = value if isinstance(value, str) else str(value)
    if len(text.encode("utf-8")) > PER_CELL_BYTE_CAP:
        return text[:PER_CELL_BYTE_CAP] + TRUNCATION_MARK
    return text
