"""Unit + django_db tests for `mcp_sql.executor`.

Honest coverage matrix:

Tested
------
- Pure helpers (`_cap_cell`, `_cap_rows`, `_classify_db_error`): no DB; the
  byte-cap / per-cell-cap / type-coercion / "first row always kept" contracts
  are pinned here.
- Parser-reject path with mocked `connections`: writes one `MCPQueryLog` row
  with `decision='rejected'`, the correct short-code `rejection_reason`, the
  raw_sql, and the error detail. Row contents are deliberately not persisted
  (no `result_sample` field on the audit model).
- `ExecutorMisconfiguredError` (alias absent OR alias-resolves-wrong): writes one
  rejected-audit row before raising — the "every code path writes one row"
  invariant holds.
- `limit=0` short-circuit: zero-row audit row, no SQL hits the DB,
  `truncated=False`.
- Mocked DB error paths: timeout (SQLSTATE 57014) classified as
  `OutcomeReason.TIMEOUT`; generic `DatabaseError` classified as
  `OutcomeReason.EXECUTION_ERROR`. Audit row written with the right reason.

NOT tested (acknowledged gaps)
------------------------------
- The real `transaction.atomic(using="mcp_readonly")` semantics — mocking
  `connections` and `transaction.atomic` bypasses them entirely.
- The alias-assertion in production: tests stub the alias check by mocking
  `connections.databases` and `connection.alias`.
- `enter_readonly_session(cursor)` behaviour against a real Postgres role
  (SET LOCAL ROLE + GUCs). The smoke management command (`mcp_sql_smoke`,
  default mode) is the manual integration test for this; Phase 3 will add
  a fixture that opens a real `mcp_readonly` alias against the test cluster.
- Real LIMIT-N+1 truncation against rows from Postgres. `_cap_rows` is unit-
  tested at the byte level but the "fetched clamped+1 rows ⇒ truncated=True"
  contract is only smoke-tested.
"""

import datetime
from decimal import Decimal
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from django.db import DatabaseError

from mcp_sql.conf import Profile
from mcp_sql.executor import ExecutorMisconfiguredError
from mcp_sql.executor import _cap_cell
from mcp_sql.executor import _cap_rows
from mcp_sql.executor import _classify_db_error
from mcp_sql.executor import run_query
from mcp_sql.models import MCPQueryLog
from mcp_sql.schemas import OutcomeReason
from mcp_sql.tests.factories import UserFactory

# The executor takes the bound profile as an argument now; these unit tests
# pass a fixed `default`-shaped profile whose whitelist is `auth.Permission`
# (the table every executor test reads / is rejected against). `declared_tables`
# reads `profile.allowed_models` directly, so no settings mutation is needed
# for the whitelist (LIMITS / BAN_SELECT_STAR still come from settings).
_DEFAULT_PROFILE = Profile(
    name="default",
    role="mcp_readonly_role",
    codename="use_mcp_session",
    group_name="mcp_sql_users",
    allowed_models=("auth.Permission",),
    session_context=None,
)


def _stub_readonly_connections(monkeypatch):
    """Return a mock-`connections` context that satisfies the alias check
    and feeds back a configurable cursor for the SQL execution path."""
    mock_cursor = MagicMock()
    mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
    mock_cursor.__exit__ = MagicMock(return_value=False)

    mock_conn = MagicMock()
    mock_conn.alias = "mcp_readonly"
    mock_conn.cursor.return_value = mock_cursor

    mock_conns = MagicMock()
    mock_conns.databases = {"default": {}, "mcp_readonly": {}}
    mock_conns.__getitem__.return_value = mock_conn

    monkeypatch.setattr("mcp_sql.executor.connections", mock_conns)
    # `transaction.atomic(using="mcp_readonly")` would try to use a real
    # connection; replace with a no-op context manager.
    monkeypatch.setattr("mcp_sql.executor.transaction.atomic", MagicMock())
    return mock_cursor


class TestCapCell:
    def test_none_passthrough(self):
        assert _cap_cell(None) is None

    def test_bool_passthrough(self):
        assert _cap_cell(True) is True  # noqa: FBT003
        assert _cap_cell(False) is False  # noqa: FBT003

    def test_int_passthrough(self):
        assert _cap_cell(42) == 42

    def test_float_passthrough(self):
        assert _cap_cell(3.14) == 3.14

    def test_short_string_passthrough(self):
        assert _cap_cell("hello") == "hello"

    def test_decimal_coerced_to_string(self):
        assert _cap_cell(Decimal("3.14")) == "3.14"

    def test_datetime_coerced_to_string(self):
        out = _cap_cell(datetime.datetime(2026, 5, 11, 12, 0, 0, tzinfo=datetime.UTC))
        assert isinstance(out, str)
        assert "2026-05-11" in out

    def test_huge_string_capped(self):
        out = _cap_cell("A" * 5000)
        # 4 KiB cap + the truncation suffix
        assert out.endswith("…[truncated]")
        assert "A" * 4096 in out
        assert len(out) <= 4096 + len("…[truncated]")


class TestHintConstants:
    """`schemas._STATEMENT_TIMEOUT_TEXT` is hardcoded so the closed enum /
    hint surface stays Django-free; this test pins it to the GUC value."""

    def test_timeout_hint_matches_session_guc(self):
        from mcp_sql.schemas import _STATEMENT_TIMEOUT_TEXT
        from mcp_sql.session import EXPECTED_SESSION_GUCS

        assert EXPECTED_SESSION_GUCS["statement_timeout"] == _STATEMENT_TIMEOUT_TEXT


class TestClassifyDbError:
    def test_query_canceled_is_timeout(self):
        exc = Exception("statement timeout")
        exc.pgcode = "57014"
        assert _classify_db_error(exc) == OutcomeReason.TIMEOUT

    def test_other_is_execution_error(self):
        exc = Exception("some other DB error")
        exc.pgcode = "42P01"
        assert _classify_db_error(exc) == OutcomeReason.EXECUTION_ERROR

    def test_missing_pgcode_is_execution_error(self):
        exc = Exception("no pgcode attr")
        assert _classify_db_error(exc) == OutcomeReason.EXECUTION_ERROR


class TestCapRows:
    """Row/byte cap contracts. Total cap comes from MCP_SQL[LIMITS][BYTES_LIMIT]."""

    def test_under_cap_returns_all_rows(self, settings):
        settings.MCP_SQL["LIMITS"]["BYTES_LIMIT"] = 10_000
        rows, total, trunc = _cap_rows([(1, "a"), (2, "b"), (3, "c")])
        assert len(rows) == 3
        assert trunc is False
        assert total > 0

    def test_over_cap_truncates(self, settings):
        settings.MCP_SQL["LIMITS"]["BYTES_LIMIT"] = 200
        big = "A" * 100  # already JSON-safe; ~100 bytes per row
        rows, total, trunc = _cap_rows([(i, big) for i in range(20)])
        assert trunc is True
        assert len(rows) < 20
        # We stopped before exceeding the cap; total can equal but not exceed.
        assert total <= 200

    def test_first_row_always_kept(self, settings):
        # Even a single huge row that exceeds BYTES_LIMIT lands; truncation
        # only applies from the *second* row onward. Otherwise the agent
        # would see "rows=0 truncated=true" with no hint of what happened.
        settings.MCP_SQL["LIMITS"]["BYTES_LIMIT"] = 50
        rows, _total, trunc = _cap_rows([("A" * 1000,)])
        assert len(rows) == 1
        assert trunc is False

    def test_decimal_and_datetime_serialise_in_byte_count(self, settings):
        settings.MCP_SQL["LIMITS"]["BYTES_LIMIT"] = 10_000
        when = datetime.datetime(2026, 5, 11, tzinfo=datetime.UTC)
        rows, total, _trunc = _cap_rows([(1, Decimal("3.14"), when)])
        assert len(rows) == 1
        # Coerced to strings, serialisable; total > 0 proves the row was
        # actually encoded.
        assert total > 0


@pytest.mark.django_db
class TestExecutorMisconfiguredError:
    """Misconfig writes an audit row (decision=rejected, reason=execution_error)
    THEN raises. The "every code path writes one row" invariant holds for
    operator errors too — the daily-volume alert and triage need one place to
    look. The Python exception is still raised for ops to handle."""

    def test_alias_missing_writes_audit_and_raises(self):
        # config.settings.test removes the mcp_readonly alias via DATABASES.pop.
        user = UserFactory()
        with pytest.raises(ExecutorMisconfiguredError):
            run_query(
                user=user,
                profile=_DEFAULT_PROFILE,
                raw_sql="SELECT id FROM auth_permission",
            )
        log = MCPQueryLog.objects.get()
        assert log.decision == MCPQueryLog.DECISION_REJECTED
        # Misconfig uses its own reason code (not EXECUTION_ERROR) so the
        # daily-volume alert and triage can distinguish ops bugs from real
        # PG errors without parsing the `error` text.
        assert log.rejection_reason == OutcomeReason.MISCONFIGURED.value
        assert "mcp_readonly alias absent" in log.error
        assert log.raw_sql == "SELECT id FROM auth_permission"
        assert log.user == user

    def test_alias_resolves_to_wrong_db_writes_audit_and_raises(
        self, settings, monkeypatch
    ):
        # Simulate a broken DATABASES: alias declared, but connection
        # returns the wrong .alias.
        user = UserFactory()

        mock_conn = MagicMock()
        mock_conn.alias = "default"  # wrong!
        mock_conns = MagicMock()
        mock_conns.databases = {"default": {}, "mcp_readonly": {}}
        mock_conns.__getitem__.return_value = mock_conn
        monkeypatch.setattr("mcp_sql.executor.connections", mock_conns)

        with pytest.raises(ExecutorMisconfiguredError):
            run_query(
                user=user,
                profile=_DEFAULT_PROFILE,
                raw_sql="SELECT id FROM auth_permission",
            )
        log = MCPQueryLog.objects.get()
        assert log.decision == MCPQueryLog.DECISION_REJECTED
        assert log.rejection_reason == OutcomeReason.MISCONFIGURED.value
        assert "different alias" in log.error


@pytest.mark.django_db
class TestExecutorParserRejectAudit:
    """When the parser rejects, the executor writes one MCPQueryLog row and
    returns a QueryResult with the rejection reason — no DB execution needed."""

    def test_select_star_writes_rejected_audit(self, settings):
        # The mcp_readonly check fires before the parser; stub it out so the
        # parser path is exercised without needing a real alias.
        user = UserFactory()

        with patch("mcp_sql.executor.connections") as mock_conns:
            mock_conns.databases = {"default": {}, "mcp_readonly": {}}
            mock_conns.__getitem__.return_value.alias = "mcp_readonly"
            result = run_query(
                user=user,
                profile=_DEFAULT_PROFILE,
                raw_sql="SELECT * FROM auth_permission",
            )

        assert result.rejection_reason == OutcomeReason.SELECT_STAR.value
        assert result.hint  # populated from HINTS
        assert result.rows == []

        log = MCPQueryLog.objects.get()
        assert log.decision == MCPQueryLog.DECISION_REJECTED
        assert log.rejection_reason == OutcomeReason.SELECT_STAR.value
        assert log.raw_sql == "SELECT * FROM auth_permission"
        assert log.profile == "default"  # per-tier attribution (migration 0011)
        assert log.normalized_sql == ""  # parser raised before normalising
        assert log.wrapped_sql == ""
        assert log.row_count is None
        assert log.user == user

    def test_disallowed_table_writes_rejected_audit(self, settings):
        user = UserFactory()

        with patch("mcp_sql.executor.connections") as mock_conns:
            mock_conns.databases = {"default": {}, "mcp_readonly": {}}
            mock_conns.__getitem__.return_value.alias = "mcp_readonly"
            result = run_query(
                user=user, profile=_DEFAULT_PROFILE, raw_sql="SELECT id FROM users_user"
            )

        assert result.rejection_reason == OutcomeReason.DISALLOWED_TABLE.value
        log = MCPQueryLog.objects.get()
        assert log.rejection_reason == OutcomeReason.DISALLOWED_TABLE.value

    def test_disallowed_function_writes_rejected_audit(self, settings):
        user = UserFactory()

        with patch("mcp_sql.executor.connections") as mock_conns:
            mock_conns.databases = {"default": {}, "mcp_readonly": {}}
            mock_conns.__getitem__.return_value.alias = "mcp_readonly"
            result = run_query(
                user=user,
                profile=_DEFAULT_PROFILE,
                raw_sql="SELECT pg_read_file('/etc/passwd')",
            )

        assert result.rejection_reason == OutcomeReason.DISALLOWED_FUNCTION.value
        # Tokens are never logged
        log = MCPQueryLog.objects.get()
        assert log.token_id == ""

    def test_parse_error_writes_rejected_audit(self, settings):
        user = UserFactory()

        with patch("mcp_sql.executor.connections") as mock_conns:
            mock_conns.databases = {"default": {}, "mcp_readonly": {}}
            mock_conns.__getitem__.return_value.alias = "mcp_readonly"
            result = run_query(
                user=user, profile=_DEFAULT_PROFILE, raw_sql="this is not sql at all"
            )

        assert result.rejection_reason == OutcomeReason.PARSE_ERROR.value
        assert result.error  # parser detail surfaces

    def test_serialization_recursion_error_writes_rejected_audit(
        self, settings, monkeypatch
    ):
        # A parseable-but-pathologically-deep AST can clear the parser yet
        # overflow during the executor's LIMIT-injection serialization
        # (`inject_limit(...).sql()`, outside the parser's own RecursionError
        # guard). It must still be audited as PARSE_ERROR, not escape as an
        # unaudited 500. Triggering real recursion here is impractical (parse
        # overflows first), so we mock `inject_limit` to raise directly.
        user = UserFactory()

        def boom(*args, **kwargs):
            raise RecursionError

        monkeypatch.setattr("mcp_sql.executor.inject_limit", boom)

        with patch("mcp_sql.executor.connections") as mock_conns:
            mock_conns.databases = {"default": {}, "mcp_readonly": {}}
            mock_conns.__getitem__.return_value.alias = "mcp_readonly"
            result = run_query(
                user=user,
                profile=_DEFAULT_PROFILE,
                raw_sql="SELECT id FROM auth_permission",
            )

        assert result.rejection_reason == OutcomeReason.PARSE_ERROR.value
        log = MCPQueryLog.objects.get()
        assert log.decision == MCPQueryLog.DECISION_REJECTED
        assert log.rejection_reason == OutcomeReason.PARSE_ERROR.value
        assert log.normalized_sql  # parser succeeded; normalisation ran


@pytest.mark.django_db
class TestAuditWriteResilience:
    """Audit-row insert failure must NOT propagate up to the response.

    Today's behaviour without `_audit_safely` was: an audit insert that
    raised `DatabaseError` (default-DB transient blip, connection pool
    exhausted) propagated out of the executor, surfacing as a 500 to the
    agent — even though the SELECT already executed and the data was in
    Python memory. That coupling provided zero audit-quality benefit
    (the row was never written either way) and punished the agent for an
    operator-side problem.

    `_audit_safely` decouples audit-success from response-success: catch
    the DB error, log via `logger.exception` (Sentry-actionable), return
    the response anyway. The PG role boundary holds regardless of audit
    state. The audit gap is recoverable out-of-band via the Sentry alert.
    """

    def test_parser_reject_returns_result_when_audit_fails(self, settings, caplog):
        user = UserFactory()

        with (
            patch("mcp_sql.executor.connections") as mock_conns,
            patch(
                "mcp_sql.executor.MCPQueryLog.objects.create",
                side_effect=DatabaseError("default DB unreachable"),
            ),
        ):
            mock_conns.databases = {"default": {}, "mcp_readonly": {}}
            mock_conns.__getitem__.return_value.alias = "mcp_readonly"
            with caplog.at_level("ERROR", logger="mcp_sql.executor"):
                result = run_query(
                    user=user,
                    profile=_DEFAULT_PROFILE,
                    raw_sql="SELECT * FROM auth_permission",
                )

        # The parser rejection still surfaces — the agent gets the same
        # response shape they would have gotten with a healthy audit DB.
        assert result.rejection_reason == OutcomeReason.SELECT_STAR.value
        assert result.hint
        # The audit failure is logged loudly (Sentry catches via the
        # `logger.exception` handler in production).
        assert any(
            "MCP audit row write failed" in record.getMessage()
            for record in caplog.records
        )

    def test_misconfig_propagates_even_when_audit_fails(self, settings, caplog):
        # The misconfig path still raises `ExecutorMisconfiguredError` because
        # that exception is the operator-facing signal; the audit row is
        # best-effort but the raise is not. The audit-failure log fires
        # before the raise.
        user = UserFactory()

        with (
            patch("mcp_sql.executor.connections") as mock_conns,
            patch(
                "mcp_sql.executor.MCPQueryLog.objects.create",
                side_effect=DatabaseError("default DB unreachable"),
            ),
        ):
            # Make the alias check fail so `_audit_misconfig` runs.
            mock_conns.databases = {"default": {}}  # mcp_readonly missing
            with (
                caplog.at_level("ERROR", logger="mcp_sql.executor"),
                pytest.raises(ExecutorMisconfiguredError),
            ):
                run_query(
                    user=user,
                    profile=_DEFAULT_PROFILE,
                    raw_sql="SELECT id FROM auth_permission",
                )
        assert any(
            "MCP audit row write failed" in record.getMessage()
            for record in caplog.records
        )


@pytest.mark.django_db
class TestExecutorLimitClamp:
    """The clamp contract: limit=None ⇒ DEFAULT_LIMIT; limit=0 ⇒ short-circuit
    (no SQL, zero-row audit); limit<0 ⇒ clamped to 0; limit>HARD_LIMIT ⇒
    clamped down. `limit or DEFAULT_LIMIT` would silently rewrite 0; this
    test pins the intended semantics."""

    def test_limit_zero_short_circuits_and_audits(self, settings, monkeypatch):
        user = UserFactory()
        mock_cursor = _stub_readonly_connections(monkeypatch)

        result = run_query(
            user=user,
            profile=_DEFAULT_PROFILE,
            raw_sql="SELECT id FROM auth_permission",
            limit=0,
        )

        assert result.row_count == 0
        assert result.rows == []
        assert result.truncated is False
        # No cursor.execute should have happened for limit=0 — short-circuit
        # before opening the transaction.
        mock_cursor.execute.assert_not_called()
        log = MCPQueryLog.objects.get()
        assert log.decision == MCPQueryLog.DECISION_ALLOWED
        assert log.row_count == 0
        assert log.wrapped_sql == ""
        assert log.profile == "default"  # per-tier attribution (migration 0011)
        assert log.normalized_sql  # parser succeeded; normalisation ran

    def test_negative_limit_treated_as_zero(self, settings, monkeypatch):
        user = UserFactory()
        mock_cursor = _stub_readonly_connections(monkeypatch)

        result = run_query(
            user=user,
            profile=_DEFAULT_PROFILE,
            raw_sql="SELECT id FROM auth_permission",
            limit=-5,
        )

        # Clamped via max(0, min(-5, 100)) == 0 ⇒ same short-circuit as 0.
        assert result.row_count == 0
        mock_cursor.execute.assert_not_called()

    def test_user_sql_limit_smaller_than_default_is_honored(
        self, settings, monkeypatch
    ):
        """User wrote `LIMIT 3` in SQL but did not pass the tool kwarg —
        the server must honor the SQL value (not clobber it with
        `DEFAULT_LIMIT=10`). Pins the user-visible bug TIC-554 hit
        post-launch where Claude Code sent `LIMIT 3` in SQL, did not pass
        `limit=3` as a tool kwarg, and got 10 rows + `truncated=True`."""
        user = UserFactory()
        mock_cursor = _stub_readonly_connections(monkeypatch)
        mock_cursor.description = [MagicMock(name="id")]
        mock_cursor.description[0].name = "id"
        mock_cursor.fetchall.return_value = [(1,), (2,), (3,)]

        run_query(
            user=user,
            profile=_DEFAULT_PROFILE,
            raw_sql="SELECT id FROM auth_permission LIMIT 3",
        )

        # Wrapped SQL must inject LIMIT 4 (user-supplied 3 + 1 for the
        # N+1 truncation-detection trick), not LIMIT 11 (DEFAULT_LIMIT+1).
        log = MCPQueryLog.objects.get()
        assert "LIMIT 4" in log.wrapped_sql
        assert "LIMIT 11" not in log.wrapped_sql

    def test_tool_kwarg_and_sql_limit_most_restrictive_wins(
        self, settings, monkeypatch
    ):
        """When BOTH the tool kwarg and the SQL LIMIT are present, the
        smaller one wins — neither can sneak past the other."""
        user = UserFactory()
        mock_cursor = _stub_readonly_connections(monkeypatch)
        mock_cursor.description = [MagicMock(name="id")]
        mock_cursor.description[0].name = "id"
        mock_cursor.fetchall.return_value = [(1,), (2,)]

        # Tool kwarg 50, SQL LIMIT 2 ⇒ effective limit is 2 (most restrictive).
        run_query(
            user=user,
            profile=_DEFAULT_PROFILE,
            raw_sql="SELECT id FROM auth_permission LIMIT 2",
            limit=50,
        )

        log = MCPQueryLog.objects.get()
        assert "LIMIT 3" in log.wrapped_sql

    def test_user_sql_limit_above_hard_limit_clamped_down(self, settings, monkeypatch):
        """User-supplied SQL LIMIT cannot exceed HARD_LIMIT. The clamp is
        the security invariant; tests pin that user-friendliness (honor
        smaller LIMITs) doesn't accidentally open a hole upward."""
        settings.MCP_SQL["LIMITS"]["HARD_LIMIT"] = 100
        user = UserFactory()
        mock_cursor = _stub_readonly_connections(monkeypatch)
        mock_cursor.description = [MagicMock(name="id")]
        mock_cursor.description[0].name = "id"
        mock_cursor.fetchall.return_value = []

        run_query(
            user=user,
            profile=_DEFAULT_PROFILE,
            raw_sql="SELECT id FROM auth_permission LIMIT 1000",
        )

        log = MCPQueryLog.objects.get()
        assert "LIMIT 101" in log.wrapped_sql  # HARD_LIMIT + 1
        assert "LIMIT 1001" not in log.wrapped_sql

    def test_user_constrained_limit_does_not_set_truncated(self, settings, monkeypatch):
        """User wrote `LIMIT 3` and the DB has more rows than that. The
        executor fetches `LIMIT 4` to use the N+1 trick, finds 4 rows,
        keeps 3. `truncated` must NOT be set: the user explicitly chose
        the cap, so the aggregation-focused hint would be misleading.
        Pins the bug TIC-554 hit post-launch where `LIMIT 3` + DB-with-
        many-rows produced `truncated=True` (and the hint pushed the
        agent toward COUNT/GROUP BY despite the explicit ask)."""
        user = UserFactory()
        mock_cursor = _stub_readonly_connections(monkeypatch)
        mock_cursor.description = [MagicMock(name="id")]
        mock_cursor.description[0].name = "id"
        # User asked for 3, executor fetches 4, DB returns 4. Without the
        # `user_constrained` guard, `len(raw_rows) > clamped` (4 > 3) sets
        # `truncated=True`.
        mock_cursor.fetchall.return_value = [(1,), (2,), (3,), (4,)]

        result = run_query(
            user=user,
            profile=_DEFAULT_PROFILE,
            raw_sql="SELECT id FROM auth_permission LIMIT 3",
        )

        assert result.row_count == 3
        assert result.truncated is False
        assert result.hint == ""

    def test_server_capped_limit_still_sets_truncated(self, settings, monkeypatch):
        """Inverse contract: when the SERVER's `DEFAULT_LIMIT` was the
        binding constraint (no user limit anywhere), `truncated=True`
        still fires. This is the hint's *correct* use: "we capped you;
        consider COUNT/GROUP BY"."""
        settings.MCP_SQL["LIMITS"]["DEFAULT_LIMIT"] = 10
        settings.MCP_SQL["LIMITS"]["HARD_LIMIT"] = 100
        user = UserFactory()
        mock_cursor = _stub_readonly_connections(monkeypatch)
        mock_cursor.description = [MagicMock(name="id")]
        mock_cursor.description[0].name = "id"
        # DEFAULT_LIMIT=10 + 1; DB has 11 matching rows.
        mock_cursor.fetchall.return_value = [(i,) for i in range(11)]

        result = run_query(
            user=user,
            profile=_DEFAULT_PROFILE,
            raw_sql="SELECT id FROM auth_permission",
        )

        assert result.row_count == 10
        assert result.truncated is True


@pytest.mark.django_db
class TestExecutorDbErrorPaths:
    """End-to-end audit-write contract for the two `except DatabaseError`
    branches. Cursor / transaction / connection are mocked — the readonly
    contract on real PG is acknowledged-untested in the module docstring."""

    def test_timeout_writes_audit_with_timeout_reason(self, settings, monkeypatch):
        user = UserFactory()
        mock_cursor = _stub_readonly_connections(monkeypatch)

        timeout_exc = DatabaseError("canceling statement due to timeout")
        timeout_exc.pgcode = "57014"

        # `enter_readonly_session` issues several `SET LOCAL` statements
        # before the wrapped query. Raise only on the wrapped query so the
        # session prelude doesn't masquerade as the failure.
        def execute_side_effect(sql, *_a, **_kw):
            if "SET LOCAL" not in sql:
                raise timeout_exc

        mock_cursor.execute.side_effect = execute_side_effect

        result = run_query(
            user=user,
            profile=_DEFAULT_PROFILE,
            raw_sql="SELECT id FROM auth_permission",
        )

        assert result.rejection_reason == OutcomeReason.TIMEOUT.value
        assert "timeout" in result.error.lower()
        log = MCPQueryLog.objects.get()
        assert log.decision == MCPQueryLog.DECISION_ALLOWED
        assert log.rejection_reason == OutcomeReason.TIMEOUT.value
        assert log.profile == "default"  # per-tier attribution (migration 0011)
        assert log.wrapped_sql  # we did try to execute
        assert log.normalized_sql  # parser succeeded
        assert log.duration_ms is not None

    def test_generic_db_error_writes_execution_error_reason(
        self, settings, monkeypatch
    ):
        user = UserFactory()
        mock_cursor = _stub_readonly_connections(monkeypatch)

        # 42P01 = relation does not exist — could happen if grants drift and
        # the role can't see a table the parser thinks exists.
        relation_exc = DatabaseError("relation does not exist")
        relation_exc.pgcode = "42P01"

        def execute_side_effect(sql, *_a, **_kw):
            if "SET LOCAL" not in sql:
                raise relation_exc

        mock_cursor.execute.side_effect = execute_side_effect

        result = run_query(
            user=user,
            profile=_DEFAULT_PROFILE,
            raw_sql="SELECT id FROM auth_permission",
        )

        assert result.rejection_reason == OutcomeReason.EXECUTION_ERROR.value
        log = MCPQueryLog.objects.get()
        assert log.rejection_reason == OutcomeReason.EXECUTION_ERROR.value


class TestExecutorHookFailureAudit:
    """The SESSION_CONTEXT hook is consumer code — every failure shape must
    still write exactly one audit row (the module invariant) and come back
    as a structured `MISCONFIGURED` result, never an unaudited exception
    escaping to the MCP transport."""

    @staticmethod
    def _hook_profile(hook):
        return Profile(
            name="hooked",
            role="mcp_readonly_role",
            codename="use_mcp_session",
            group_name="mcp_sql_users",
            allowed_models=("auth.Permission",),
            session_context=hook,
        )

    def _assert_hook_misconfig(self, result, profile_name="hooked"):
        assert result.rejection_reason == OutcomeReason.MISCONFIGURED.value
        assert "SESSION_CONTEXT hook failure" in result.error
        log = MCPQueryLog.objects.get()
        assert log.decision == MCPQueryLog.DECISION_REJECTED
        assert log.rejection_reason == OutcomeReason.MISCONFIGURED.value
        assert log.profile == profile_name

    @pytest.mark.django_db
    def test_hook_that_raises_is_audited(self, settings, monkeypatch):
        user = UserFactory()
        _stub_readonly_connections(monkeypatch)

        def exploding_hook(user, profile):
            msg = "user has no tenant"
            raise KeyError(msg)

        result = run_query(
            user=user,
            profile=self._hook_profile(exploding_hook),
            raw_sql="SELECT id FROM auth_permission",
        )
        self._assert_hook_misconfig(result)

    @pytest.mark.django_db
    def test_hook_returning_non_mapping_is_audited(self, settings, monkeypatch):
        user = UserFactory()
        _stub_readonly_connections(monkeypatch)

        result = run_query(
            user=user,
            profile=self._hook_profile(lambda user, profile: "not-a-mapping"),
            raw_sql="SELECT id FROM auth_permission",
        )
        self._assert_hook_misconfig(result)

    @pytest.mark.django_db
    def test_hook_returning_bad_guc_name_is_audited(self, settings, monkeypatch):
        user = UserFactory()
        _stub_readonly_connections(monkeypatch)

        result = run_query(
            user=user,
            profile=self._hook_profile(
                lambda user, profile: {"statement_timeout": "0"}
            ),
            raw_sql="SELECT id FROM auth_permission",
        )
        self._assert_hook_misconfig(result)
