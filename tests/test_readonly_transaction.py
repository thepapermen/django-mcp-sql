"""The read transaction is read-only while it runs, and never committed.

Ledger F01: `SET LOCAL default_transaction_read_only = on` is read when a
transaction starts, and the executor's has already started when it is set,
so a SECURITY DEFINER function owned by a privileged role could write, and
the write committed. Exercised against real Postgres (the readonly role is
bootstrapped by `sql/role_setup.sql`); the executor runs on the `default`
alias here (`DB_ALIAS` pointed at it), the same database it reads in tests.
"""

import pytest
from django.db import DatabaseError
from django.db import connection
from django.db import transaction
from mcp_sql.executor import pgcode
from mcp_sql.executor import run_query
from mcp_sql.models import MCPQueryLog
from mcp_sql.schemas import OutcomeReason
from mcp_sql.session import EXPECTED_SESSION_GUCS
from mcp_sql.session import enter_readonly_session
from mcp_sql.session import guc_value_sql
from mcp_sql.session import session_drift
from mcp_sql.tests.factories import UserFactory
from mcp_sql.tests.test_executor import _DEFAULT_PROFILE

_ROLE = "mcp_readonly_role"
READ_ONLY_SQL_TRANSACTION = "25006"


@pytest.fixture
def probe_write(db):
    """A table the readonly role cannot write, and a SECURITY DEFINER
    function (owned by the test superuser) that writes to it."""
    with connection.cursor() as cur:
        cur.execute("CREATE TABLE mcp_sql_probe_target (n int)")
        cur.execute(
            "CREATE FUNCTION mcp_sql_probe_write() RETURNS int "
            "LANGUAGE sql SECURITY DEFINER AS "
            "$$ INSERT INTO mcp_sql_probe_target VALUES (1) RETURNING n $$"
        )
    return "mcp_sql_probe_target"


def _rows(table: str) -> int:
    with connection.cursor() as cur:
        cur.execute(f"SELECT count(*) FROM {table}")  # noqa: S608 — fixture name
        return cur.fetchone()[0]


@pytest.mark.django_db
class TestReadOnlySession:
    def test_the_running_transaction_is_read_only(self):
        with transaction.atomic(), connection.cursor() as cur:
            enter_readonly_session(cur, role=_ROLE)
            cur.execute("SHOW transaction_read_only")
            assert cur.fetchone() == ("on",)
            assert session_drift(cur, _ROLE) == {}

    def test_drift_check_reads_the_live_flag(self):
        with transaction.atomic(), connection.cursor() as cur:
            # The pre-fix session: the role and every default, but the
            # running transaction left read-write.
            cur.execute(f"SET LOCAL ROLE {_ROLE}")
            for name, value in EXPECTED_SESSION_GUCS.items():
                cur.execute(f"SET LOCAL {name} = {guc_value_sql(value)}")
            drift = session_drift(cur, _ROLE)
        assert drift == {"transaction_read_only": ("on", "off")}

    def test_security_definer_write_is_refused(self, probe_write):
        with (  # noqa: PT012
            pytest.raises(DatabaseError) as exc,
            transaction.atomic(),
            connection.cursor() as cur,
        ):
            enter_readonly_session(cur, role=_ROLE)
            cur.execute("SELECT mcp_sql_probe_write()")
        assert pgcode(exc.value) == READ_ONLY_SQL_TRANSACTION
        assert _rows(probe_write) == 0


@pytest.mark.django_db
class TestExecutorReadTransaction:
    @pytest.fixture(autouse=True)
    def _execute_on_default(self, settings):
        settings.MCP_SQL = {**settings.MCP_SQL, "DB_ALIAS": "default"}

    def test_security_definer_write_through_run_query_is_refused(self, probe_write):
        result = run_query(
            user=UserFactory(),
            profile=_DEFAULT_PROFILE,
            raw_sql="SELECT mcp_sql_probe_write() AS n",
        )
        assert result.rejection_reason == OutcomeReason.EXECUTION_ERROR.value
        assert "read-only transaction" in result.error
        assert _rows(probe_write) == 0
        log = MCPQueryLog.objects.get()
        assert log.rejection_reason == OutcomeReason.EXECUTION_ERROR.value

    def test_read_transaction_is_rolled_back(self, monkeypatch):
        calls: list = []
        original = transaction.set_rollback

        def spy(rollback, using=None):
            calls.append((rollback, using))
            return original(rollback, using=using)

        monkeypatch.setattr("mcp_sql.executor.transaction.set_rollback", spy)
        result = run_query(
            user=UserFactory(),
            profile=_DEFAULT_PROFILE,
            raw_sql="SELECT 1 AS one",
        )
        assert result.rows == [[1]]
        assert calls == [(True, "default")]
