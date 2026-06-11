"""`session.enter_readonly_session` SESSION_CONTEXT hook — dormant by default,
parameterized + namespace-checked when set (TIC-585)."""

from unittest.mock import MagicMock

import pytest
from django.db import connection
from django.db import transaction
from mcp_sql.session import EXPECTED_SESSION_GUCS
from mcp_sql.session import enter_readonly_session
from mcp_sql.session import session_drift


def _executed_sql(cursor: MagicMock) -> list[str]:
    return [call.args[0] for call in cursor.execute.call_args_list]


def test_dormant_by_default_issues_no_set_config():
    cur = MagicMock()
    enter_readonly_session(cur, role="mcp_readonly_role")
    sql = _executed_sql(cur)
    assert any("SET LOCAL ROLE mcp_readonly_role" in s for s in sql)
    # The four static guard GUCs, and nothing via set_config.
    assert not any("set_config" in s for s in sql)


def test_hook_sets_each_guc_via_parameterized_set_config():
    cur = MagicMock()
    enter_readonly_session(
        cur,
        role="mcp_ro_second_profile",
        session_context={"mcp_sql.tenant": "42"},
    )
    set_config_calls = [
        call for call in cur.execute.call_args_list if "set_config" in call.args[0]
    ]
    assert len(set_config_calls) == 1
    # transaction-local (third arg true), value bound as a param — never
    # interpolated into the SQL text.
    assert set_config_calls[0].args[0] == "SELECT set_config(%s, %s, true)"
    assert set_config_calls[0].args[1] == ["mcp_sql.tenant", "42"]


def test_hook_rejects_guc_name_outside_mcp_sql_namespace():
    cur = MagicMock()
    with pytest.raises(ValueError, match="unsafe SESSION_CONTEXT GUC name"):
        enter_readonly_session(
            cur,
            role="r",
            session_context={"statement_timeout": "0"},
        )


def test_hook_rejects_injection_shaped_guc_name():
    cur = MagicMock()
    with pytest.raises(ValueError, match="unsafe SESSION_CONTEXT GUC name"):
        enter_readonly_session(
            cur,
            role="r",
            session_context={"mcp_sql.x; DROP TABLE": "1"},
        )


@pytest.mark.parametrize(
    "name",
    [
        "mcp_sql.Tenant",  # uppercase — outside [a-z_]
        "mcp_sql.",  # empty suffix
        "mcp_sql..x",  # double dot
        "mcp_sql.x.y",  # nested namespace
        "",  # empty string
    ],
)
def test_hook_rejects_boundary_shaped_guc_names(name):
    """`_SAFE_CONTEXT_GUC_NAME` is the sole gate on hook-supplied GUC names;
    pin the boundary shapes, not just the obvious non-namespaced/injection
    cases above."""
    cur = MagicMock()
    with pytest.raises(ValueError, match="unsafe SESSION_CONTEXT GUC name"):
        enter_readonly_session(cur, role="r", session_context={name: "1"})


_ROLE = "mcp_readonly_role"


class TestSessionDrift:
    """`session_drift` is the smoke/executor pre-flight check that the read
    connection actually entered the role + the four `SET LOCAL` guards.
    Exercised against a real connection (the in-package readonly role is
    bootstrapped by `sql/role_setup.sql`, per CONTRIBUTING)."""

    @pytest.mark.django_db
    def test_no_drift_after_enter_readonly_session(self):
        with transaction.atomic(), connection.cursor() as cur:
            enter_readonly_session(cur, role=_ROLE)
            assert session_drift(cur, _ROLE) == {}

    @pytest.mark.django_db
    def test_wrong_expected_role_reported_as_current_user_drift(self):
        with transaction.atomic(), connection.cursor() as cur:
            enter_readonly_session(cur, role=_ROLE)
            drift = session_drift(cur, "some_other_role")
        assert drift["current_user"] == ("some_other_role", _ROLE)
        # The four GUCs still match — only current_user drifted.
        assert set(drift) == {"current_user"}

    @pytest.mark.django_db
    def test_guc_drift_detected(self):
        with transaction.atomic(), connection.cursor() as cur:
            enter_readonly_session(cur, role=_ROLE)
            # Override one guard transaction-locally to force a mismatch.
            cur.execute("SET LOCAL statement_timeout = '99s'")
            drift = session_drift(cur, _ROLE)
        expected = EXPECTED_SESSION_GUCS["statement_timeout"]
        assert drift["statement_timeout"] == (expected, "99s")
        assert "current_user" not in drift
