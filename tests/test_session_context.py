"""`session.enter_readonly_session` SESSION_CONTEXT hook — dormant by default,
parameterized + namespace-checked when set (TIC-585)."""

from unittest.mock import MagicMock

import pytest

from mcp_sql.session import enter_readonly_session


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
