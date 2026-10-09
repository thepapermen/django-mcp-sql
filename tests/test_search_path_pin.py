"""`MCP_SQL["PIN_SEARCH_PATH"]` — the opt-in `search_path` pin (round 21).

Off (the default), the read transaction does not set `search_path` and
`session_drift` does not expect it: an unqualified name resolves through the
database's own `search_path`. On, `SET LOCAL search_path = 'public',
'pg_temp'` is one of the per-transaction guards and `session_drift` checks
it. The schema-scoped whitelist (`test_schema_scoping.py`) holds either way.
"""

import copy
from typing import Any
from unittest.mock import MagicMock

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.db import connection
from django.db import transaction
from mcp_sql.conf import DEFAULTS
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.session import EXPECTED_SESSION_GUCS
from mcp_sql.session import PINNED_SEARCH_PATH
from mcp_sql.session import enter_readonly_session
from mcp_sql.session import session_drift
from mcp_sql.session import session_gucs
from mcp_sql.tests.test_validation import VALID
from mcp_sql.validation import McpSqlSettings
from mcp_sql.validation import validate_mcp_sql_settings
from pydantic import ValidationError

_ROLE = "mcp_readonly_role"
_PIN_SQL = "SET LOCAL search_path = 'public', 'pg_temp'"
_CLIENT = {
    "LABEL": "Example",
    "REDIRECTS": [{"MATCH": "exact", "URI": "https://example.com/callback"}],
}
# Each an unknown key's path into the settings dict (a list index for a
# REDIRECTS rule), as pydantic reports it.
_UNKNOWN_KEYS: list[tuple[str | int, ...]] = [
    ("PIN_SEARCHPATH",),
    ("pin_search_path",),
    ("SEARCH_PATH",),
    ("LIMITS", "EXTRA"),
    ("PROFILES", "default", "EXTRA"),
    ("CLIENTS", "example", "EXTRA"),
    ("CLIENTS", "example", "REDIRECTS", 0, "EXTRA"),
]


@pytest.fixture
def pinned(settings):
    settings.MCP_SQL = {**settings.MCP_SQL, "PIN_SEARCH_PATH": True}


def _executed(cursor: MagicMock) -> list[str]:
    return [call.args[0] for call in cursor.execute.call_args_list]


class TestSetting:
    def test_off_by_default(self):
        # Flipping the default changes what every install's queries resolve
        # to; it needs a CHANGELOG entry and the owner's sign-off.
        assert DEFAULTS["PIN_SEARCH_PATH"] is False

    def test_the_test_settings_leave_it_at_the_default(self):
        assert mcp_sql_settings.PIN_SEARCH_PATH is False

    def test_declared_in_both_defaults_and_the_validated_shape(self):
        assert "PIN_SEARCH_PATH" in DEFAULTS
        assert "PIN_SEARCH_PATH" in McpSqlSettings.__optional_keys__

    @pytest.mark.parametrize("value", [True, False])
    def test_a_bool_is_accepted(self, value):
        validate_mcp_sql_settings({**copy.deepcopy(VALID), "PIN_SEARCH_PATH": value})

    @pytest.mark.parametrize(
        "value", ["true", "false", "False", "off", 1, 0, None, [True]]
    )
    def test_anything_but_a_bool_refuses_to_boot(self, value):
        cfg = {**copy.deepcopy(VALID), "PIN_SEARCH_PATH": value}
        with pytest.raises(ImproperlyConfigured):
            validate_mcp_sql_settings(cfg)

    @pytest.mark.parametrize(
        "path", _UNKNOWN_KEYS, ids=[".".join(map(str, p)) for p in _UNKNOWN_KEYS]
    )
    def test_an_unknown_key_refuses_to_boot(self, path):
        # A typo would otherwise leave the pin silently off. Refused at any
        # level: `extra="forbid"` on `McpSqlSettings` reaches the nested
        # TypedDicts (LIMITS, a PROFILES entry, a CLIENTS entry and its
        # REDIRECTS rules) too.
        cfg = {**copy.deepcopy(VALID), "CLIENTS": {"example": copy.deepcopy(_CLIENT)}}
        container: Any = cfg
        for step in path[:-1]:
            container = container[step]
        container[path[-1]] = True
        with pytest.raises(
            ImproperlyConfigured, match="Invalid MCP_SQL settings"
        ) as excinfo:
            validate_mcp_sql_settings(cfg)
        cause = excinfo.value.__cause__
        assert isinstance(cause, ValidationError)
        # The error names the key's path, and nothing else is wrong.
        assert [(e["loc"], e["type"]) for e in cause.errors()] == [
            (path, "extra_forbidden")
        ]
        assert ".".join(map(str, path)) in str(cause)

    def test_the_unknown_key_baseline_is_valid(self):
        # The cases above differ from this only by the unknown key.
        validate_mcp_sql_settings(
            {**copy.deepcopy(VALID), "CLIENTS": {"example": copy.deepcopy(_CLIENT)}}
        )


class TestGuards:
    def test_unpinned_guards_have_no_search_path(self):
        assert session_gucs() == EXPECTED_SESSION_GUCS
        assert "search_path" not in session_gucs()

    @pytest.mark.usefixtures("pinned")
    def test_pinned_guards_add_it(self):
        assert session_gucs() == EXPECTED_SESSION_GUCS | PINNED_SEARCH_PATH

    def test_unpinned_session_issues_no_search_path(self):
        cur = MagicMock()
        enter_readonly_session(cur, role=_ROLE)
        sql = _executed(cur)
        assert not [s for s in sql if "search_path" in s]
        assert sql[0] == f"SET LOCAL ROLE {_ROLE}"
        assert all(s.startswith("SET LOCAL ") for s in sql)

    @pytest.mark.usefixtures("pinned")
    def test_pinned_session_sets_it_locally(self):
        cur = MagicMock()
        enter_readonly_session(cur, role=_ROLE)
        assert [s for s in _executed(cur) if "search_path" in s] == [_PIN_SQL]


@pytest.mark.django_db
class TestOnPostgres:
    @pytest.fixture
    def role_without_default(self):
        # Rolled back with the test (pg_db_role_setting is transactional).
        with connection.cursor() as cur:
            cur.execute(f"ALTER ROLE {_ROLE} RESET search_path")

    @pytest.mark.usefixtures("role_without_default")
    @pytest.mark.parametrize(
        "login_search_path", ['"$user", public', "mcp_sql_a21_none, public"]
    )
    def test_unpinned_no_drift_and_the_logins_search_path(self, login_search_path):
        with transaction.atomic(), connection.cursor() as cur:
            cur.execute(f"SET LOCAL search_path = {login_search_path}")
            enter_readonly_session(cur, role=_ROLE)
            assert session_drift(cur, _ROLE) == {}
            cur.execute("SHOW search_path")
            assert cur.fetchone() == (login_search_path,)

    @pytest.mark.usefixtures("role_without_default", "pinned")
    def test_pinned_no_drift_without_the_role_default(self):
        with transaction.atomic(), connection.cursor() as cur:
            cur.execute("SET LOCAL search_path = mcp_sql_a21_none, public")
            enter_readonly_session(cur, role=_ROLE)
            assert session_drift(cur, _ROLE) == {}
            cur.execute("SHOW search_path")
            assert cur.fetchone() == ("public, pg_temp",)

    @pytest.mark.usefixtures("pinned")
    def test_pinned_drift_reports_a_changed_search_path(self):
        with transaction.atomic(), connection.cursor() as cur:
            enter_readonly_session(cur, role=_ROLE)
            cur.execute("SET LOCAL search_path = public")
            assert session_drift(cur, _ROLE) == {
                "search_path": ("public, pg_temp", "public")
            }

    def test_unpinned_drift_ignores_search_path(self):
        with transaction.atomic(), connection.cursor() as cur:
            enter_readonly_session(cur, role=_ROLE)
            cur.execute("SET LOCAL search_path = public")
            assert session_drift(cur, _ROLE) == {}
