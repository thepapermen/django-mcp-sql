"""The package's Django system checks (`mcp_sql/checks.py`).

`mcp_sql.E001` — an unqualified whitelisted `db_table` that `public` lacks
while the login's `search_path` finds it in another schema. Until 0.1.0b5
`GRANT SELECT ON "t"` resolved through the login's `search_path`; since
round 16 an unqualified `db_table` is `"public"."t"` to the parser, the
grants and the read path, so on such a deployment `mcp_sql_grants --apply`
failed with `relation "public.t" does not exist`, and for an unmanaged
entry the `post_migrate` drift check's view-parity probe raised a bare
`ProgrammingError` that failed `migrate` itself.
"""

from io import StringIO
from logging import ERROR

import pytest
from django.apps import apps
from django.core.checks import run_checks
from django.core.management import call_command
from django.core.management.base import CommandError
from django.core.management.base import SystemCheckError
from django.db import connection
from mcp_sql.signals import audit_grants_drift_after_migrate
from mcp_sql.tests.testapp.models import MCPWidgetSecondProfileView

pytestmark = pytest.mark.django_db

_SCHEMA = "mcp_sql_fu7_s"
_ENTRY = "mcp_sql_testapp.MCPWidgetSecondProfileView"
_NAME = MCPWidgetSecondProfileView._meta.db_table  # unqualified
_COLUMNS = "(id bigint, name varchar(100))"


@pytest.fixture
def whitelisted(settings):
    settings.MCP_SQL = {
        **settings.MCP_SQL,
        "PROFILES": {
            "default": {
                **settings.MCP_SQL["PROFILES"]["default"],
                "ALLOWED_MODELS": [_ENTRY],
            }
        },
    }


@pytest.fixture
def elsewhere(whitelisted):
    """The whitelisted relation only in `_SCHEMA`, which the login's
    `search_path` lists (rolled back with the test)."""
    with connection.cursor() as cur:
        cur.execute(f"CREATE SCHEMA {_SCHEMA}")
        cur.execute(f"CREATE TABLE {_SCHEMA}.{_NAME} {_COLUMNS}")
        cur.execute(f"SET LOCAL search_path = {_SCHEMA}, public")


def _e001(**kwargs) -> list:
    return [m for m in run_checks(**kwargs) if m.id == "mcp_sql.E001"]


class TestE001:
    def test_reported_with_the_schema_and_the_remedy(self, elsewhere):
        [error] = _e001(databases=["default"])
        assert error.is_serious()
        assert "'default'" in error.msg
        assert _ENTRY in error.msg
        assert f"finds it in schema {_SCHEMA!r}" in error.msg
        assert repr(f'{_SCHEMA}"."{_NAME}') in error.hint
        assert "Meta.managed = False" in error.hint
        assert "Curated-view pattern" in error.hint
        assert error.obj is MCPWidgetSecondProfileView

    def test_a_database_check_only(self, elsewhere):
        """A plain `check` (and `runserver`) does not query the database."""
        assert _e001() == []

    def test_the_relation_in_public_is_not_reported(self, elsewhere):
        with connection.cursor() as cur:
            cur.execute(f"CREATE TABLE public.{_NAME} {_COLUMNS}")
        assert _e001(databases=["default"]) == []

    def test_a_schema_qualified_db_table_is_not_reported(self, elsewhere, monkeypatch):
        monkeypatch.setattr(
            MCPWidgetSecondProfileView._meta, "db_table", f'{_SCHEMA}"."{_NAME}'
        )
        assert _e001(databases=["default"]) == []

    def test_a_relation_not_yet_created_is_not_reported(self, whitelisted):
        """A fresh database, before the migration that creates it."""
        assert _e001(databases=["default"]) == []

    def test_check_and_migrate_stop_on_it(self, elsewhere):
        """`check --database default` fails, and `manage.py migrate` (which
        runs the checks with its database before it applies anything; a
        programmatic `call_command` skips them unless asked) stops before
        migrating — `--check` here, so nothing would be applied either way."""
        with pytest.raises(SystemCheckError, match="mcp_sql.E001"):
            call_command("check", "--database", "default", stdout=StringIO())
        with pytest.raises(SystemCheckError, match="mcp_sql.E001"):
            call_command("migrate", "--check", skip_checks=False, stdout=StringIO())

    def test_the_grants_pipeline_names_it_instead_of_failing_in_sql(self, elsewhere):
        for args in ([], ["--apply"]):
            with pytest.raises(CommandError, match=f"finds it in schema {_SCHEMA!r}"):
                call_command("mcp_sql_grants", *args, stdout=StringIO())

    def test_post_migrate_logs_it_and_lets_migrate_finish(self, elsewhere, caplog):
        with caplog.at_level(ERROR, logger="mcp_sql.signals"):
            audit_grants_drift_after_migrate(
                sender=apps.get_app_config("mcp_sql"), using="default"
            )
        assert f"finds it in schema {_SCHEMA!r}" in caplog.text


class TestW001:
    """`check --deploy` warns while `PIN_SEARCH_PATH` is off (the default,
    kept: an extension outside `public` keeps its unqualified functions)."""

    @staticmethod
    def _w001(**kwargs) -> list:
        return [m for m in run_checks(**kwargs) if m.id == "mcp_sql.W001"]

    def test_warns_when_off(self, settings):
        settings.MCP_SQL = {**settings.MCP_SQL, "PIN_SEARCH_PATH": False}
        [warning] = self._w001(include_deployment_checks=True)
        assert not warning.is_serious()
        assert '"$user"' in warning.msg
        assert "mcp_sql_grants does not see it" in warning.msg
        assert 'PIN_SEARCH_PATH"] = True' in warning.hint

    def test_warns_on_the_shipped_default(self, settings):
        assert "PIN_SEARCH_PATH" not in settings.MCP_SQL
        assert len(self._w001(include_deployment_checks=True)) == 1

    def test_silent_when_on(self, settings):
        settings.MCP_SQL = {**settings.MCP_SQL, "PIN_SEARCH_PATH": True}
        assert self._w001(include_deployment_checks=True) == []

    def test_deploy_only(self, settings):
        settings.MCP_SQL = {**settings.MCP_SQL, "PIN_SEARCH_PATH": False}
        assert self._w001() == []
        out = StringIO()
        # `--tag security`: other test modules register throwaway models a
        # full `check` would report.
        call_command("check", "--deploy", "--tag", "security", stdout=out, stderr=out)
        assert "mcp_sql.W001" in out.getvalue()
