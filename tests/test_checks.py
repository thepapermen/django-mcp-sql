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

import ast
import re
from io import StringIO
from logging import ERROR

import pytest
from django.apps import apps
from django.core.checks import run_checks
from django.core.management import call_command
from django.core.management.base import CommandError
from django.core.management.base import SystemCheckError
from django.db import connection
from django.test.utils import override_system_checks
from mcp_sql.checks import check_whitelist_schemas
from mcp_sql.grants import quote_ident
from mcp_sql.grants import relation_sql
from mcp_sql.parser import relation_of
from mcp_sql.signals import audit_grants_drift_after_migrate
from mcp_sql.tests.testapp.models import MCPWidgetSecondProfileView

pytestmark = pytest.mark.django_db

_SCHEMA = "mcp_sql_fu7_s"
_ENTRY = "mcp_sql_testapp.MCPWidgetSecondProfileView"
_NAME = MCPWidgetSecondProfileView._meta.db_table  # unqualified
_COLUMNS = "(id bigint, name varchar(100))"
_FOUND = f'finds it in schema "{_SCHEMA}"'


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
        assert _FOUND in error.msg
        assert repr(f'{_SCHEMA}"."{_NAME}') in error.hint
        assert "Meta.managed = False" in error.hint
        assert "Curated-view pattern" in error.hint
        assert "migrate --skip-checks" in error.hint
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
            with pytest.raises(CommandError, match=_FOUND):
                call_command("mcp_sql_grants", *args, stdout=StringIO())

    def test_post_migrate_logs_it_and_lets_migrate_finish(self, elsewhere, caplog):
        with caplog.at_level(ERROR, logger="mcp_sql.signals"):
            audit_grants_drift_after_migrate(
                sender=apps.get_app_config("mcp_sql"), using="default"
            )
        assert _FOUND in caplog.text

    def test_post_migrate_names_it_before_the_role_exists(
        self, elsewhere, settings, caplog
    ):
        """The relation is looked up through the login, not the role: a
        fresh environment's first `migrate` (the system check left its
        pending entries to this run) names it although `role_setup.sql` has
        not run yet."""
        profile = settings.MCP_SQL["PROFILES"]["default"]
        settings.MCP_SQL = {
            **settings.MCP_SQL,
            "PROFILES": {"default": {**profile, "ROLE": "mcp_sql_fu7_no_role"}},
        }
        with caplog.at_level(ERROR, logger="mcp_sql.signals"):
            audit_grants_drift_after_migrate(
                sender=apps.get_app_config("mcp_sql"), using="default"
            )
        assert _FOUND in caplog.text


class TestE001Lookup:
    """What counts as the relation, in `public` and on the `search_path`
    (`grants.relations_off_default_schema`)."""

    _OTHER = "mcp_sql_fu7_a"

    @pytest.mark.parametrize(
        "create",
        [
            f"CREATE SEQUENCE {{schema}}.{_NAME}",
            f"CREATE TYPE {{schema}}.{_NAME} AS (x int)",
            f"CREATE INDEX {_NAME} ON {{schema}}.mcp_sql_fu7_t (id)",
        ],
        ids=["sequence", "composite type", "index"],
    )
    def test_only_relations_count(self, elsewhere, create):
        """A same-named sequence, composite type or index (all `pg_class`
        rows) neither stands for the relation in `public` nor is named as
        where the `search_path` finds it."""
        with connection.cursor() as cur:
            cur.execute(f"CREATE SCHEMA {self._OTHER}")
            for schema in ("public", self._OTHER):
                cur.execute(f"CREATE TABLE {schema}.mcp_sql_fu7_t (id int)")
            cur.execute(create.format(schema="public"))
            cur.execute(create.format(schema=self._OTHER))
            cur.execute(f"SET LOCAL search_path = {self._OTHER}, {_SCHEMA}, public")
        [error] = _e001(databases=["default"])
        assert _FOUND in error.msg

    def test_a_temporary_relation_is_not_named(self, whitelisted):
        """The session's temporary schema is on `current_schemas(true)`; a
        temporary relation is `PIN_SEARCH_PATH`'s case (W001), and no
        `db_table` names it."""
        with connection.cursor() as cur:
            cur.execute(f"CREATE TEMPORARY TABLE {_NAME} {_COLUMNS}")
        assert _e001(databases=["default"]) == []

    def test_a_temporary_relation_does_not_hide_the_schema(self, elsewhere):
        """Searched first (Postgres implies `pg_temp` ahead of the path),
        it is skipped and the schema the path lists is named."""
        with connection.cursor() as cur:
            cur.execute(f"CREATE TEMPORARY TABLE {_NAME} {_COLUMNS}")
        [error] = _e001(databases=["default"])
        assert _FOUND in error.msg
        assert "pg_temp" not in error.msg + error.hint

    def test_pg_catalog_is_not_named(self, whitelisted, monkeypatch):
        monkeypatch.setattr(MCPWidgetSecondProfileView._meta, "db_table", "pg_class")
        assert _e001(databases=["default"]) == []


class TestE001HostileSchemaName:
    """The schema name comes from the catalog: whoever may create a schema
    chooses it. The message shows it as an SQL identifier, and the remedy
    offers a `db_table` only when it is a Python literal that Django and
    the package read as exactly that relation."""

    @staticmethod
    def _create(schema: str) -> None:
        quoted = '"' + schema.replace('"', '""') + '"'
        with connection.cursor() as cur:
            cur.execute(f"CREATE SCHEMA {quoted}")
            cur.execute(f"CREATE TABLE {quoted}.{_NAME} {_COLUMNS}")
            cur.execute(f"SET LOCAL search_path = {quoted}, public")

    @staticmethod
    def _offered(hint: str) -> str:
        return ast.literal_eval(re.search(r"db_table = (.*?) \(and grant", hint)[1])

    @pytest.mark.parametrize(
        "schema", ["it's", "back\\slash", "Mixed Case", "ünï"], ids=repr
    )
    def test_an_expressible_name_is_offered_as_a_literal(self, whitelisted, schema):
        self._create(schema)
        [error] = _e001(databases=["default"])
        assert f"finds it in schema {quote_ident(schema)}." in error.msg
        offered = self._offered(error.hint)
        assert relation_of(offered) == (schema, _NAME)
        assert connection.ops.quote_name(offered) == relation_sql((schema, _NAME))

    @pytest.mark.parametrize(
        "schema",
        [
            'x"."y',
            'evil"; DROP TABLE t; --',
            "two\nlines",
            "rtl\u202eoverride",
        ],
        ids=repr,
    )
    def test_a_name_no_db_table_can_spell_is_not_offered(self, whitelisted, schema):
        self._create(schema)
        [error] = _e001(databases=["default"])
        assert f"finds it in schema {quote_ident(schema)}." in error.msg
        assert "db_table = " not in error.hint
        assert "rename the schema or the relation" in error.hint
        assert relation_sql((schema, _NAME)) in error.hint
        for text in (error.msg, error.hint):
            assert text.isprintable()
            assert text.count(quote_ident(schema)) == 1


_MIGRATIONS = "mcp_sql.tests.testapp.e001_migrations"


class _OnlyTestappMigrated:
    """`MIGRATION_MODULES` with the test app's migrations at `module` and
    every other app's disabled, as pytest-django's `--nomigrations` leaves
    them (their tables exist already)."""

    def __init__(self, module: str) -> None:
        self.module = module

    def __contains__(self, app_label: str) -> bool:
        return True

    def __getitem__(self, app_label: str) -> str | None:
        return self.module if app_label == "mcp_sql_testapp" else None


class TestE001PendingMigrations:
    """`migrate` runs the database checks before it applies anything, so a
    whitelisted table that a pending migration creates in `public` is not
    there yet: E001 stopped the very `migrate` that would create it, on
    every run, and its remedy pointed `db_table` at the other schema's
    same-named relation. The check skips an entry whose app has migrations
    still to apply; the `post_migrate` grants pipeline names it if it is
    still wrong once they ran."""

    @staticmethod
    def _migrate() -> None:
        """`manage.py migrate` with its system checks on (a programmatic
        `call_command` skips them unless asked), E001 the only one
        registered: other test modules register throwaway models that
        Django's own model checks refuse."""
        with override_system_checks([check_whitelist_schemas]):
            call_command("migrate", skip_checks=False, verbosity=0)

    @pytest.fixture
    def migrations_at(self, elsewhere, settings):
        def point_at(module: str) -> None:
            settings.MIGRATION_MODULES = _OnlyTestappMigrated(module)

        return point_at

    def test_not_reported_while_the_app_has_a_migration_to_apply(self, migrations_at):
        migrations_at(f"{_MIGRATIONS}.creates")
        assert _e001(databases=["default"]) == []

    def test_migrate_runs_and_creates_it(self, migrations_at):
        migrations_at(f"{_MIGRATIONS}.creates")
        self._migrate()
        with connection.cursor() as cur:
            cur.execute("SELECT to_regclass(%s)", [f"public.{_NAME}"])
            assert cur.fetchone()[0] is not None
        assert _e001(databases=["default"]) == []

    def test_still_off_after_migrate_post_migrate_names_it(self, migrations_at, caplog):
        """The pending migration does not create it in `public`: `migrate`
        finishes, its `post_migrate` receiver logs the reconciler's message,
        and the next check (nothing pending now) is E001."""
        migrations_at(f"{_MIGRATIONS}.noop")
        with caplog.at_level(ERROR, logger="mcp_sql.signals"):
            self._migrate()
        assert _FOUND in caplog.text
        [error] = _e001(databases=["default"])
        assert _ENTRY in error.msg

    def test_reported_once_the_apps_migrations_are_applied(self, migrations_at):
        """A migrations package with nothing in it: nothing to apply, so
        the check stands (an app without migrations at all is the suite's
        own `--nomigrations` state, `TestE001`)."""
        migrations_at(_MIGRATIONS)
        assert len(_e001(databases=["default"])) == 1

    def test_a_database_without_django_migrations(self, migrations_at):
        """A fresh database (no `django_migrations` table, every migration
        pending): the check neither fails nor reports."""
        migrations_at(f"{_MIGRATIONS}.creates")
        with connection.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS django_migrations")
        assert _e001(databases=["default"]) == []


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
