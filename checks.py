"""Django system checks for the MCP SQL surface (registered in `apps.ready`).

IDs are `mcp_sql.<level><nnn>`, Django's `<app label>.<E|W><number>` shape:

- `mcp_sql.E001` (database-tagged: runs on `migrate`, on `check --database
  default` and in Django's test runner, never on a plain `check` or at
  `runserver`): a whitelisted model's unqualified `db_table` names no
  relation in `public` while the login's `search_path` finds it in another
  schema (`grants.relations_off_default_schema`), unless the model's app
  has migrations still to apply.
- `mcp_sql.W001` (`Tags.security`, deploy-only: `check --deploy`):
  `MCP_SQL["PIN_SEARCH_PATH"]` is off, so a relation earlier on the
  `search_path` can shadow a whitelisted name unreported.
- `mcp_sql.W002` (`Tags.security`, deploy-only): refresh tokens are on
  (`MCP_SQL["REFRESH_TOKEN_MAX_AGE_SECONDS"] > 0`) while DOT's
  `REFRESH_TOKEN_EXPIRE_SECONDS` is `0` or unset, so DOT never expires a
  refresh token and `cleartokens` never deletes a rotated-out one.
"""

from collections.abc import Iterable
from collections.abc import Sequence
from typing import Any

from django.apps import AppConfig
from django.apps import apps
from django.core.checks import CheckMessage
from django.core.checks import Error
from django.core.checks import Tags
from django.core.checks import Warning as CheckWarning
from django.core.checks import register
from django.db import DEFAULT_DB_ALIAS
from django.db import connections
from django.db.backends.base.base import BaseDatabaseWrapper
from django.db.migrations.exceptions import InconsistentMigrationHistory
from django.db.migrations.exceptions import NodeNotFoundError
from django.db.migrations.executor import MigrationExecutor
from django.db.models import Model
from mcp_sql.conf import mcp_sql_settings
from mcp_sql.conf import refresh_tokens_enabled
from oauth2_provider.settings import oauth2_settings


@register(Tags.database)
def check_whitelist_schemas(
    app_configs: Sequence[AppConfig] | None = None,
    databases: Iterable[str] | None = None,
    **kwargs: Any,
) -> list[CheckMessage]:
    """`mcp_sql.E001`: an unqualified whitelisted `db_table` that `public`
    lacks but the login's `search_path` resolves elsewhere.

    Since round 16 an unqualified `db_table` is the relation in `public`
    (until 0.1.0b5 GRANT resolved it through the `search_path`), so for
    such an entry `mcp_sql_grants --apply` fails (`relation "public.<name>"
    does not exist`), and so would the `post_migrate` drift check's
    view-parity probe of an unmanaged entry. As a database check it runs
    before `migrate` applies anything (`migrate` runs the checks with its
    database on Django 4.2 through 6.1), so the error stops a `manage.py
    migrate` up front rather than at `post_migrate`.

    Running first is also why an entry whose app has a migration still to
    apply is skipped (`_apps_with_pending_migrations`): that migration may
    be the one that creates the relation in `public`, and failing on it
    stopped, on every run, the `migrate` that would have created it (with a
    remedy naming the other schema's same-named relation). If the relation
    is still not in `public` once they ran, the `post_migrate` receiver
    logs the reconciler's refusal (`grants._verify_off_default_schema`)
    and the next `migrate` / check reports E001. The hint names
    `migrate --skip-checks` for a relation that a migration of another app
    creates.

    Runs on the `default` alias only, through the connection the grants
    pipeline uses (`grants._verify_default_alias`): that is where
    `mcp_sql_grants` and the `post_migrate` receiver resolve and grant, as
    the app login, with the login's `search_path`. The read alias (the same
    database, possibly another login) is not consulted: it enters a profile
    role, whose `"$user"` differs, and with `PIN_SEARCH_PATH` on it pins
    `public, pg_temp`, so `public` is what both sides must hold.
    An `ALLOWED_MODELS` entry whose app is not installed is skipped (the
    grants pipeline reports it).
    """
    if not databases or DEFAULT_DB_ALIAS not in databases:
        return []
    if app_configs is not None and not any(a.name == "mcp_sql" for a in app_configs):
        return []
    connection = connections[DEFAULT_DB_ALIAS]
    if connection.vendor != "postgresql":
        return []
    from mcp_sql.grants import off_default_schema_message
    from mcp_sql.grants import relations_off_default_schema

    pending: set[str] | None = None
    errors: list[CheckMessage] = []
    for profile in mcp_sql_settings.profiles().values():
        models = _installed_models(profile.allowed_models)
        tables = {entry: model._meta.db_table for entry, model in models.items()}
        off = relations_off_default_schema(tables)
        if not off:
            continue
        if pending is None:
            # Built once, and only when there is something to report: it
            # imports every app's migrations.
            pending = _apps_with_pending_migrations(connection)
        for entry, schema in sorted(off.items()):
            if models[entry]._meta.app_label in pending:
                continue
            message, remedy = off_default_schema_message(
                profile.name, entry, tables[entry], schema
            )
            hint = (
                f"{remedy} If a migration of another app creates the relation "
                "in public, run `manage.py migrate --skip-checks` (the "
                "post_migrate grants check then logs this error if it is still "
                "wrong)."
            )
            errors.append(
                Error(message, hint=hint, obj=models[entry], id="mcp_sql.E001")
            )
    return errors


def _installed_models(entries: Iterable[str]) -> dict[str, type[Model]]:
    """`{entry: model}` for the `ALLOWED_MODELS` entries whose app is
    installed."""
    models = {}
    for entry in entries:
        try:
            models[entry] = apps.get_model(entry)
        except (LookupError, ValueError):
            continue
    return models


def _apps_with_pending_migrations(connection: BaseDatabaseWrapper) -> set[str]:
    """The labels of the apps with a migration `migrate` would apply on
    `connection` (to every app's latest migration, as a bare `migrate`
    does). Read as `migrate` reads it (`MigrationExecutor`): with no
    `django_migrations` table yet (a fresh database) every migration is
    pending, and an app without migrations has none. A graph Django cannot
    build (a dependency on a migration that does not exist) skips nothing:
    the check then reports as it would without this lookup, rather than
    raising out of `check`."""
    try:
        executor = MigrationExecutor(connection)
        plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
    except (NodeNotFoundError, InconsistentMigrationHistory):
        return set()
    return {migration.app_label for migration, _backwards in plan}


@register(Tags.security, deploy=True)
def check_search_path_pinned(
    app_configs: Sequence[AppConfig] | None = None, **kwargs: Any
) -> list[CheckMessage]:
    """`mcp_sql.W001` (`check --deploy` only): `PIN_SEARCH_PATH` is off.

    The default stays off (an extension outside `public` keeps its
    unqualified functions and operators); the deploy check is where an
    install that never chose says so. docs/architecture.md "`search_path`
    is pinned only on request" has what each mode guarantees."""
    if mcp_sql_settings.PIN_SEARCH_PATH:
        return []
    return [
        CheckWarning(
            'MCP_SQL["PIN_SEARCH_PATH"] is False: an unqualified table name '
            "in an agent's query resolves through the database's own "
            "search_path, so a same-named relation in a schema searched "
            'before public (a "$user" schema named after the profile role, '
            "a temporary relation on a backend shared under transaction-mode "
            "pooling) is served under the whitelisted name, and "
            "mcp_sql_grants does not see it.",
            hint=(
                'Turn it on: MCP_SQL["PIN_SEARCH_PATH"] = True. Functions and '
                "operators of an extension installed outside public then "
                "need qualifying (ext.f(...), OPERATOR(ext.op)). See "
                'docs/architecture.md "`search_path` is pinned only on '
                'request".'
            ),
            id="mcp_sql.W001",
        )
    ]


@register(Tags.security, deploy=True)
def check_refresh_tokens_expire(
    app_configs: Sequence[AppConfig] | None = None, **kwargs: Any
) -> list[CheckMessage]:
    """`mcp_sql.W002` (`check --deploy` only): refresh on, DOT's refresh
    tokens unexpirable.

    The package's own cap still ends every chain; what DOT's value decides
    is how long `cleartokens` keeps the rows. A warning, not a boot error:
    the value is the operator's (docs/oauth.md "Keeping the refresh-token
    table bounded")."""
    if not refresh_tokens_enabled() or oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS:
        return []
    return [
        CheckWarning(
            'MCP_SQL["REFRESH_TOKEN_MAX_AGE_SECONDS"] turns refresh tokens on '
            "while OAUTH2_PROVIDER['REFRESH_TOKEN_EXPIRE_SECONDS'] is "
            f"{oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS!r}: DOT never "
            "expires a refresh token, and cleartokens never deletes a "
            "rotated-out one, so the refresh-token table grows without bound.",
            hint=(
                "Give OAUTH2_PROVIDER['REFRESH_TOKEN_EXPIRE_SECONDS'] a value "
                'of at least MCP_SQL["REFRESH_TOKEN_MAX_AGE_SECONDS"] (shorter lets '
                "cleartokens delete the rotated-out tokens reuse detection "
                "matches a replay against) and run `manage.py cleartokens` on "
                'a schedule. See docs/oauth.md "Keeping the refresh-token '
                'table bounded".'
            ),
            id="mcp_sql.W002",
        )
    ]
