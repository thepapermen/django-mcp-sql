"""Django system checks for the MCP SQL surface (registered in `apps.ready`).

IDs are `mcp_sql.<level><nnn>`, Django's `<app label>.<E|W><number>` shape:

- `mcp_sql.E001` (database-tagged: runs on `migrate`, on `check --database
  default` and in Django's test runner, never on a plain `check` or at
  `runserver`): a whitelisted model's unqualified `db_table` names no
  relation in `public` while the login's `search_path` finds it in another
  schema (`grants.relations_off_default_schema`).
- `mcp_sql.W001` (deploy-only, `check --deploy`): `MCP_SQL["PIN_SEARCH_PATH"]`
  is off.
"""

from collections.abc import Iterable
from collections.abc import Sequence
from typing import Any

from django.apps import AppConfig
from django.apps import apps
from django.core.checks import CheckMessage
from django.core.checks import Error
from django.core.checks import Tags
from django.core.checks import register
from django.db import DEFAULT_DB_ALIAS
from django.db import connections
from mcp_sql.conf import mcp_sql_settings


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
    if connections[DEFAULT_DB_ALIAS].vendor != "postgresql":
        return []
    from mcp_sql.grants import off_default_schema_message
    from mcp_sql.grants import relations_off_default_schema

    errors: list[CheckMessage] = []
    for profile in mcp_sql_settings.profiles().values():
        tables: dict[str, str] = {}
        models = {}
        for entry in profile.allowed_models:
            try:
                models[entry] = apps.get_model(entry)
            except (LookupError, ValueError):
                continue
            tables[entry] = models[entry]._meta.db_table
        off = relations_off_default_schema(tables)
        for entry, schema in sorted(off.items()):
            message, remedy = off_default_schema_message(
                profile.name, entry, tables[entry], schema
            )
            errors.append(
                Error(message, hint=remedy, obj=models[entry], id="mcp_sql.E001")
            )
    return errors
