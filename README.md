# django-mcp-sql

[![PyPI](https://img.shields.io/pypi/v/django-mcp-sql)](https://pypi.org/project/django-mcp-sql/)
[![CI](https://github.com/thepapermen/django-mcp-sql/actions/workflows/ci.yml/badge.svg)](https://github.com/thepapermen/django-mcp-sql/actions/workflows/ci.yml)

A tightly scoped, read-only PostgreSQL surface for an LLM agent (e.g.
Claude Code) over the [Model Context Protocol](https://modelcontextprotocol.io/).
Defense-in-depth at four layers: parser (sqlglot AST validators), executor
(PG NOLOGIN role + GUCs), DB-role (`mcp_readonly_role` SELECT grants), and
transport (DRF + django-oauth-toolkit OAuth 2.1 with PKCE + RFC 7591/8414/9728
discovery).

> **Status**: pre-release alpha (`0.1.0a1`). The package is used in
> production as part of a larger Django project; expect the public API and
> settings shape to move between alpha releases.

## What you get

Three MCP tools mounted at `/mcp/sql/`:

| Tool | Purpose |
|---|---|
| `list_tables()` | Returns the whitelisted db_tables for the surface (sorted). |
| `describe_table(name)` | Returns column types / null / pk for a whitelisted table. |
| `run_query(sql, limit=None)` | Validates + executes a single SELECT. Returns `{columns, rows, row_count, truncated, duration_ms, hint, rejection_reason, error, data_handling}`. `rows` (and `error`, when set) come back wrapped in a per-response random-UUID `<untrusted-data-…>` fence so DB content carrying a prompt-injection payload can't be read as agent instructions; `data_handling` explains the boundary. |

Every call writes one append-only `MCPQueryLog` audit row. Every auth
rejection writes one `MCPAuthRejectionLog` row (six resolved-user gates;
anonymous / bad-token probing goes through Django-cache counters with a
silent per-IP block, not the audit table — use a shared cache backend
(Redis, Memcached) in production: with a per-process backend like LocMem
the counters, and therefore the block, are per-worker).

**Observability** — per-user query-volume tripwires (one `ERROR` per
`(user, decision, window)` crossing of `VOLUME_ALERT_THRESHOLDS`; alerts,
never blocks), an `ERROR` when a user is added to the MCP permission group,
and read-only Django admin browsers for both audit tables plus a per-user
usage-summary view (allowed / rejected / auth-rejection counts per rolling
window). The package emits `logger.error` only — wire a Sentry
`LoggingIntegration(event_level=logging.ERROR)` to receive these as events;
the package itself never imports `sentry_sdk`.

## Postgres-only by design

The package depends on Postgres features that don't port: `SET LOCAL ROLE`
into a NOLOGIN role, `statement_timeout` / `lock_timeout` /
`idle_in_transaction_session_timeout` / `default_transaction_read_only`
GUCs, PG-only error codes (`57014`, `42501`), `CREATE OR REPLACE VIEW`
semantics, sqlglot's `dialect='postgres'`. There is no design path to
MySQL / SQLite without a parallel implementation — hence `django-mcp-sql`
not `django-mcp-mysql` etc.

## Installation

```sh
pip install django-mcp-sql
# Optional extras
pip install "django-mcp-sql[allauth]"   # wire MFA gate to allauth.mfa.utils.is_mfa_enabled
```

Then in your Django settings:

```python
INSTALLED_APPS = [
    # ... your apps ...
    "rest_framework",
    "oauth2_provider",
    "mcp_sql",
]

DATABASES = {
    "default": { ... },
    # Required: dedicated read-only alias. The executor asserts
    # connection.alias == MCP_SQL["DB_ALIAS"] before issuing any SELECT.
    "mcp_readonly": {
        # ... pointed at the same database as default but as a non-superuser ...
        "OPTIONS": {"application_name": "mcp-readonly"},
        "ATOMIC_REQUESTS": False,
        "CONN_MAX_AGE": 0,
    },
}

DATABASE_ROUTERS = ["mcp_sql.db_router.McpSqlRouter"]

MCP_SQL = {
    "ALLOWED_MODELS": [
        "auth.Permission",  # your real whitelist goes here
    ],
    "BAN_SELECT_STAR": True,
    "LIMITS": {"DEFAULT_LIMIT": 10, "HARD_LIMIT": 100, "BYTES_LIMIT": 256 * 1024},
    # Per-user volume tripwires: {decision: {window_seconds: threshold}}.
    # Crossing emits one Sentry ERROR per (user, decision, window) bucket;
    # it alerts, it never blocks.
    "VOLUME_ALERT_THRESHOLDS": {
        "allowed": {3600: 50, 86400: 150},
        "rejected": {3600: 50, 86400: 150},
    },
    "BAD_TOKEN_IP_THRESHOLD": 100,
    "BAD_TOKEN_IP_WINDOW_SECONDS": 21600,
    # Optional overrides — see `mcp_sql/conf.py` DEFAULTS for the full list:
    # "RESOURCE_NAME": "My App",
    # "MFA_CHECKER": "allauth.mfa.utils.is_mfa_enabled",
    # "SESSION_MODEL": "your_app.Session",  # opt-in runtime session-existence gate;
                                            # must be a session model with a `user` FK
                                            # (stock `django.contrib.sessions.Session`
                                            # does NOT qualify — its absence of a `user`
                                            # column is why the default is `None`)
}

OAUTH2_PROVIDER = {
    "OAUTH2_VALIDATOR_CLASS": "mcp_sql.oauth.MCPOAuth2Validator",
    "SCOPES": {"mcp:sql": "Read-only SQL surface for MCP agents"},
    "DEFAULT_SCOPES": ["mcp:sql"],
    "ACCESS_TOKEN_EXPIRE_SECONDS": 6 * 3600,
    "REFRESH_TOKEN_EXPIRE_SECONDS": 0,
    "AUTHORIZATION_CODE_EXPIRE_SECONDS": 60,
    "PKCE_REQUIRED": True,
    "ALLOWED_REDIRECT_URI_SCHEMES": ["http"],   # RFC 8252 loopback
}
```

Wire the URLs in your project's `urls.py`:

```python
urlpatterns = [
    # ... your routes ...
    path("", include("mcp_sql.urls")),
]
```

Then run the DBA setup once per environment (creates the
`mcp_readonly_role` Postgres role + role-level guard GUCs):

```sh
psql -U <superuser> -d <database> \
    -v app_role=<your_app_role> \
    -f $(python -c "import mcp_sql, os; print(os.path.join(os.path.dirname(mcp_sql.__file__), 'sql/role_setup.sql'))")
```

Then apply migrations and the SELECT grants:

```sh
python manage.py migrate
python manage.py mcp_sql_grants --apply
```

## Documentation

The architecture / design doc and the full operational runbooks ship inside
the package (importable consumers find them under `mcp_sql/docs/`):

- `docs/architecture.md` — design, file map, settings shape, OAuth surface,
  curated-view pattern, the complete "Watch out" list.
- `docs/role-setup.md` — DBA setup, grants reconciliation, sanity checks.
- `docs/oauth.md` — OAuth issuance gate, MCP client registration, incident response.

## Compatibility

- **Python**: 3.11+
- **Django**: 5.2+ (LTS line; 6.0 untested).
- **Postgres**: 14+ recommended (uses `pg_has_role`, `information_schema.role_table_grants`, `SET LOCAL ROLE`, `CREATE OR REPLACE VIEW` — all of which work on earlier versions, but the test matrix runs on 14+).

The package has been exercised against a 2000+ test suite in a real
Django CRM. Its own standalone suite (`make test`, settings in
`tests/settings.py`) runs in CI across Python 3.11–3.13 against
PostgreSQL 14 (`.github/workflows/ci.yml`).

## Postgres role setup

Once per environment, a DBA with PG superuser rights applies
`sql/role_setup.sql` to create the `mcp_readonly_role` role + the
role-level guard GUCs (`statement_timeout`, `lock_timeout`,
`idle_in_transaction_session_timeout`, `default_transaction_read_only`)
and grant the role membership to the consuming app's PG user. The script
is idempotent and is parameterised by a `-v app_role=<role>` psql
variable so a single SQL file works across deployments whose app role
differs.

```sh
psql -h <pg_host> -U <pg_superuser> -d <database> \
    -v app_role=<app_pg_role> \
    -f sql/role_setup.sql

# Verify:
psql -h <pg_host> -U <pg_superuser> -d <database> -c "\du mcp_readonly_role"
# Expected: row present, "Cannot login".
```

After the role exists, apply the package's migrations and reconcile the
table-level SELECT grants:

```sh
python manage.py migrate
python manage.py mcp_sql_grants --apply
```

See `docs/role-setup.md` for the full DBA-facing runbook (drift
detection, CI gates, troubleshooting).

## Local example

A standalone, stock-Django consumer of the package lives in the
[`example/`](https://github.com/thepapermen/django-mcp-sql/tree/main/example)
directory of the repository (not shipped in the wheel). It demonstrates the
package against a vanilla Django setup — `auth.User`, stock sessions, no
allauth — including a two-profile (multi-tier) configuration with a
row-and-column-limited curated view. Its own README carries the full
end-to-end runbook: bootstrap, OAuth dance, and registering the server with
`claude mcp add`.

## Development

Run the package's own test suite (needs `uv` and a reachable PostgreSQL —
see `tests/settings.py` for the `MCP_SQL_TEST_PG_*` connection env vars.
Bootstrap `mcp_readonly_role` via `sql/role_setup.sql` first — several
tests enter it with `SET LOCAL ROLE` — and connect as a superuser so the
role-isolation tests run instead of skipping):

```sh
make test
```

Build the distribution and verify the wheel installs cleanly into a fresh
venv (Django-independent imports + package-data presence):

```sh
make build              # produces ./dist/django_mcp_sql-<version>-py3-none-any.whl + .tar.gz
make test-install       # ephemeral build + venv install + import & package-data smoke
```

All targets require `uv` on PATH (install once: `curl -LsSf https://astral.sh/uv/install.sh | sh`).
Release/extraction mechanics live in `RELEASING.md`; contribution
expectations in `CONTRIBUTING.md`.

## License

MIT.
