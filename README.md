# django-mcp-sql

[![PyPI](https://img.shields.io/pypi/v/django-mcp-sql)](https://pypi.org/project/django-mcp-sql/)
[![CI](https://github.com/thepapermen/django-mcp-sql/actions/workflows/ci.yml/badge.svg)](https://github.com/thepapermen/django-mcp-sql/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/thepapermen/django-mcp-sql/branch/main/graph/badge.svg)](https://codecov.io/gh/thepapermen/django-mcp-sql)
[![django packages](https://img.shields.io/badge/Django%20Packages-django--mcp--sql-8c3c26.svg)](https://djangopackages.org/packages/p/django-mcp-sql/)
[![Python versions](https://img.shields.io/pypi/pyversions/django-mcp-sql)](https://pypi.org/project/django-mcp-sql/)
[![License: MIT](https://img.shields.io/pypi/l/django-mcp-sql)](https://github.com/thepapermen/django-mcp-sql/blob/main/LICENSE)
[![Development status](https://img.shields.io/pypi/status/django-mcp-sql)](https://pypi.org/project/django-mcp-sql/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://www.mypy-lang.org/static/mypy_badge.svg)](https://mypy-lang.org/)

A tightly scoped, read-only PostgreSQL surface for an LLM agent (e.g.
Claude Code) over the [Model Context Protocol](https://modelcontextprotocol.io/).
Defense-in-depth at four layers: parser (sqlglot AST validators), executor
(PG NOLOGIN role + GUCs), DB-role (`mcp_readonly_role` SELECT grants), and
transport (DRF + django-oauth-toolkit OAuth 2.1 with PKCE + RFC 7591/8414/9728
discovery).

> **Status**: pre-release alpha (`0.1.0a2`). The package is used in
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

- **Python**: 3.11–3.13
- **Postgres**: 14+ recommended (uses `pg_has_role`, `information_schema.role_table_grants`, `SET LOCAL ROLE`, `CREATE OR REPLACE VIEW` — all of which work on earlier versions, but the test matrix runs on 14+).

### Supported combinations

The package's own surface is Django-version-agnostic; the version coupling
comes entirely from **DRF**, which gained each Django line in a later release.
Support is therefore a **staircase** — a higher Django needs a higher minimum
DRF:

| Django  | Python      | DRF (supported) | django-oauth-toolkit |
|---------|-------------|-----------------|----------------------|
| 4.2 LTS | 3.11, 3.12  | 3.14 – 3.17     | 3.2 – 3.3            |
| 5.2 LTS | 3.11 – 3.13 | 3.15 – 3.17     | 3.2 – 3.3            |
| 6.0     | 3.12, 3.13  | 3.17            | 3.3                  |

- The DRF floor is **3.14** — the lowest we support, i.e. what a legacy
  Django 4.2 app is likely already pinning. Each Django line has its own DRF
  minimum (5.x from 3.15, 6.0 from 3.17). A fresh `pip install` always
  resolves the **newest** in-range DRF (3.17) for whatever Django you run; the
  older DRF columns matter only when adopting the package into an app that
  already pins one.
- **Do not pin DRF below the minimum its Django requires** — e.g. DRF 3.14
  with Django ≥ 5.0 breaks at runtime. A single dependency floor cannot encode
  "DRF must track Django", and pip never auto-resolves that pair, but it also
  cannot stop you from pinning it by hand. Stay on a supported row above.
- **Django 6.0 drops Python 3.11**; **Django 4.2 has no Python 3.13** — hence
  the ragged Python columns.
- `django-oauth-toolkit`, `mcp`, `sqlglot`, `a2wsgi`, and `pydantic` are not
  Django-version-coupled within their declared ranges.

### Dropping into an existing app with an older pinned DRF

When you install the package into an **existing** project that already pins an
older DRF, that project's pins win — the package's floor does not force an
upgrade. The package's narrow DRF surface (an `OAuth2Authentication` subclass,
`@api_view`, `IsAuthenticated`) is verified to run on **DRF 3.14 with Django
4.2** by a dedicated CI leg, even though a greenfield install would never
select that pair. So a Django 4.2 app on DRF 3.14 can adopt the package without
touching its DRF pin. (DRF 3.14 + Django ≥ 5.0 is *not* supported — DRF 3.14
predates those Django lines.)

### MFA / django-allauth

The `allauth` extra (`django-mcp-sql[allauth]`) wires the TOTP gate to
`django-allauth[mfa] >= 65.14`. On a project running an older allauth without
`allauth.mfa`, skip the extra and point `MCP_SQL["MFA_CHECKER"]` at your own
2FA predicate — the core package has no hard allauth dependency.

The standalone suite (`make test`, settings in `tests/settings.py`) runs in CI
(`.github/workflows/ci.yml`) across every row above, plus pinned floor legs and
the DRF 3.14 + Django 4.2 legacy leg, against PostgreSQL 14.

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
