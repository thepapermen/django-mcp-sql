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

Let an LLM agent — like Claude Code — run **read-only** SQL against your
PostgreSQL database over the
[Model Context Protocol](https://modelcontextprotocol.io/), without handing it
a database login or the ability to write anything.

> **In one line:** the self-hosted, Postgres-only safe-execution-and-access-control
> layer that gives Django shops the part of [QueryBear](https://querybear.com) a
> SaaS can't — an agent reading a precisely-scoped slice of your database, with
> your database credentials never leaving your infrastructure and the agent able
> to reach only the slice you expose, never a login or the rest of your data.
> Bring your own SQL-writing agent. ([How it compares](#how-it-compares) — and
> [where your data actually goes](#where-your-data-actually-goes).)

**It already runs in production**, mediating an LLM agent's database access
inside a larger Django application — this package is an extraction of that
code, not a greenfield experiment.

It's safe by construction, not by asking the model nicely. Even a confused or
hijacked agent can only ever touch the slice of data you chose to expose — four
independent layers enforce it, so a bypass has to beat all four:

- **It sees only what you expose.** Each access profile's whitelist points at
  the specific tables — or, better, [curated row- and column-limited
  views](docs/architecture.md#curated-view-pattern) — you pick. You can hand the
  agent a view that drops the sensitive columns and filters the rows, and the
  underlying table stays invisible: a login-less Postgres role simply holds no
  `SELECT` on anything off the list, so "invisible" is enforced by the database,
  not by trust. (Run several profiles to give different agents different slices.)
- **It only runs `SELECT`.** Every statement is parsed and checked first;
  anything that isn't a single read-only query is rejected before it reaches the
  database.
- **It runs in a sandbox.** Queries execute in a locked-down, time-limited
  transaction that can't linger or mutate.
- **Nothing reaches it unauthenticated.** The endpoint sits behind OAuth 2.1
  with PKCE (RFC 7591/8414/9728 discovery); an unauthenticated client can't even
  open the door.

### Where your data actually goes

**This package never ships your database anywhere.** Your Postgres credentials
stay put — the agent authenticates to *you* over OAuth and never holds a
database login — and anything you didn't whitelist stays invisible, enforced by
a role that genuinely can't read it.

What the agent *does* receive is the slice you chose to expose: the rows a query
returns and the schema of the tables you allowed. Those bytes go wherever the
agent runs. Point a cloud model like Claude at the endpoint and the rows it
reads travel to that model's provider, exactly like any other prompt — and no
library on the database side can change that.

Want the queried slice to stay on your hardware too? Run a **local** agent
against the same endpoint: the access-control and audit story is identical, and
then nothing leaves at all. So the product doesn't keep your data *in* — it
controls *which* rows an agent can ever reach, and logs every one that moves.
Pick your agent accordingly.

> **Status**: beta. The public API and settings shape are stabilizing, but
> may still shift before `1.0`. The PyPI badge above shows the current
> release.

## Quickstart — try it in 5 minutes

The fastest way to see this work is the bundled **example app** — a vanilla
Django project (`auth.User`, stock sessions, no allauth) that wires the package
end to end, including a two-tier curated-view setup. You don't have to touch
your own project to watch Claude Code query a database.

```sh
git clone https://github.com/thepapermen/django-mcp-sql
cd django-mcp-sql/example

# Needs `uv` and a reachable PostgreSQL. See example/README.md for the one-time
# login-role snippet and the EXAMPLE_PG_* connection defaults.
make install                                       # venv + editable install of the package
make createdb migrate roles grants bootstrap_demo  # db, migrations, PG roles + grants, demo users
make runserver                                     # serves http://127.0.0.1:8001/

# In another terminal, register it with Claude Code — then just ask Claude to use it:
claude mcp add --transport http mcp-sql-example http://127.0.0.1:8001/mcp/sql/
```

The first tool call kicks off the OAuth dance (log in as `demo` / `demo`);
after that, `list_tables` and `run_query` work against the demo data. The full
walkthrough — the OAuth flow, the second access tier, the MFA note — is in the
[example README](https://github.com/thepapermen/django-mcp-sql/tree/main/example#end-to-end-runbook).

Ready to wire it into your own project? See [Installation](#installation) below.

## What you get

Three MCP tools mounted at `/mcp/sql/`:

| Tool | Purpose |
|---|---|
| `list_tables()` | Returns the whitelisted db_tables for the surface (sorted). |
| `describe_table(name)` | Returns column types / null / pk for a whitelisted table. |
| `run_query(sql, limit=None)` | Validates + executes a single SELECT. Returns `{columns, rows, row_count, truncated, duration_ms, hint, rejection_reason, error, data_handling}`. The `rows`/`error` fields come back inside a prompt-injection fence — see [Security model](#security-model--prompt-injection--untrusted-data). |

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

## Security model — prompt injection & untrusted data

> [!WARNING]
> **`run_query` returns database content verbatim to the agent — treat every
> value as a prompt-injection vector.** Any column an outside party can write
> to (free-text fields, names, uploaded filenames — anything your app ingested
> from an outside source) can carry instructions aimed at the
> *agent*, not at you. An agent that can read this data **and** also act
> (shell, file write, web fetch, other MCP tools) holds the "lethal trifecta" —
> private-data access + exposure to untrusted content + the ability to
> exfiltrate — so an injected row can re-steer its *next* action.
>
> As defense-in-depth, `run_query` `rows` and `error` come back wrapped in a
> **per-response random-UUID `<untrusted-data-…>` fence** with an instruction
> to treat the contents as data, never commands (the random tag stops an
> attacker from closing the fence from inside a cell value). **This is
> belt-and-suspenders, not a guarantee** — nothing forces the model to obey
> the fence, so it must never be your primary control. Safer designs:
>
> - **Exclude user-supplied data from the surface.** Point each profile's
>   whitelist at [curated, column-limited PostgreSQL views](docs/architecture.md#curated-view-pattern)
>   that drop the attacker-controllable free-text columns, rather than at raw
>   tables.
> - **Don't expose this surface to a privileged agent.** Keep the read-only
>   SQL context separate from any agent that also holds act/exfiltrate tools,
>   so a malicious row has nothing to pivot into.
>
> Further reading (the prior art this fence design follows):
> [Defense in Depth for MCP Servers](https://supabase.com/blog/defense-in-depth-mcp) ·
> ["Supabase MCP can leak your entire SQL database"](https://generalanalysis.com/blog/supabase-mcp-blog) (the disclosure it answers) ·
> [Supabase MCP docs](https://supabase.com/docs/guides/ai-tools/mcp) ·
> [reference wrapper source](https://github.com/supabase-community/supabase-mcp/blob/main/packages/mcp-server-supabase/src/tools/database-operation-tools.ts).

## Postgres-only by design

The package depends on Postgres features that don't port: `SET LOCAL ROLE`
into a NOLOGIN role, `statement_timeout` / `lock_timeout` /
`idle_in_transaction_session_timeout` / `default_transaction_read_only`
GUCs, PG-only error codes (`57014`, `42501`), `CREATE OR REPLACE VIEW`
semantics, sqlglot's `dialect='postgres'`. There is no design path to
MySQL / SQLite without a parallel implementation — hence `django-mcp-sql`
not `django-mcp-mysql` etc.

## How it compares

Most "AI + your database" tools are **hosted services that write the SQL for
you**: you connect a database, ask a question in English, the service generates
a query, runs it on *its* infrastructure, and hands back rows. Products like
[QueryBear](https://querybear.com) work this way. They're a good fit when you
want answers fast and don't mind your queries — and sometimes your data —
passing through someone else's servers.

`django-mcp-sql` is the other half of that stack. It does **not** generate SQL
and it is **not** a service. The agent (Claude Code, or anything that speaks
MCP) writes the SQL; this package is the part that decides whether that SQL is
allowed to run, runs it safely, and records it. It's a library you embed in a
Django app you already operate.

It isn't really a feature-by-feature contest — it's a fork in the road:

<table>
<thead>
<tr>
<th></th>
<th>Hosted NL→SQL service<br>(e.g. <a href="https://querybear.com">QueryBear</a>)</th>
<th>Reference / platform MCP server<br>(e.g. Anthropic, Supabase, Neon)</th>
<th><code>django-mcp-sql</code></th>
</tr>
</thead>
<tbody>
<tr>
<th align="left">Writes the SQL?</th>
<td>Yes — natural language → SQL</td>
<td colspan="2">No — the agent writes it</td>
</tr>
<tr>
<th align="left">Credentials</th>
<td>Held by the vendor</td>
<td colspan="2">You hold them — agent never gets a DB login</td>
</tr>
<tr>
<th align="left">Your data</th>
<td>Passes through the vendor's servers</td>
<td colspan="2">Goes to whatever agent you point at it</td>
</tr>
<tr>
<th align="left">Safety model</th>
<td>Vendor-defined</td>
<td>Varies by implementation</td>
<td>Four independent layers (parser → role grants → sandbox → OAuth)</td>
</tr>
<tr>
<th align="left">Audit</th>
<td>Vendor dashboard</td>
<td>Varies</td>
<td>Append-only tables in your own DB</td>
</tr>
</tbody>
</table>

Pick a hosted service if you want natural-language answers with the least
setup. Pick this if you already run a Django + Postgres app and want access
that's enforced by four independent layers and auditable line by line — not safe
because you trusted a prompt or a vendor. And if your data genuinely can't leave
your perimeter, pair it with a local agent (see [Where your data actually
goes](#where-your-data-actually-goes)) so the queried slice stays on your
hardware too.

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
    # At least one access tier (profile) is REQUIRED — the package validates
    # this at startup and refuses to boot without it. The `default` profile
    # below reproduces the original single-tier behaviour; add more entries
    # for multi-tier setups, each with its own unique ROLE /
    # PERMISSION_CODENAME / GROUP_NAME. See docs/architecture.md "Profiles".
    "PROFILES": {
        "default": {
            "ROLE": "mcp_readonly_role",  # NOLOGIN PG role entered via SET LOCAL ROLE
            "PERMISSION_CODENAME": "use_mcp_session",  # binds a user to this tier
            "GROUP_NAME": "mcp_sql_users",
            "ALLOWED_MODELS": [
                "auth.Permission",  # your real whitelist goes here
            ],
            # "SESSION_CONTEXT": "your_app.scoping.context",  # optional per-row hook
        },
    },
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
    # MFA gate (fail-closed) — set this before onboarding anyone. The default
    # `deny_unconfigured_mfa` returns False for EVERY user, so the whole MCP
    # surface is locked out (the app logs a startup WARNING) until you wire a
    # real check. django-allauth projects use:
    # "MFA_CHECKER": "allauth.mfa.utils.is_mfa_enabled",
    # Optional overrides — see `mcp_sql/conf.py` DEFAULTS for the full list:
    # "RESOURCE_NAME": "My App",
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
