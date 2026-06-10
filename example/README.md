# django-mcp-sql example project

A standalone, stock-Django consumer of
[`django-mcp-sql`](https://github.com/thepapermen/django-mcp-sql) — vanilla
`auth.User`, stock sessions, no allauth, no custom middleware. It exists to
prove the package works against a fresh Django setup and to walk an
end-to-end OAuth + MCP flow locally, including the **multi-profile** (access
tier) feature:

- **`default` profile** — the flat demo surface: `auth.Permission` (so
  `list_tables` returns something inspectable) plus `notes.Note`
  (user-created rows for `run_query`). Role `mcp_readonly_role`, group
  `mcp_sql_users`, permission `use_mcp_session`.
- **`second_profile`** — a second tier with its own Postgres role
  (`mcp_ro_second_profile`), group, and permission, whose only readable
  object is a curated VIEW (`notes.MCPNoteSecondProfileView`) that row- AND
  column-limits notes: only titles starting with "S", without
  `body`/`author_id`. The per-role row-limiting pattern from
  `docs/architecture.md`.

This directory is **never published to PyPI** (its `pyproject.toml` carries
the `Private :: Do Not Upload` classifier) and is not part of the
`django-mcp-sql` wheel. It consumes the sibling package as an editable
install via `[tool.uv.sources]`, so package edits reflect immediately.

## Prerequisites

- `uv` on PATH (install with `curl -LsSf https://astral.sh/uv/install.sh | sh`).
- A reachable PostgreSQL cluster. The per-profile read-only roles
  (including `mcp_readonly_role`) are created later by `make roles` — no
  separate role bootstrap needed.
- The `createdb` and `psql` CLIs on PATH (Debian: `postgresql-client`;
  macOS Homebrew: `postgresql`).
- The example's login role, created once by any superuser (`CREATEROLE` is
  what lets `make roles` create the read-only roles and grant their
  membership later):

  ```sh
  psql -h 127.0.0.1 -U <superuser> -d postgres -c \
      "CREATE ROLE mcp_sql_example LOGIN CREATEDB CREATEROLE PASSWORD 'mcp_sql_example';"
  ```

  Alternatively skip this and point `EXAMPLE_PG_USER` / `EXAMPLE_PG_PASSWORD`
  at an existing superuser.

Connection settings come from environment variables with these defaults:

| Variable | Default |
|---|---|
| `EXAMPLE_PG_HOST` | `127.0.0.1` |
| `EXAMPLE_PG_PORT` | `5432` |
| `EXAMPLE_PG_DB` | `mcp_sql_example_local` |
| `EXAMPLE_PG_USER` | `mcp_sql_example` |
| `EXAMPLE_PG_PASSWORD` | `mcp_sql_example` |

`make roles` (the DBA step) connects as `ROLES_PG_USER` /
`ROLES_PG_PASSWORD`, defaulting to the `EXAMPLE_PG_*` login. On a fresh
cluster the `CREATEROLE` attribute from the prerequisite snippet suffices.
When any profile role **already exists cluster-wide** — e.g. a DBA created
`mcp_readonly_role` earlier — `CREATEROLE` cannot alter it (PostgreSQL 16+
semantics); run that one step as a superuser:

```sh
ROLES_PG_USER=<superuser> ROLES_PG_PASSWORD=<password> make roles
```

Membership is granted to `EXAMPLE_PG_USER` either way.

## End-to-end runbook

From this directory:

```sh
make install            # uv-managed venv + editable install of django-mcp-sql
make createdb           # creates the example PG database (once)
make migrate            # Django + mcp_sql + notes migrations
                        # (post_migrate provisions both profiles' groups/permissions)
make roles              # creates the per-profile PG roles from MCP_SQL["PROFILES"]
make grants             # each profile role gets SELECT on its whitelist
make bootstrap_demo     # users demo/demo (default) and second/second (second_profile)
make runserver          # serves on http://127.0.0.1:8001/
```

Then register the example as a Claude Code MCP server:

```sh
claude mcp add --transport http mcp-sql-example http://127.0.0.1:8001/mcp/sql/
```

Open `claude` in a new terminal and ask it to use the surface. The first
tool call triggers the OAuth dance — Claude Code opens the browser, you log
in as `demo` / `demo`, the consent screen appears, and Claude Code captures
the auth code on its loopback port. From there, `list_tables` returns the
default profile's whitelist (`auth_permission`, `notes_note`) and
`run_query` reads them.

To see the second tier, log out of the admin, re-run the OAuth dance as
`second` / `second` (`/mcp/sql/` re-authentication happens on the next tool
call after you clear the first user's session or use a fresh browser
profile): `list_tables` now returns only `mcp_note_second_profile`, and the
underlying `notes_note` table is invisible — both at the whitelist layer and
at the Postgres grant layer.

There is no real MFA in the demo: stock Django has no TOTP, and the package
default is fail-closed, so the example wires a permissive `MFA_CHECKER`
(`example.mfa.allow_all`). Production consumers point `MFA_CHECKER` at a
real check (e.g. `allauth.mfa.utils.is_mfa_enabled`).

When done, stop the server (`Ctrl+C`); `make clean` removes the venv.
