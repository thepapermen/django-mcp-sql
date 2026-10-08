# mcp_sql — agent guidance

The full architecture, file map, settings shape, OAuth surface, curated-view
pattern, naming map, and the complete "Watch out" list live in
**`docs/architecture.md`** (shipped in the wheel). Read it before touching
anything non-trivial here. Operational runbooks: `docs/role-setup.md` (DB
role + grants) and `docs/oauth.md` (OAuth + MCP transport).

This package is distributed standalone as `django-mcp-sql` (see
`pyproject.toml`, `RELEASING.md`). It must stay consumer-agnostic: no
imports from the surrounding project in production code OR tests; every
consumer-specific value comes from the `MCP_SQL` settings dict. The test
suite runs standalone via `make test` here (settings: `tests/settings.py`).

## Load-bearing invariants (full rationale in docs/architecture.md)

- **Only `SET LOCAL`, never bare `SET`** — transaction-mode pgbouncer would
  leak session GUCs onto reused backends. `session.enter_readonly_session`
  is the single helper; never inline a partial copy.
- **The default DB alias must never serve MCP reads.** The guarantee is the
  executor's `connection.alias == DB_ALIAS` assert, NOT the router (routers
  can't intercept explicit `connections[...]`). The router only blocks
  migrations on the read alias.
- **Parser check ordering is a pinned contract**
  (`test_parser.TestCheckOrdering`) — security reasons fire before ergonomic
  ones so audit rows name the real problem. Reorder with care.
- **`run_query` results are fenced**: `rows` (and `error`) come back as a
  per-response random-UUID `<untrusted-data-…>` string, not a list — the
  prompt-injection boundary. `list_tables`/`describe_table` are not fenced.
- **`MCPOAuth2Authentication` is mounted on `/mcp/sql/` only** — never in
  `REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]`; the view self-declares
  `IsAuthenticated` so stock DRF defaults can't pierce the package.
- **An RFC 8707 `resource` is the advertised identifier or `invalid_target`**
  (`audience.py`): `/o/authorize/` and `/o/token/` accept only
  `audience.mcp_resource_url` with or without its trailing slash, scheme and
  host case-insensitive and the default port optional (both sides through
  `consts.canonical_authority`; the path, query, fragment and userinfo are
  never normalised — the bare origin and other prefixes stay foreign; a
  port the package does not take — two ports or above 65535, which URL
  parsers refuse too, or over five digits, the package's own cap — is
  foreign, so DOT never sees a value it would refuse naming it), and
  `/mcp/sql/` verifies bearers through `audience.CanonicalUriOAuthLibCore`,
  so DOT's (3.4+) audience check sees the URL built the way discovery
  builds `resource`. Build any new OAuth absolute URL with
  `consts.absolute_url`; never verify the bearer with DOT's stock core, and
  keep `MCPTokenView` on DOT's form-body `OAuthLibCore` (a JSON backend
  would parse a `resource` the check never read). Equivalence is per step:
  when the grant carries a `resource`, DOT's token step compares the
  token request's with it as a string.
- **Per-request `FastMCP` instantiation is deliberate** (tool closures over
  the authenticated user). Tools are `async def`, dispatch ORM work via
  `sync_to_async(..., thread_sensitive=False)`, and every dispatch is
  wrapped in `_close_conns_after` — keep all three properties for any new
  tool.
- **Curated-view migrations** live in the OWNING app, use
  `CREATE OR REPLACE VIEW` forward SQL (column-additive) and carry
  `state_operations=[CreateModel(..., managed=False)]`; a view that filters
  rows is created `WITH (security_barrier)`.
- **A declared client's kind and client_id namespace are DERIVED from its
  redirect scheme** (`clients.derive_kind`): all-https → `cloud`, all-loopback
  → `local`, mixed → boot error. Never let an entry carry both, and never let
  `client_kind` be declared — that is what keeps one client_id from spanning a
  provider-hosted and a machine-local surface, and what makes the audit
  trail's `client_kind` trustworthy.
- **A declared client is settings-gated end to end**: recognition AND its
  redirects (`oauth.MCPOAuth2Validator.validate_redirect_uri` /
  `get_default_redirect_uri`) are decided from `MCP_SQL["CLIENTS"]` at every
  request — never from the provisioned row's `redirect_uris` (refreshed only
  by `post_migrate`), so no fall-through to DOT's row-backed `super()`.
  Recognition (`consts.classify_application`) also requires the row's
  `client_id == name`, on every branch; never recognise from the name alone.
- **Every `MCP_SQL` key has a default and a declared key replaces its default
  WHOLESALE** — no per-member merge, `extra="forbid"` at every level. Adding a
  key means adding it to `conf.DEFAULTS` *and* `validation.McpSqlSettings`;
  removing one means adding it to `validation._REMOVED_KEYS` so the upgrade
  fails loudly instead of reverting to a default.
- **`clients.py` is settings-free** (takes the prefix as an argument), which
  is what lets `conf.py`, `validation.py`, and `consts.py` all import it
  without a cycle. Redirect *safety* rules live in `validation.py`; `clients.py`
  only classifies.
- **The package's OAuth views use `MCPServerViewMixin`** (narrow
  `oauth_server.MCPServer`, `OAuthLibCore`, core built per call) and
  **`MCPOAuth2Authentication` verifies through
  `get_mcp_oauthlib_core(CanonicalUriOAuthLibCore)`** — never DOT's
  `get_oauthlib_core()` / `super().authenticate()`, which use the consumer's
  `OAUTH2_SERVER_CLASS`. `MCPTokenView.post` runs its grant-type guard, then
  the control-character screen, then the RFC 8707 `resource` check, all
  before DOT's own handling.
- **The executor sends only `parser.render_for_execution` output**: the
  rendered text (no comments) itself passes the full `parse_and_validate`
  and re-renders (by sqlglot) to the same string — validated as sqlglot
  reads it, not a proof about Postgres's lexer. Never send `ast.sql()` to
  the database directly. Parse and render only with `FaithfulPostgres`
  (renders SQL as written: function calls stay `exp.Anonymous` unless the
  checks need sqlglot's node); source forms sqlglot and
  Postgres read differently are refused by the lexical-fidelity check (keep
  that list current). `tests/test_sql_functional_corpus.py` must keep
  passing: ordinary analytics return exactly what Postgres returns.
- **The read transaction is read-only while it runs and always rolled
  back** (`SET LOCAL transaction_read_only = on` in
  `session.enter_readonly_session`; `default_transaction_read_only` alone
  does not cover a transaction that has already begun).
