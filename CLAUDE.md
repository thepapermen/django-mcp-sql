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
- **Per-request `FastMCP` instantiation is deliberate** (tool closures over
  the authenticated user). Tools are `async def`, dispatch ORM work via
  `sync_to_async(..., thread_sensitive=False)`, and every dispatch is
  wrapped in `_close_conns_after` — keep all three properties for any new
  tool.
- **Curated-view migrations** live in the OWNING app, use
  `CREATE OR REPLACE VIEW` forward SQL (column-additive) and carry
  `state_operations=[CreateModel(..., managed=False)]`; a view that filters
  rows is created `WITH (security_barrier)`.
- **The package's OAuth views use `MCPServerViewMixin`** (narrow
  `oauth_server.MCPServer`, `OAuthLibCore`, core built per call) and
  **`MCPOAuth2Authentication` verifies through `get_mcp_oauthlib_core()`** —
  never DOT's `get_oauthlib_core()` / `super().authenticate()`, which use the
  consumer's `OAUTH2_SERVER_CLASS`. `MCPTokenView.post`'s grant-type guard
  runs before DOT's own handling.
- **The executor sends only `parser.render_for_execution` output**: the
  rendered text (no comments) itself passes the full `parse_and_validate`
  and re-renders (by sqlglot) to the same string — validated as sqlglot
  reads it, not a proof about Postgres's lexer. Never send `ast.sql()` to
  the database directly. Parse and render only with `FaithfulPostgres`
  (rewrites that change results switched off); source forms sqlglot and
  Postgres read differently are refused by the lexical-fidelity check (keep
  that list current). `tests/test_sql_functional_corpus.py` must keep
  passing: ordinary analytics return exactly what Postgres returns.
- **The read transaction is read-only while it runs and always rolled
  back** (`SET LOCAL transaction_read_only = on` in
  `session.enter_readonly_session`; `default_transaction_read_only` alone
  does not cover a transaction that has already begun).
