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
  port no URL parser takes is foreign, so DOT never sees a value it would
  refuse naming it), and
  `/mcp/sql/` verifies bearers through `audience.CanonicalUriOAuthLibCore`,
  so DOT's (3.4+) audience check sees the URL built the way discovery
  builds `resource`. Build any new OAuth absolute URL with
  `consts.absolute_url`; never verify the bearer with DOT's stock core, and
  keep `MCPTokenView` on DOT's form-body `OAuthLibCore` (a JSON backend
  would parse a `resource` the check never read). Equivalence is per step:
  DOT's token step compares `resource` with the grant's as a string.
- **Per-request `FastMCP` instantiation is deliberate** (tool closures over
  the authenticated user). Tools are `async def`, dispatch ORM work via
  `sync_to_async(..., thread_sensitive=False)`, and every dispatch is
  wrapped in `_close_conns_after` — keep all three properties for any new
  tool.
- **Curated-view migrations** live in the OWNING app, use
  `CREATE OR REPLACE VIEW` forward SQL (column-additive) and carry
  `state_operations=[CreateModel(..., managed=False)]`.
- **A declared client's kind and client_id namespace are DERIVED from its
  redirect scheme** (`clients.derive_kind`): all-https → `cloud`, all-loopback
  → `local`, mixed → boot error. Never let an entry carry both, and never let
  `client_kind` be declared — that is what keeps one client_id from spanning a
  provider-hosted and a machine-local surface, and what makes the audit
  trail's `client_kind` trustworthy.
- **Every `MCP_SQL` key has a default and a declared key replaces its default
  WHOLESALE** — no per-member merge, `extra="forbid"` at every level. Adding a
  key means adding it to `conf.DEFAULTS` *and* `validation.McpSqlSettings`;
  removing one means adding it to `validation._REMOVED_KEYS` so the upgrade
  fails loudly instead of reverting to a default.
- **`clients.py` is settings-free** (takes the prefix as an argument), which
  is what lets `conf.py`, `validation.py`, and `consts.py` all import it
  without a cycle. Redirect *safety* rules live in `validation.py`; `clients.py`
  only classifies.
