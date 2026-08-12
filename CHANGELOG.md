# Changelog

All notable changes to `django-mcp-sql` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

## 0.2.0b1 - 2026-08-11

The multi-client release: declared clients ship ON, Cursor is supported, every
`MCP_SQL` key has a default, and every audit row now names the client that
made the request.

### Breaking

All of these fail loudly at startup — none of them can be missed silently, and
none require any client to reconnect (client_ids are unchanged, provisioning
never deletes rows, and tokens are 6-hour anyway).

- **`MCP_SQL["CLOUD_CLIENTS"]` → `MCP_SQL["CLIENTS"]`**, reshaped from a list
  of entries carrying `NAME` to a **dict keyed by slug**, and from the singular
  `REDIRECT_MATCH` / `REDIRECT_URI` pair to a **`REDIRECTS` list** of
  `{"MATCH": "exact"|"prefix", "URI": ...}` rules (so one provider is one
  client_id even when it calls back from several shapes). Optional `LABEL` sets
  the consent-screen display name. Declaring the old key raises
  `ImproperlyConfigured` naming the replacement — it is not silently ignored,
  because ignoring it would empty `CLIENTS`, de-recognise the consumer's
  declared clients, and start rejecting their live tokens.

  ```python
  # before                                     # after
  "CLOUD_CLIENTS": [                           "CLIENTS": {
      {"NAME": "claude",                           "claude": {
       "REDIRECT_MATCH": "exact",                      "LABEL": "Claude.ai",
       "REDIRECT_URI": "https://…/cb"},                "REDIRECTS": [
  ]                                                        {"MATCH": "exact", "URI": "https://…/cb"}],
                                                   },
                                               }
  ```

- **Unknown `MCP_SQL` keys are now rejected** (`extra="forbid"`, at every
  nesting level). A typo'd key used to be ignored, leaving the default in place
  with nothing in the logs to explain why the setting had no effect.
- **`"https"` in `OAUTH2_PROVIDER["ALLOWED_REDIRECT_URI_SCHEMES"]` is now
  required by default**, because the shipped clients use https callbacks. DOT's
  own default includes it; this only affects a consumer who narrowed the list
  (e.g. to `["http"]`). Add `"https"`, or set `"CLIENTS": {}`.

### Added

- **Every `MCP_SQL` key now has an in-package default** — declare only what you
  change, or omit `MCP_SQL` entirely. One merge rule, applied identically by
  the settings accessor and by `conf.merged_config()`: a declared key replaces
  its default **wholesale**, never member-by-member. In practice a real
  deployment sets two things: each profile's `ALLOWED_MODELS` (default: empty,
  so nothing is readable) and `MFA_CHECKER` (default: denies everyone). Both
  defaults are useless-but-safe on purpose.
- **Declared clients ship ON**: `claude`, `chatgpt`, and `cursor` (its hosted
  web / Cursor Agents surface). They are inert until an operator pastes a
  client_id into the provider's connector AND a user passes the login, MFA,
  profile, and consent gates. `"CLIENTS": {}` runs loopback-only.
- **Cursor support.** The hosted surface rides the shipped `cursor` entry; the
  desktop app and CLI need no configuration, because Cursor performs RFC 7591
  dynamic registration automatically and `/o/register` now accepts their
  request (see below). They therefore get their own `mcp-sql-<token>` identity,
  distinct in the audit trail from the hosted agents. The legacy
  `cursor://` deeplink is deliberately unsupported — admitting a custom scheme
  means widening `ALLOWED_REDIRECT_URI_SCHEMES`, which is install-global.
- **A `local` client kind** for a client that pins a fixed loopback port and
  cannot use DCR (Cursor's static `mcp.json` path). Held to narrower rules than
  an https entry: `localhost` only (never `127.0.0.1` / `::1`, which DOT
  port-wildcards), explicit port, non-root path, `MATCH: "exact"`. Documented,
  not shipped — see `docs/oauth.md` → "Clients".
- **Client attribution on every audit row.** `MCPQueryLog` gains
  `application_name` and `client_kind`; `MCPAuthRejectionLog` gains
  `client_kind` (migration `0013`). `client_kind` is one of `curated` / `dcr` /
  `cloud` / `local` and is **derived, never declared** — for a declared client
  it comes from its redirect scheme, so it cannot drift from what the client
  is. The query-volume tripwire names the client too.
- **`manage.py mcp_sql_clients`** prints each declared client's client_id and
  callbacks — the values to paste into a provider connector, without scrolling
  through `migrate` output.

### Changed

- **A declared client's client_id namespace is derived from its redirect
  scheme**: all-https → `mcp-sql-cloud.<slug>` (unchanged from 0.1.0b5),
  all-loopback → `mcp-sql-local.<slug>`, and an entry mixing the two refuses to
  boot. One client_id must never span a provider-hosted and a machine-local
  surface, or `client_kind` on an audit row would be a guess.
- **`/o/register` registers the loopback SUBSET** of a request's
  `redirect_uris` and echoes back what it registered (RFC 7591 §3.2.1), instead
  of refusing any request containing a non-loopback URI. This is what lets
  Cursor register at all — it may present a hosted https callback and the
  `cursor://` deeplink alongside its loopback one. Nothing non-loopback is ever
  stored, an empty subset is still a refusal, duplicates collapse, and the list
  is capped at 10. The declared (unverified) `client_name` is now logged at INFO
  beside the minted client_id; it is still never persisted.
- **The consent screen now says who is asking and where the code will go.** It
  showed "Authorize MCP SQL?" for every client — naming the resource, never the
  requester or the destination — which left nothing to check on the screen that
  exists to break phished authorization links. It now shows the declared
  client's operator-authored `LABEL` and, for every client, the destination
  (`scheme://host[:port]`, rebuilt from the validated `redirect_uri`'s parsed
  parts so a userinfo component cannot render). A self-registered client gets
  no label: its `client_name` is attacker-chosen free text.
- Provisioning now names orphaned declared-client `Application` rows in a
  WARNING. It still never deletes them — that would cascade live tokens in the
  middle of a `migrate`.

### Fixed

- **`validate_redirect_uri` rejected the exact callbacks of any client that
  also had a prefix rule.** It returned the prefix verdict instead of falling
  through to DOT's stock exact matching. Unreachable in 0.1.0b5 (one rule per
  entry); reachable the moment a client carries both.
- **Over-long `redirect_uris` silently discarded audit rows.** Both writers
  passed the Application's registered list straight into a 1024-char column; an
  overflow raised `DataError`, which the best-effort audit wrappers swallow —
  losing the row entirely. It is now truncated at the single point where the
  client identity is built.
- `MCPQueryLog.client_redirect` was documented as the redirect the token "was
  issued against … the auth url cannot lie". It is the Application's
  **registered** `redirect_uris` — DOT does not persist which redirect a given
  authorization used. Read it as "one of these". The docstring now says so.

## 0.1.0b5 - 2026-07-01

### Added

- **Opt-in cloud MCP clients** (`MCP_SQL["CLOUD_CLIENTS"]`, empty default =
  feature off / loopback-only). Admits operator-blessed cloud-brokered clients
  (Claude.ai web/desktop/mobile/Cowork, ChatGPT/Codex-cloud) that authenticate
  against a provider-hosted HTTPS callback and vault the token in the provider's
  cloud — **without** relaxing the loopback-only `/o/register` (DCR) endpoint.
  - Each entry yields a derived, stable `client_id` (`mcp-sql-cloud.<name>`,
    logged at `migrate`) to paste into the provider's connector, secret left
    blank. Recognition is settings-gated and fail-closed: removing an entry
    denies its outstanding tokens at the next `/o/authorize/` and `/mcp/sql/`
    request.
  - Provisioning is a `post_migrate` receiver (`provision_mcp_cloud_clients`,
    mirroring `provision_mcp_profiles`): one curated `Application` per entry
    (public/PKCE, no secret, `skip_authorization=False`), create/update only,
    never deleting.
  - Redirect matching is per-entry `"exact"` (Claude — DOT stock matching) or
    `"prefix"` (ChatGPT's per-instance callback — one hardened override:
    https-only, exact host, port-normalised, no userinfo, no traversal,
    segment-anchored prefix).
  - New `client_redirect` audit column on `MCPQueryLog` /
    `MCPAuthRejectionLog` (migration `0012`) records the **issued** redirect URI
    (ground truth), so cloud-client activity stays attributable in the logs.
  - No refresh tokens: the 6-hour re-consent applies to cloud clients too.
  - Operator runbook: `docs/oauth.md` "Cloud clients".

### Changed

- A non-empty `MCP_SQL["CLOUD_CLIENTS"]` now requires `"https"` in
  `OAUTH2_PROVIDER["ALLOWED_REDIRECT_URI_SCHEMES"]`; the app raises
  `ImproperlyConfigured` at startup otherwise (cloud callbacks are https). DOT's
  default already allows https, so this only affects a consumer who narrowed the
  list (e.g. to `["http"]` for loopback DCR). Empty `CLOUD_CLIENTS` (the
  default) is unaffected.
- The MCP transport endpoint is now routed at **both** `/mcp/sql/` (canonical —
  what `reverse()` and the RFC 9728 `resource` advertise) and a slash-less
  `/mcp/sql` alias, so a cloud connector that normalises the trailing slash off
  and POSTs to `/mcp/sql` is served rather than triggering an `APPEND_SLASH`
  500.

## 0.1.0b4 - 2026-06-15

Documentation-only release (no code changes).

### Fixed

- README "Installation" `MCP_SQL` block used the pre-`PROFILES` flat
  `ALLOWED_MODELS` shape, which fails startup validation
  (`ImproperlyConfigured`). It now uses the required `PROFILES` shape. A new
  test (`tests/test_docs_config.py`) runs every paste-ready `MCP_SQL` block in
  the docs through `validate_mcp_sql_settings`, so the install snippet can't
  drift from the validator again.
- The OAuth and role-setup runbooks described the pre-`PROFILES`
  authorization model (`has_perm("mcp_sql.use_mcp_session")`, flat
  `ALLOWED_MODELS`); they now match the code's `resolve_profile` /
  per-profile-whitelist behaviour, with corrected auth-error strings and
  logout token-scope. MFA (`MFA_CHECKER`) and the runtime session-existence
  gate (`SESSION_MODEL`) are now documented as opt-in rather than default.

### Added

- README "How it compares" section positioning the package against hosted
  natural-language→SQL services and reference/platform MCP servers, plus a
  one-line summary callout near the top.

### Changed

- Removed internal build-phase ("Phase N") references from the shipped docs;
  added a "Roadmap / known gaps" section instead. Reorganized the
  architecture doc (curated-view pattern ahead of the OAuth surface; the
  "Watch out" invariants grouped under per-layer subheadings with a mini-TOC).

## 0.1.0b3 - 2026-06-12

### Added

- `Documentation` entry in `[project.urls]` (pointing at the repo's `docs/`
  tree). Django Packages reads a package's documentation link from PyPI
  `project_urls` (keys `Documentation`/`Docs`/`docs`/`documentation`); without
  this key the grid listing showed no documentation despite the docs shipping
  in the wheel.

## 0.1.0b2 - unreleased

### Added

- The MCP tools now advertise output schemas: `run_query` and
  `describe_table` declare `TypedDict` return types (`FencedQueryResult`,
  `TableDescription | ToolError`), which the MCP SDK turns into each tool's
  output schema — so a connecting client sees the result shape, including
  that `run_query`'s `rows` is a fenced JSON string rather than a row matrix.
- A stricter type-check gate: the high-signal subset of mypy strict
  (`warn_unused_ignores`, `warn_redundant_casts`, `warn_return_any`,
  `disallow_any_generics`, `disallow_incomplete_defs`) is now enabled, with
  the package annotated to satisfy it (full `disallow_untyped_defs` stays
  off). A consumer's type checker now reads more precise inline types — e.g.
  `QueryResult.rows` is `list[list[Cell]]`, the cursor surface is a
  `SQLCursor` protocol, and audit kwargs are a `TypedDict` — instead of
  `object`/`Any`.

### Changed

- New runtime dependency `typing-extensions>=4.12` (already present
  transitively via pydantic): the MCP tool-output `TypedDict`s must be the
  `typing_extensions` variant for pydantic to build their schemas on
  Python < 3.12.

## 0.1.0b1 - unreleased

### Added

- Django 4.2 LTS and Django 6.0 support, alongside the existing 5.2 LTS line
  (`Framework :: Django` 4.2/5.2/6.0). No source changes were needed — the
  package uses no Django-version-specific APIs.
- CI expanded to a ragged Django × Python matrix (4.2, 5.2, 6.0 against their
  respective supported interpreters), plus a pinned leg verifying the package
  on DRF 3.14 + Django 4.2 — i.e. drop-in into an app that already pins an
  older DRF.
- `py.typed` marker (PEP 561): the package now ships its inline type
  annotations, so a consumer's type checker reads `mcp_sql`'s types instead
  of treating it as untyped. A `typecheck` extra (`mypy` + `django-stubs` +
  `djangorestframework-stubs`), a `[tool.mypy]` config, a `make typecheck`
  target, and a CI `typecheck` job keep those annotations honest (the public
  surface is annotated; untyped-def bodies are still checked).

### Changed

- Promoted from alpha to **Beta** (`Development Status :: 4 - Beta`).
- Dependency floor `django>=4.2,<6.1` (was `>=5.2,<6.0`).
- Dependency floor `djangorestframework>=3.14` (was `>=3.15.2`): 3.14 is the
  lowest DRF supported — what a legacy Django 4.2 app already pins — so the
  package drops into such a stack without forcing a DRF upgrade. Support is a
  staircase (5.x needs DRF ≥3.15, 6.0 needs ≥3.17); a greenfield install
  resolves the newest in-range DRF for whatever Django it runs.

## 0.1.0a1 - unreleased

First alpha. The feature set below has been exercised in production as part
of a larger Django CRM; the standalone distribution itself is pre-release.

### Added

- Three MCP tools over Streamable HTTP at `/mcp/sql/`: `list_tables`,
  `describe_table`, `run_query` (single validated SELECT).
- sqlglot-backed AST parser gate: single SELECT-shaped statement, scope-aware
  table whitelist, system-schema and function deny-lists, no
  `SELECT *` (configurable), no writeable CTEs, no OFFSET/FETCH/locking
  reads, no set-returning functions in the projection.
- Read-only executor: dedicated `mcp_readonly` Django DB alias,
  `SET LOCAL ROLE` into a Postgres NOLOGIN role with statement-level guard
  GUCs, most-restrictive-wins row caps with LIMIT N+1 truncation detection,
  per-cell and total byte caps.
- Append-only audit: one `MCPQueryLog` row per `run_query` call (every code
  path) and one `MCPAuthRejectionLog` row per resolved-user auth rejection;
  read-only Django admin browsers plus a per-user usage-summary view.
- OAuth 2.1 surface via django-oauth-toolkit: authorization-code + PKCE
  (S256 only), public client, 6h tokens, no refresh tokens; RFC 7591
  dynamic client registration (loopback-only redirect URIs), RFC 8414 +
  RFC 9728 discovery documents; issuance gate and per-request re-validation
  (active staff + MFA + unambiguous profile + optional session-existence
  check); logout revokes tokens.
- Multi-profile access tiers: N profiles in `MCP_SQL["PROFILES"]`, each its
  own Postgres role, whitelist, Django permission and group;
  explicit-assignment binding (superuser confers nothing); config-derived
  group/permission provisioning via post_migrate; dormant per-profile
  `SESSION_CONTEXT` hook for per-user row scoping recipes.
- Prompt-injection fencing: `run_query` rows/error wrapped in a per-response
  random-UUID `<untrusted-data-…>` fence with a `data_handling` instruction;
  standing security posture delivered via MCP `initialize` instructions.
- Grants tooling: `mcp_sql_grants` (drift check / `--apply`),
  `mcp_sql_role_setup --emit-sql` (N-role bootstrap SQL),
  `mcp_sql_smoke` (session-contract + end-to-end executor smoke),
  `mcp_sql_lint` (column-add review gate); idempotent
  `sql/role_setup.sql` + Docker init wrapper.
- Observability: per-user query-volume tripwires (alert, never block),
  group-add alerts, silent per-IP throttle on bad-token probing and
  anonymous registration.
- Standalone test suite (`tests/settings.py`, stock Django + Postgres) and
  GitHub Actions CI (Python 3.11–3.13 × PostgreSQL 14).
