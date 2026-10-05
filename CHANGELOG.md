# Changelog

All notable changes to `django-mcp-sql` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

### Security

- **`/o/register` could register an off-machine redirect URI (affects
  0.1.0b5 and earlier).** The anonymous dynamic-client-registration endpoint
  validated each submitted redirect URI with `urlparse` (scheme `http`, no
  userinfo, loopback host) but stored the list as one space-joined string,
  which django-oauth-toolkit splits again on any `str.split()` whitespace
  when matching. A single submitted URI with embedded whitespace (space, tab,
  CR/LF, or a less obvious separator such as NBSP or U+2028) therefore passed
  the loopback check yet was stored as two or more redirects, one of which
  could name any host. An attacker could mint such a client without
  credentials; turning it into a stolen token still required a logged-in
  user who passes the issuance gate (staff + MFA + MCP profile) to approve
  the attacker's authorization link on the consent screen, after which the
  code went to the attacker's host and was exchangeable with the attacker's
  own PKCE verifier.
  - Registration now refuses any URI that `str.split()` would break apart
    (deliberately DOT's own operation), any non-printable or non-ASCII
    character, any URI whose authority or port does not parse, and an empty
    userinfo (`@` with nothing before it, which the old non-empty-userinfo
    check let through) — each a normal 400 `invalid_redirect_uri` with no
    `Application` row created.
    Previously a malformed authority (e.g. an unterminated IPv6 literal), a
    NUL or a lone surrogate raised an uncaught 500, and a non-numeric or
    out-of-range port was stored, leaving a client that could never complete
    a flow (and, for some such URIs, an uncaught 500 at `/o/authorize/`).
  - Other malformed registration input that raised an uncaught 500 is now a
    400 `invalid_client_metadata` with no row: `grant_types` /
    `response_types` that are not JSON arrays of strings (null or a number
    raised; a plain string was substring-matched and accepted), and a body
    that is not valid UTF-8 or is pathologically nested. A client asking
    for `["authorization_code", "refresh_token"]` is still registered.
  - Rows already registered by an affected release are not deleted.
    `MCPOAuth2Validator` now re-applies the same loopback check at
    `/o/authorize/` to the requested redirect, and to the stored default
    used when a request omits one, of every client that is not a declared
    cloud client. A smuggled entry is therefore refused after upgrading (the
    row's loopback entries keep working). A stored `localhost` URI with an
    unparseable port no longer makes `/o/authorize/` raise a 500: requests
    against that row are refused. For a stored `127.0.0.1` / `[::1]` URI with
    such a port, DOT never reads the stored port (it port-wildcards loopback
    IPs), so a request for a valid port on the same path is still authorized
    — the destination stays on the loopback. `docs/oauth.md` has a shell
    snippet that lists such rows for review and deletion.
  - Behaviour change for the canonical `mcp-sql` row as well: a
    non-loopback redirect, requested or stored, is now refused for it too,
    even if an operator edited its `redirect_uris` (the documented posture
    was already loopback-only).
- **Refresh tokens renewed access indefinitely (affects 0.1.0b5 and
  earlier).** The docs said refresh tokens were disabled by
  `REFRESH_TOKEN_EXPIRE_SECONDS=0`, but django-oauth-toolkit reads `0` as
  "no age limit": `/o/token/` issued a `refresh_token` alongside every
  access token and honoured it on `grant_type=refresh_token` (verified on
  DOT 3.2.0 and 3.4.1). A client could therefore keep renewing its access
  token without the user ever re-consenting.
  `MCPOAuth2Validator.validate_refresh_token` now refuses every refresh
  grant with `invalid_grant`, including refresh tokens already stored, and
  `save_bearer_token` no longer mints them: the `/o/token/` response has no
  `refresh_token` field and no `RefreshToken` row is created. Existing
  `RefreshToken` rows are left in place and are inert.
  - **Behaviour change:** a client that relied on refresh now re-authorizes
    every `ACCESS_TOKEN_EXPIRE_SECONDS` (6 h in the documented settings),
    with the consent screen for DCR and cloud clients — the interval the
    docs always described.
- **PKCE was not S256-only, and could be switched off (affects 0.1.0b5 and
  earlier).** The validator's S256-only check
  (`validate_code_challenge_method`) is not a hook oauthlib or DOT ever
  calls, so `/o/authorize/` accepted `code_challenge_method=plain`, and an
  omitted method (which oauthlib treats as `plain`), although the discovery
  document advertises `S256` only. With `plain` the challenge in the
  authorization URL is the verifier itself, so anyone who observes that
  request can redeem an intercepted code. A consumer's
  `PKCE_REQUIRED=False` also turned PKCE off altogether.
  `MCPOAuth2Validator.is_pkce_required` now requires PKCE on every
  authorization regardless of `PKCE_REQUIRED` and refuses any method but
  `S256` with `invalid_request` — redirected, like any non-fatal authorize
  error, to the already-validated redirect URI — on the authorize GET and
  on the consent POST. `get_code_challenge_method` refuses to exchange a
  stored non-S256 grant (`invalid_grant`). The dead override is removed.
  - **Behaviour change:** a client that sends `plain`, or no
    `code_challenge_method`, is now refused at `/o/authorize/`.
- Both policies are install-wide: the validator is the DOT install's
  `OAUTH2_VALIDATOR_CLASS` (which already refuses any scope but `mcp:sql`),
  so they apply to every client of that install.
- **`/mcp/sql/` accepted a bearer token in the URL query string (affects
  every release up to and including 0.1.0b5).** oauthlib, and so DOT, falls
  back to an `access_token` request parameter when there is no
  `Authorization` header, so `/mcp/sql/?access_token=<token>` authenticated
  like the header (verified on DOT 3.2.0, 3.4.0 and 3.4.1), and a form-body
  token passed authentication too — although the RFC 9728 metadata
  advertised `bearer_methods_supported: ["header"]`. A token in a URL ends up
  in proxy and access logs and in `Referer` headers. RFC 6750 §2.3 and §5.3
  advise against sending bearer tokens in URLs, OAuth 2.1 (the draft the MCP
  specification builds on) drops the query-parameter method entirely, and
  the MCP authorization specification requires clients to use the
  `Authorization` header and says access tokens MUST NOT be included in the
  URI query string.
  `MCPOAuth2Authentication` now refuses any request to `/mcp/sql/` (with or
  without the trailing slash) that carries an `access_token` query parameter
  or a form-body `access_token` — even alongside a valid header — with 400
  `invalid_request` (RFC 6750 §3.1) and the usual `WWW-Authenticate`
  challenge, now including `error="invalid_request"`. The check runs before
  any token lookup, so a URL token is never validated. Nothing is written
  to `MCPAuthRejectionLog` and the bad-token throttle is not counted (it is
  malformed transport, like the 413 body cap).
  - **Behaviour change:** a client sending its token anywhere but the
    `Authorization` header is now refused.
- **Raised the `django-oauth-toolkit` floor to `>=3.4.1` (was `>=3.2`)**,
  for two upstream fixes that sit below any of this package's checks:
  - Releases before 3.4.0 redirect an unauthenticated `prompt=none`
    authorization request to whatever `redirect_uri` it names, with an
    `error=login_required` but never a code, before any validation (DOT
    #1719). Now that request is validated first, like any other: an
    unregistered `redirect_uri` gets an error page instead of a redirect,
    while a registered one (a loopback URI, or a declared cloud client's
    `https` callback) still receives the specified `error=login_required`,
    never a code. A new test pins this for the canonical client.
  - Releases before 3.4.1 match redirect URIs loosely. Against a
    registered `https://claude.ai/api/mcp/auth_callback`, DOT 3.4.0's
    matcher accepts the same host with userinfo, extra query parameters, a
    fragment or `;params` added. oauthlib's own absolute-URI check stops the
    userinfo and fragment forms first, but the extra-query and `;params`
    forms reached the consent page end to end (verified on 3.4.0), so an
    authorization code could be delivered to the registered host with
    attacker-chosen parameters. 3.4.1 matches exactly, per RFC 9700 §2.1.
    This is the matcher behind declared "exact" cloud clients; a new test
    pins all four forms being refused at `/o/authorize/` for one.
  - **Action required** for a consumer pinning django-oauth-toolkit below
    3.4.1 (e.g. `==3.2.0`): bump it. 3.4.1 still supports Django 4.2 and
    requires `oauthlib>=3.3.0` (unchanged from 3.2.0). Django 4.2 remains
    supported; CI's minimum-versions job now pins
    `django-oauth-toolkit==3.4.1`.

### Changed

- Raised the `mcp` floor to `>=1.28.1` (was `>=1.27`), so the declared range
  no longer admits releases carrying CVE-2026-52869, CVE-2026-52870 (both
  fixed in 1.27.2) or CVE-2026-59950 (fixed in 1.28.1). The package was not
  exposed to these: it serves Streamable HTTP with `stateless_http=True`,
  never enables the SDK's experimental tasks, and has no WebSocket
  transport. CI's minimum-versions job now pins `mcp==1.28.1`.

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
