# django-mcp-sql architecture — MCP read-only SQL surface for an LLM agent

A tightly scoped, read-only SQL endpoint exposed to a remote LLM agent
(Claude Code as the MCP client) over MCP Streamable HTTP. Defense-in-depth
at parser, executor, DB-role, and transport layers.

This is a standalone Django app (import name `mcp_sql`, distribution name
`django-mcp-sql`), not tied to any particular domain model. Every
consumer-specific value, override, and deployment context lives in the
consumer's settings and its own integration notes, **not** here.

Operational runbooks: `docs/role-setup.md` (DB role + grants) and
`docs/oauth.md` (OAuth + MCP transport).

## Architecture

- **Transport**: MCP Streamable HTTP via the official Anthropic `mcp` Python
  SDK (`FastMCP`), mounted at `/mcp/sql/` behind a custom DOT-backed
  bearer-token authenticator. The SDK ships an ASGI app; we bridge it into
  Django's WSGI worker via `a2wsgi.ASGIMiddleware` so the existing Gunicorn
  pool serves it. CSRF excluded; CORS default-deny.
- **Auth**: `django-oauth-toolkit` provides the OAuth 2.1 surface. Single
  Application named `mcp-sql`, single scope `mcp:sql`, `authorization_code` +
  PKCE only. The curated Application's redirect URI is `http://127.0.0.1`
  per RFC 8252 §7.3 (DOT 3.x port-wildcards any port on the loopback IP
  `127.0.0.1`; bare `localhost` can't be port-wildcarded so the curated app
  omits it — but the DCR endpoint DOES accept `localhost` via exact-match,
  see "OAuth surface"). 6h hard cap on tokens, refresh tokens
  disabled (cosmetic field still emitted by DOT, zero lifetime). Audience
  binding is implicit: DOT 3.2.0 + oauthlib 3.3.1 don't natively support
  RFC 8707, so the binding is achieved via the single `mcp:sql` scope plus
  the auth class being mounted only on `/mcp/sql/` (no explicit `aud`
  claim — revisit when DOT releases first-class RFC 8707 support). See
  `docs/oauth.md` for the operational profile.
- **Authorization**: layered — issuance gate at `/o/authorize/` (Option D
  session-trust: `is_active AND is_staff AND is_mfa_enabled AND an
  unambiguous single-profile assignment (resolve_profile)`, no fresh-TOTP
  timestamp check — the consumer's `SESSION_COOKIE_AGE` forces re-MFA at the
  boundary naturally), per-request token validation re-running the same gate
  inside `MCPOAuth2Authentication.authenticate` **plus a session-existence
  check** (the user must still hold at least one live Django session;
  see "Watch out" for the runtime half of the session-trust gate), AST table whitelist check,
  Postgres role grants (the actual access boundary), statement-level GUCs.
- **Connection isolation**: dedicated `mcp_readonly` DB alias, `ATOMIC_REQUESTS=False`,
  `CONN_MAX_AGE=0`, small pool (~4). Default alias has `ATOMIC_REQUESTS=True`
  so it must NEVER be used by the executor.

## File map

| Path | Purpose |
|---|---|
| `sql/role_setup.sql` | Idempotent SQL to create `mcp_readonly_role` + role-level GUC defaults + the membership GRANT. The app role name is supplied via the psql variable `app_role` (`-v app_role=<role>`); the GRANT lives inside a `DO $$ ... $$` block (so psql variable substitution does not reach it directly), so the script wraps the GRANT in an explicit `BEGIN ... COMMIT` and uses `SET LOCAL mcp_sql.app_role = :'app_role'` (psql substitutes the variable at the call site, and the DO block reads the value via `current_setting(...)` + `EXECUTE format('GRANT mcp_readonly_role TO %I', target_role)`). `SET LOCAL` (not bare `SET`) keeps the library-wide invariant — no session-scope SET in mcp_sql code, even on bootstrap paths that don't traverse pgbouncer today. Portable across environments whose `POSTGRES_USER` differs (the caller passes the matching value via `-v app_role=<role>`). |
| `sql/10_mcp_role.sh` | Init-dir wrapper for fresh dev clusters. Mounted at `/docker-entrypoint-initdb.d/10_mcp_role.sh`; the Postgres image entrypoint runs it once after `POSTGRES_USER` is created. It `exec`s psql with `-v app_role="$POSTGRES_USER"` against `role_setup.sql` (mounted at `/mcp_sql/role_setup.sql`, deliberately OUTSIDE the init dir so the entrypoint does not also auto-run the SQL without the variable substitution). For long-lived deployments the DBA applies the SQL manually with the matching `-v app_role=<role>` value (see `docs/role-setup.md`). |
| `session.py` | Single source of truth for the `SET LOCAL ROLE` + `SET LOCAL` GUC sequence every read transaction must issue. The executor and the smoke command both call `enter_readonly_session(cursor, role=..., session_context=...)` from here. |
| `db_router.py` | One universal invariant, nothing else: `allow_migrate` returns `False` for `MCP_SQL["DB_ALIAS"]` so **no** app ever builds or tracks schema through the read-only execution alias — it is a lens onto a database `default` owns (or a read replica), which Django can't infer and would otherwise migrate per-alias (a `migrate --database=<alias>`, or the test runner's per-alias setup). Abstains (`None`) on every other decision: audit writes/reads land on `default` via Django's fallback (no explicit pin needed), and the executor reaches the read alias via an explicit `connections[DB_ALIAS]` that routers don't intercept. Deliberately bakes in **no** consumer-topology assumption (no literal `"default"` home for `mcp_sql`'s own tables — a multi-DB consumer manages that with their own routers). Keyed on the `DB_ALIAS` setting, so it holds whether the alias is the same DB via a read-only role or a separate replica. |
| `models.py` | Two audit tables. `MCPQueryLog` — every `executor.run_query` call (parser-reject / executor-misconfig / timeout / execution-error / `limit=0` short-circuit / success). `MCPAuthRejectionLog` — every `MCPOAuth2Authentication.authenticate` rejection (bad-token / bad-application / bad-scope / inactive-or-non-staff / no-MFA / no-perm / no-session). Separate tables by design: auth rejections happen before query evaluation, conflating them in `MCPQueryLog` would pollute the daily-volume "queries per user" aggregation with bot-probe rejection counts. The planned revoked-credential probing alert reads `MCPAuthRejectionLog`. Both tables append-only by convention; admin has no write paths; both have `REVOKE SELECT ... FROM mcp_readonly_role` (migrations 0002 + 0008). |
| `management/commands/mcp_sql_grants.py` | The single grants-pipeline command. Default mode is read-only: prints the drift diff and exits non-zero if any profile role's grants don't match its `MCP_SQL["PROFILES"][...]["ALLOWED_MODELS"]` whitelist (pre-deploy gate). With `--apply`, executes GRANT / REVOKE — intended as the deploy-pipeline step right after `migrate`, and also runnable against an ephemeral CI test cluster to fail PRs that add a model to a profile's `ALLOWED_MODELS` without the migration that creates its table. Strict in both modes: raises if the role is missing, the app role lacks membership, OR any curated MCPxxx view's column list drifts from its unmanaged-model declaration (verified inside `reconcile_grants` via `_verify_view_parity` so the same gate runs on the deploy command + the post_migrate signal). The `post_migrate` signal (see `signals.py`) only DETECTS drift and logs a WARNING; this command is the only code path that mutates. |
| `management/commands/mcp_sql_lint.py` | Walks `git diff <base>...HEAD`, fails on column-add migrations targeting whitelisted models without `# MCP-OK: <reason>` annotation. |
| `management/commands/mcp_sql_smoke.py` | Smoke check, two modes. Default: role/grants contract — opens `mcp_readonly`, enters the read-only session, verifies guard GUCs, asserts the audit table is unreadable, asserts a write is rejected. `--run-query "<sql>"`: drives the executor end-to-end (parser → LIMIT N+1 → readonly tx → row caps → audit). |
| `schemas.py` | `QueryResult` dataclass + `OutcomeReason` short-code vocabulary + `HINTS` map (agent-facing text per reason + truncation hint). Reused by the MCP transport layer. |
| `fencing.py` | `fence_query_result(payload)` — wraps `run_query`'s untrusted, DB-sourced fields (`rows`, and `error` when set) in a per-response random-UUID `<untrusted-data-…>` XML fence plus a `data_handling` instruction, so injected DB content (email subjects, contact names, comments, …) can't forge the boundary and be read as agent instructions. Pure-Python / Django-free (travels with the package); called from the `run_query` tool closure in `views/mcp_endpoint.py`. |
| `parser.py` | `parse_and_validate(raw_sql, *, allowed_tables, ban_select_star=True) -> ParsedQuery` and `inject_limit(ast, n) -> Expression`. sqlglot-backed AST validators: single statement (trailing `;` and comments are stripped), SELECT-shaped root, no `SELECT *`, no writeable CTE, no SELECT INTO/RETURNING, no OFFSET / FETCH / FOR UPDATE / FOR SHARE, no set-returning / table functions in the projection (`generate_series` / `unnest` via the `exp.GenerateSeries` / `exp.UDTF` base classes, the json/regexp expanders via the `DENIED_SRF_FUNCTIONS` name set — both escape the empty-name FROM-Table guard; not exhaustive of every PG SRF, the `statement_timeout` + LIMIT backstop covers anything unlisted), scope-aware table whitelist (a CTE name only masks a table reference when that CTE is **in scope** for it — `_resolves_to_cte`; a flat global CTE-name set let an inner CTE shadow an outer-scope real table), system-schema reject (`pg_*` / `information_schema`), function deny-list (exact: `copy`, `current_setting`, `set_config`; prefix: `dblink_*`, `lo_*`, `pg_*`, `has_*`). Raises `QueryRejectedError(reason, detail)`. |
| `executor.py` | `run_query(*, user, raw_sql, limit=None, token_id="", client_ip=None) -> QueryResult`. Pipeline: parse → extract user's SQL `LIMIT N` → resolve effective cap as `min(kwarg, sql_LIMIT, HARD_LIMIT)` defaulting to `DEFAULT_LIMIT` (`limit=0` short-circuits without touching DB) → inject `LIMIT N+1` → open `mcp_readonly` tx → `enter_readonly_session` → execute → per-cell + total byte caps → write one `MCPQueryLog` row → return. Every code path (parser reject, executor error, timeout, success, `limit=0` short-circuit, `ExecutorMisconfiguredError`) writes exactly one audit row. The audit row carries `raw_sql`, `normalized_sql`, `wrapped_sql`, `row_count`, `result_bytes`, `duration_ms`, `decision`, and `rejection_reason` — never the actual row contents (privacy / retention concern on a CRM with shipper PII). |
| `observability.py` | `record_query_volume(*, user_id, decision, user_label="")` — per-(user, decision, window) fixed-window cache counters (mirrors `throttle`'s `cache.add`+`incr` primitive), called from `executor._audit_safely` on every audited row. Emits ONE `logger.error` (Sentry event) at each crossing of `MCP_SQL["VOLUME_ALERT_THRESHOLDS"][decision][window]` (hour + day, allowed + rejected). ALERTS, never blocks; fail-open on cache trouble. The alert names the user (pk + `get_username()`); it never logs SQL. |
| `oauth.py` | `MCPOAuth2Validator` — rejects any client_id that isn't the `mcp-sql` Application and any scope set that isn't `{"mcp:sql"}`. |
| `auth.py` | `MCPOAuth2Authentication` — DRF auth class subclassing DOT's `OAuth2Authentication` with per-request re-validation of `is_active`, `is_staff`, `is_mfa_enabled`, and an unambiguous single-profile assignment via `resolve_profile` (binds `request.mcp_profile`; a revoked assignment, ambiguity, or removed MFA device invalidates outstanding tokens immediately, without waiting for the 6h hard cap). The view layers `@permission_classes([IsAuthenticated])` on top of this so the package's "you must be authenticated" contract is self-contained — anonymous fall-through is rejected by the view's own decorator, never by the consumer's `REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"]` (stock DRF defaults to `AllowAny`, which would silently let probes reach the bridge and break OAuth bootstrap). **Mounted only on `/mcp/sql/`**; never added to `REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]`. |
| `views/oauth_authorize.py` | `MCPAuthorizationView` — subclasses DOT's `AuthorizationView` and runs the issuance gate (`is_active + is_staff + is_mfa_enabled` + an unambiguous single-profile binding via `resolve_profile`, denying `NO_PERM` / `AMBIGUOUS_PROFILE`) before delegating to upstream `dispatch`. Failed gates raise `PermissionDenied` (HTTP 403); unauthenticated requests fall through to DOT's `LoginRequiredMixin` (redirect to login). Renders a **package-owned** consent template, `template_name = "mcp_sql/authorize.html"` (uniquely named so it is never shadowed by DOT's bundled `oauth2_provider/authorize.html` regardless of `INSTALLED_APPS` order, and so a consumer can re-theme it by overriding `mcp_sql/authorize.html` in their own template dir). `render_to_response` injects `resource_name = RESOURCE_NAME` so the consent page shows the configured server name (the same identity in the RFC 9728 metadata) instead of DOT's opaque per-client `application.name` (`mcp-sql-<token>` for every DCR client). `render_to_response` is the single chokepoint for the view's only two template renders — the consent page (`get`) and the fatal-client-error page (`error_response` when oauthlib refuses to redirect: unknown `client_id` / untrusted `redirect_uri`); recoverable OAuth errors 302 back to the client, success 302s with the code, and the gate's `PermissionDenied` renders the consumer's `403.html` — none of those go through here. The error branch ignores `resource_name`; `setdefault` leaves a preset value untouched. |
| `views/mcp_endpoint.py` | `/mcp/sql/` view. Per-request `FastMCP` instantiation with three tool callables (`list_tables`, `describe_table`, `run_query`) closed over the authenticated `user`/`token_id`/`client_ip`. Mounted via `a2wsgi.ASGIMiddleware`; the DRF auth class decorator runs first, so anonymous / wrong-scope requests are rejected before the bridge runs. CSRF exempt (bearer auth, not cookies). The `FastMCP` carries `instructions=_SERVER_INSTRUCTIONS` (the standing untrusted-data + human-in-the-loop security posture, delivered once in the `initialize` response — see "Watch out") and each tool carries honest `readOnlyHint=True` / `openWorldHint=False` `ToolAnnotations`. **Routed (`urls.py`) at BOTH `/mcp/sql/` (canonical — named, what `reverse()` + the RFC 9728 `resource` advertise) and the slash-less alias `/mcp/sql`**: Claude.ai's web connector normalises the trailing slash off and POSTs to `/mcp/sql`, and `APPEND_SLASH` can't 301-redirect a POST without dropping the body, so a slash-only route 500s the instant the transport opens (`docs/oauth.md` → "Cloud clients" → Troubleshooting; pinned by `test_mcp_endpoint.py::TestEndpointRouting`). |
| `views/discovery.py` | OAuth 2.0 discovery surface. `protected_resource_metadata` (RFC 9728) at `/.well-known/oauth-protected-resource/mcp/sql` advertises the MCP endpoint's `resource`, the env's `resource_name` (sourced from `MCP_SQL["RESOURCE_NAME"]`; consuming projects typically override this to an env-distinct value), and the AS URL. `authorization_server_metadata` (RFC 8414) at `/.well-known/oauth-authorization-server/o` (path-suffix per RFC 8414 §3.1, matching the `https://<host>/o` issuer) advertises `issuer`, the three OAuth endpoints, the `registration_endpoint`, scopes, grant types, `code_challenge_methods_supported=["S256"]`, and `token_endpoint_auth_methods_supported=["none"]` (public client). Both anonymous-GET, CSRF-exempt. Referenced by `MCPOAuth2Authentication.authenticate_header()` via the `resource_metadata` parameter in `WWW-Authenticate` so MCP clients can bootstrap the OAuth dance off a 401. |
| `throttle.py` | Shared per-IP fixed-window block backed by the Django cache (use a SHARED backend — Redis, Memcached — in production: with a per-process backend like LocMem the counters, and therefore the block, are per-worker). One primitive, two surfaces: `auth` (`bad_token` scope, silent 401) and `views/registration` (`register` scope, silent inert 201). Both share `MCP_SQL["BAD_TOKEN_IP_THRESHOLD"]` / `["BAD_TOKEN_IP_WINDOW_SECONDS"]`; keys are scope-namespaced so one surface never depletes the other's budget. Keys on `REMOTE_ADDR` — sound only behind a hardened edge proxy (see "Watch out: the per-IP throttle trusts the proxy's IP handling"). |
| `decorators.py` | `cap_request_body(max_bytes)` — the body-size cap on the OAuth endpoints, applied in `urls.py` (64 KiB; `OAUTH_REQUEST_BODY_MAX_BYTES`). Header-only `CONTENT_LENGTH` check (Django's `LimitedStream` truncates an under-declared body to the lie, so the header is the only gate needed), returning a plain 413 before the view reads the body; `functools.wraps` preserves each view's `csrf_exempt` flag. `/mcp/sql/` is capped separately and higher (1 MiB) in `auth.py`, since its body carries the SQL query. |
| `views/registration.py` | RFC 7591 OAuth 2.0 Dynamic Client Registration endpoint at `/o/register`. Anonymous JSON POST that creates a new `Application` row with the curated public-client / PKCE-required posture and a `mcp-sql-<token>` name (so the prefix-based validator/auth/signal recognise it). Enforces RFC 8252 §7.3 loopback-only `redirect_uris` server-side and applies a **silent** per-IP block via `throttle` — once an IP crosses the threshold it gets an inert 201 (no `Application` row persisted) indistinguishable from success. Request-body size is capped at 64 KiB by `decorators.cap_request_body`, applied to all four OAuth endpoints in `urls.py`; periodic cleanup of stale dynamically-registered Applications is deferred until a concrete abuse pattern names the threat. |
| `signals.py` | Five receivers. (1) `user_logged_out` → deletes the user's `AccessToken` rows scoped to BOTH the canonical `mcp-sql` Application AND every dynamically-registered `mcp-sql-*` Application (`Q \| Q`) — the `mcp-sql-` prefix also covers settings-declared `mcp-sql-cloud.<name>` clients. (2) `post_migrate` `provision_mcp_profiles` → idempotently `get_or_create`s one Permission (content_type `mcpquerylog`) + one Group per `MCP_SQL["PROFILES"]` entry (config-derived, replaces static `Meta.permissions` + migration 0004). (2b) `post_migrate` `provision_mcp_cloud_clients` → idempotently `update_or_create`s one curated `Application` (`mcp-sql-cloud.<name>`, public/PKCE, no secret, `skip_authorization=False`, per-entry `redirect_uris`) per `MCP_SQL["CLOUD_CLIENTS"]` entry; create/update only (never deletes — settings-gated recognition is the off-switch). (3) `post_migrate` `audit_grants_drift_after_migrate` → calls `reconcile_grants(strict=False, apply=False)` and logs a WARNING when any profile's grants drift from its whitelist. **Read-only on the signal path.** Apply happens explicitly via `python manage.py mcp_sql_grants --apply` (`reconcile_grants(strict=True, apply=True)`) as a deploy step. Lenient mode: a fresh env whose DBA has not yet created the roles logs a WARNING and skips. (4) `m2m_changed` on `User.groups.through` → `logger.error` (Sentry event) when a user is ADDED to ANY MCP profile group; layered on top, a second ERROR when the addition leaves the user in >1 MCP profile group (ambiguous → denied until fixed). Gain-only, group-only by design (no defense without a named threat): losing a group, direct `user_permissions` grants, and group-permission-set changes are deliberately out of scope. Names the affected user(s) + profile(s); None-safe before provisioning (fresh DB). |
| `admin.py` | Unregisters django-oauth-toolkit's ModelAdmins (single-Application invariant), AND registers READ-ONLY admins for `MCPQueryLog` / `MCPAuthRejectionLog` (browse-only — `has_add/change/delete_permission` all False, via a LOCAL mixin, deliberately not a consumer-provided read-only mixin) plus a per-user **usage-summary** view at `/admin/mcp_sql/mcpquerylog/usage-summary/` aggregating allowed/rejected query + auth-rejection counts per rolling window (1h/24h/7d) — the `VOLUME_ALERT_THRESHOLDS` tuning instrument. `search_fields`/`ordering`/summary labels traverse the consumer user model's `USERNAME_FIELD`; the `user_email` display stays `get_username()`-generic — no email-keyed assumption. |
| `migrations/0004_create_mcp_sql_users_group.py` | Retained **no-op**. Originally created the `mcp_sql_users` group + `mcp_sql.use_mcp_session` permission; provisioning moved to the config-derived `provision_mcp_profiles` `post_migrate` receiver (signals.py) because the package can't enumerate consumer profile names in a migration. Kept so the graph stays intact for environments that already applied it. |
| `management/commands/mcp_sql_role_setup.py` | `--emit-sql`: generates the N-role bootstrap SQL (one `CREATE ROLE … NOLOGIN` + GUC defaults + membership `GRANT … TO <app_role>` per distinct profile role) from `MCP_SQL["PROFILES"]`, mirroring `sql/role_setup.sql`. Read-only — prints to stdout for a DBA to review/run (`… --emit-sql \| psql … -v app_role=<role>`); never connects or applies. |
| `migrations/0005_create_mcp_sql_application.py` | Hand-written data migration creating the curated `mcp-sql` OAuth Application: public client, PKCE, `skip_authorization=True` (operator-provisioned, known redirect URI — see the "OAuth surface" section for why DCR-minted clients have `skip_authorization=False` instead), RFC 8252 loopback redirect URI `http://127.0.0.1` (only — DOT 3.x doesn't treat `localhost` as loopback). |

## Settings shape

A single nested dict `MCP_SQL`, validated on startup by
`McpSqlConfig.ready()` against the `McpSqlSettings` TypedDict in
`mcp_sql/validation.py`. Validation enforces structural shape, positive
numerics, `DEFAULT_LIMIT <= HARD_LIMIT`, at-least-one profile with
non-empty + cross-profile-unique ROLE / PERMISSION_CODENAME / GROUP_NAME,
and the `app_label.ModelName` format on every profile's `ALLOWED_MODELS`
entry. Model resolution itself is deferred to runtime so optional installs
and load-order edge cases don't crash boot.

```python
MCP_SQL = {
    "PROFILES": {                         # one entry per access tier
        "default": {                      # ships in-package; reproduces flat behaviour
            "ROLE": "mcp_readonly_role",  # NOLOGIN PG role entered via SET LOCAL ROLE
            "PERMISSION_CODENAME": "use_mcp_session",   # mcp_sql.<codename>
            "GROUP_NAME": "mcp_sql_users",
            "ALLOWED_MODELS": [...],
            # "SESSION_CONTEXT": "dotted.path",  # optional dormant per-row hook
        },
        # more tiers: each its own ROLE / codename / group / whitelist
    },
    "BAN_SELECT_STAR": True,
    "LIMITS": {"DEFAULT_LIMIT": ..., "HARD_LIMIT": ..., "BYTES_LIMIT": ...},
    "VOLUME_ALERT_THRESHOLDS": {  # {decision: {window_seconds: threshold}}
        "allowed": {3600: 50, 86400: 150},
        "rejected": {3600: 50, 86400: 150},
    },
}
```

## Profiles (access tiers)

`MCP_SQL["PROFILES"]` defines N access tiers. Each profile is one
Postgres read-only role + its own `ALLOWED_MODELS` whitelist + the Django
permission/group that bind a user to it + an optional dormant per-row hook.
The in-package default ships a single `default` profile reproducing the
original flat behaviour, so `django-mcp-sql` works out of the box
and a single-tier consumer is a behaviour-preserving config.

- **Binding — one profile per user, by EXPLICIT assignment.** `conf.resolve_profile(user)`
  (shared by `auth.py` and `views/oauth_authorize.py`) queries the user's
  permission *assignments directly* (`Permission.objects.filter(Q(group__user=user)
  | Q(user=user), content_type__app_label="mcp_sql", codename__in=<profile codenames>)`),
  NOT `has_perm`. That is the only superuser-blind path: `has_perm` /
  `get_*_permissions` return every permission for an active superuser, so a
  superuser would otherwise be ambiguous AND gain access never explicitly
  granted. **Superuser confers nothing** — it reads every table via the shell
  anyway, so this is clean resolution + honest audit, not a confidentiality
  boundary. Fail-closed: 0 matches → `NO_PERM` deny; >1 distinct codename →
  `AMBIGUOUS_PROFILE` deny (never guess). A codename held via BOTH a group and
  a direct grant collapses to one (distinct), so it is not falsely ambiguous.
- **One alias, N roles.** Still one `mcp_readonly` Django alias; tiers are
  separated by role. `session.enter_readonly_session(cursor, *, role=...)` does
  `SET LOCAL ROLE`. The app login role needs membership in every profile role.
- **Per-profile groups/permissions are config-derived**, not static. The
  package can't enumerate consumer profile codenames at model-definition time,
  so `MCPQueryLog.Meta.permissions` is empty and the `provision_mcp_profiles`
  `post_migrate` receiver (signals.py) idempotently `get_or_create`s one
  Permission (content_type `mcpquerylog`) + one Group per profile after every
  `migrate`. Migration 0004 is a retained no-op (provisioning moved here);
  existing `default` rows are found and left untouched (zero data migration).
- **Per-role row limiting = static curated views** (no new mechanism — the
  same curated-view pattern below, granted to a specific profile's role with a
  static `WHERE`). A universal table shared across tiers can be exposed to a
  narrower tier as a `WHERE <discriminator> = '<value>'` view; the role gets
  SELECT on the view only. RLS is deferred (role-keyed RLS only enforces *through* a
  view on PG15+ `security_invoker`; the CI/test image is PG14).
- **Per-user scoping = the dormant `SESSION_CONTEXT` hook, NOT a feature.** A
  profile may set `SESSION_CONTEXT` to a dotted path
  `callable(user, profile) -> Mapping[str, str] | None` (default `None`;
  import-checked by the startup validator so a typo'd path fails every
  process at boot, and resolved eagerly at the first `profiles()` call).
  When set, `enter_readonly_session` applies
  each returned GUC via parameterized `set_config(name, value, true)` —
  transaction-local, values bound as params, names restricted to the
  `mcp_sql.*` namespace. Per-user row scoping is then "write a hook + a
  GUC-aware view" entirely in consumer code — a docs recipe, not core
  machinery. **The recipe carries a hardened contract**: the view's
  predicate must be a STRICT EQUALITY against a NOT-NULL column —
  `WHERE <not_null_col> = current_setting('mcp_sql.<x>', true)` — because
  that is the only shape whose fail-closed property (hook unset →
  `current_setting(..., true)` returns NULL → comparison is NULL → 0 rows)
  survives. Explicitly forbidden in scoping views: `OR` fallbacks
  (`WHERE current_setting(...) = 'all' OR col = ...` turns unset-context
  into an author-didn't-think-about-it branch), `IS NULL` branches
  (`OR col IS NULL` leaks NULL-column rows to every tenant), `LIKE`/pattern
  predicates (a `'%'` context value matches everything), and sentinel
  values. One correct example:
  `CREATE VIEW orders_scoped AS SELECT id, total FROM orders WHERE tenant_id = current_setting('mcp_sql.tenant', true);`
  — and its incorrect twin adds `OR tenant_id IS NULL`. Ship the hook now
  (retrofitting the executor seam later is the expensive part); nothing
  speculative hangs off it.
- **Alert split** (aggregate-alert convention): a request-time
  `AMBIGUOUS_PROFILE` denial logs a deduped WARNING + one `MCPAuthRejectionLog`
  row (no per-request Sentry); the paging Sentry ERROR fires once at
  ASSIGNMENT time, in the `m2m_changed` group-add receiver, when a user lands
  in >1 MCP profile group.
- **Roles bootstrap**: `manage.py mcp_sql_role_setup --emit-sql` generates the
  N-role `CREATE ROLE` + GUC + membership SQL from `PROFILES` (read-only;
  prints for a DBA). `sql/role_setup.sql` remains the single-role file for the
  package default.

Per-token / per-minute / concurrent rate limits and token-lifetime settings
are out of scope for this subsystem. The DB-role and per-statement guards
(`statement_timeout`, `idle_in_transaction_session_timeout`, `lock_timeout`,
`default_transaction_read_only`) plus the per-user volume tripwires
(`VOLUME_ALERT_THRESHOLDS`) are the only enforcement/alerting layers — and
the tripwire alerts, it does not block. Revisit only if abuse patterns appear.

## Whitelist contract

Each profile's `MCP_SQL["PROFILES"][<name>]["ALLOWED_MODELS"]` is the
**code-reviewed, env-shared** list of dotted model names that the tier's
read-only surface exposes. Define it once in the consumer's base settings so every environment inherits
the same list by default — one diff to review when adding or removing
an entry. Env-specific settings files should override only when they
need a narrower (test suites typically wipe to `[]` and stub per-case)
or genuinely-broader list. **If you ever need a per-env override, the
security review of the override diff matters more than the review of
the base diff** — env-specific entries are the highest-risk place to
widen the surface.

Each entry resolves at apply / check time to its `Model._meta.db_table`.
`mcp_sql_grants --apply` emits **table-level** SELECT grants (no
column-level grants). For sensitive subsets where exposing the full
table would leak passwords, encrypted credentials, or other PII, use
the **curated-PG-view pattern** below. Annotate sensitive whitelisted
models with `# MCP-EXPOSED: review carefully when adding fields` so
column-add reviewers see the cue. The `mcp_sql_lint` management
command is a **local pre-commit aid**, not a CI gate — run it manually
before opening a PR that adds columns to a whitelisted model.
It may be wired into the pipelines once the gate's signal-to-noise
is proven on real PRs; until then "I forgot to run it" is recoverable
on review, not at merge time.

## Curated-view pattern

When the agent needs to read *some* columns of a table but the table also
carries sensitive ones (passwords, encrypted credentials, URLs that may
embed secrets), expose a column-projecting PostgreSQL VIEW instead of
granting SELECT on the whole table.

The pattern is **two artifacts working together**, neither sufficient
alone:

1. **The PG VIEW** is the DB-level access boundary. `mcp_readonly_role`
   gets SELECT on the view; PG resolves that into SELECT on the underlying
   table only for the projected columns. The agent literally cannot SELECT
   the hidden columns. Created by a `RunSQL` migration; `mcp_sql` does NOT
   own the migration — it lives in the **owning app** alongside the
   underlying model. That keeps `mcp_sql` decoupled from the consumer's
   table schemas: when someone modifies the underlying table and the
   view's column list goes stale, the broken migration is in the same
   app as the table.

2. **The unmanaged Django model** is a Python handle that
   `apps.get_model("<owning_app>.MCPXxx")` resolves to a model whose
   `_meta.db_table` is the view name. `Meta.managed = False` so Django
   does not try to manage the schema (the migration's
   `CREATE OR REPLACE VIEW` holds the source of truth). The model is
   declared in the owning app's `models.py`, next to the underlying
   model. The migration registers the model in Django's state graph via
   `RunSQL(..., state_operations=[migrations.CreateModel(..., managed=False)])`;
   without that, `makemigrations` auto-generates a noisy state-only
   migration on every run and `make check-migrations` (CI gate) fails.

   **Why the model is needed at all** — `ALLOWED_MODELS` entries use
   the dotted `app_label.ModelName` notation, not raw `db_table` strings.
   That format is the project's chosen security-policy language:

   - **Reviewable**: code reviewers see Python types, not SQL identifiers.
   - **Refactor-safe**: renaming a `db_table` (e.g. via `Meta.db_table`)
     leaves the whitelist entry valid as long as the Python class stays put.
   - **Validated at startup**: `validate_mcp_sql_settings` regex-checks
     the `app_label.ModelName` shape, and `apps.get_model(entry)` raises
     `LookupError` immediately on a typo — vs a typo in a raw table name
     that would silently fail at GRANT time.
   - **One layer of indirection**: the view name is internal DB jargon;
     the model name is the consumer-facing identifier the whitelist
     advertises.

   The unmanaged-model + view pair bridges PG view ↔ Django-style policy
   notation. Without the model, the grants tooling has no Python handle
   to resolve `<owning_app>.MCPXxx` into its underlying table at
   `apps.get_model(entry)._meta.db_table` lookup time, and the whitelist
   validator at startup would reject the entry as not pointing at a real
   model class.

The whitelist entry uses the **owning-app dotted path**, never the
underlying table — e.g. `"users.MCPUserSummary"` (view) rather than
`"users.User"` (full table with `password`).

To add a new curated view (e.g. for a table whose body text or other
columns should stay hidden), follow the **two invariants** every
view migration must uphold:

- **Forward SQL uses `CREATE OR REPLACE VIEW`** (not bare `CREATE VIEW`)
  **when the change only adds columns**. Long-lived deployments with a
  no-destructive-DB-recovery posture (typical of stage / prod environments)
  would otherwise stall the deploy until a DBA manually `DROP VIEW`s an
  orphaned half-applied view. `CREATE OR REPLACE VIEW` makes the forward
  step idempotent on retry. The reverse SQL is always `DROP VIEW IF EXISTS`
  (views own no data, dropping is safe).
  **Exception — removing or reordering columns:** Postgres's
  `CREATE OR REPLACE VIEW` may only *append* columns to the end; it cannot
  drop, rename, or reorder existing ones, and fails on any DB that already
  has the old view. For those changes the forward SQL must be
  `DROP VIEW IF EXISTS <view>;` + `CREATE VIEW <view> AS ...`, which is
  equally retry-idempotent and still drops no data. See a consumer's
  column-removal view migration for a working example.

- **`RunSQL` carries `state_operations=[migrations.CreateModel(...)]`**
  registering the unmanaged model. Without it, Django's migration state
  graph doesn't know the model exists, `makemigrations` emits a spurious
  state-only migration on every run, and `check-migrations` (CI gate)
  fails. The `CreateModel` mirrors the model's fields and sets
  `options={"managed": False, "db_table": "<view_name>"}` so Django
  records "model in state, no DB schema managed". See the consumer's
  existing curated-view migrations for a working example.

Steps:

1. **Migration** in the owning app (e.g. `<owning_app>/migrations/000X_mcp_<view>_view.py`):
   ```python
   migrations.RunSQL(
       sql="CREATE OR REPLACE VIEW mcp_<view> AS SELECT col_a, col_b, ... FROM <table>;",
       reverse_sql="DROP VIEW IF EXISTS mcp_<view>;",
       state_operations=[
           migrations.CreateModel(
               name="MCP<View>",
               fields=[("id", models.AutoField(auto_created=True, primary_key=True, ...)), ...],
               options={"managed": False, "db_table": "mcp_<view>", ...},
           ),
       ],
   )
   ```
2. **Unmanaged model** in the owning app's `models.py`: `class MCP<View>(models.Model): ... ; class Meta: managed = False; db_table = "mcp_<view>"`. Field set must match the migration's `state_operations` `CreateModel` exactly.
3. **Whitelist entry** in the exposing profile's `MCP_SQL["PROFILES"][<name>]["ALLOWED_MODELS"]`: `"<owning_app>.MCP<View>"`. Remove the underlying `<owning_app>.<Model>` if it was there.
4. **Run `check-migrations`** to confirm the state graph is in sync ("No changes detected" — not "Would create migrations for ..."). Then **run `mcp_sql_grants --apply`** so `mcp_readonly_role` gets SELECT on the new view.

Why not column-level GRANTs instead? Postgres supports `GRANT SELECT
(col1, col2, ...) ON table TO role`, which would obviate both view and
model. The reason we don't: `grants.declared_tables()` and
`mcp_sql_grants --apply` operate at table granularity today; rewriting
for columns is a real chunk of work. The view + unmanaged-model pair is
the standard Django idiom and is more legible — a `git diff` on a single
view migration shows "we expose these N columns" at a glance, vs
column-level grants scattered in tooling state.

## OAuth surface

- **Application identity**: three recognised shapes — the exact name `mcp-sql` (the canonical row from migration 0005), the prefix `mcp-sql-` (every RFC 7591 dynamically-registered client, named `mcp-sql-<urlsafe16>`), and — only when `MCP_SQL["CLOUD_CLIENTS"]` is non-empty — one settings-declared `mcp-sql-cloud.<name>` per operator-blessed cloud client. The first two come from `mcp_sql_settings.APPLICATION_NAME` / `APPLICATION_NAME_PREFIX` (defaults `"mcp-sql"` / `"mcp-sql-"` — note the trailing dash, see "Watch out" for why); the third is a **settings-gated** branch in `consts.is_mcp_application_name(name)` that matches against `mcp_sql_settings.cloud_clients()` (drop the entry from settings → denied at the next request, tokens included). The `.` after `cloud` keeps the id disjoint from the DCR `<urlsafe16>` shape. `MCPOAuth2Validator` / `MCPOAuth2Authentication` use the helper; the logout signal uses `Q(name=APPLICATION_NAME) | Q(name__startswith=APPLICATION_NAME_PREFIX)` (the prefix covers the cloud shape too). All MCP-purpose Applications carry `client_type=public` (no `client_secret`), `authorization_grant_type=authorization_code`, PKCE-required.
- **Consent screen asymmetry**: the curated migration-0005 `mcp-sql` Application has `skip_authorization=True`; every DCR-minted `mcp-sql-<token>` Application has `skip_authorization=False`. The curated client is operator-provisioned — its redirect URI is fixed in the migration so there is no rogue-client attack surface — and consent would be friction without security. DCR clients are anonymous-registration by RFC 7591 §3 design; an attacker can mint a rogue `mcp-sql-<token>` client with a loopback `redirect_uri` they control, then phish a logged-in MCP-cohort victim with a fully-formed `/o/authorize/?client_id=<attacker's>&...` link. With `skip_authorization=True` the auth code 302s silently to the victim's `127.0.0.1:<attacker-chosen-port>` and any process listening there captures it; with `skip_authorization=False` the consent screen is a CSRF-protected POST the victim must explicitly submit, breaking the silent-GET attack chain. The trade-off is one consent click every 6 h (token TTL) for legitimate users — DOT 3.x has no native "remember my choice" mechanism on its consent template. Settings-declared `mcp-sql-cloud.<name>` clients also carry `skip_authorization=False`: their redirect is a provider-hosted, off-device callback, so the same phishing surface applies and consent is required.
- **Single scope**: `mcp:sql`. `MCPOAuth2Validator` refuses to mint anything else, and `MCPOAuth2Authentication` re-checks the scope on every request.
- **Redirect URI**: RFC 8252 §7.3 loopback — `http://127.0.0.1`, `http://[::1]`, or `http://localhost`, any port, with or without path. The registration endpoint enforces this server-side (`views/registration.py::_is_loopback_redirect`) and additionally rejects a userinfo component (`http://user:pass@127.0.0.1/cb`). **The two surfaces treat `localhost` differently, and both are correct:** the curated migration-0005 Application registers bare `http://127.0.0.1` and leans on DOT's *port-wildcarding* — DOT accepts any port on a registered loopback **IP** (`127.0.0.1`/`::1`) at a path-exact match, but it does NOT port-wildcard `localhost`, so a bare `http://localhost` there would match only a literal port-less `http://localhost` (useless) and is omitted. Dynamically-registered (DCR) clients instead store the **exact** URI they provided (e.g. `http://localhost:62064/callback`), which DOT matches exactly — no port-wildcarding needed — so the DCR endpoint *does* accept `localhost`. It must: Anthropic's MCP SDK (and Google/GitHub native-app OAuth) use `http://localhost:<port>/callback` despite RFC 8252 §7.3's SHOULD-NOT, and interop wins. **Non-loopback (`https`) redirects are admitted only for operator-declared cloud clients** (`MCP_SQL["CLOUD_CLIENTS"]`, see the "OAuth surface" cloud-clients note below): exact-match entries ride DOT's stock exact matching, and the single `MCPOAuth2Validator.validate_redirect_uri` prefix override (`_redirect_under_prefix`) admits a per-instance callback under an allowlisted `https` host+path prefix (host-exact never `endswith`, no userinfo, no `..`, port-exact). `/o/register` itself is **unchanged — still loopback-only**; the cloud path never touches it.
- **Token lifetime**: 6 h access (`ACCESS_TOKEN_EXPIRE_SECONDS=21600`); refresh tokens "disabled" via `REFRESH_TOKEN_EXPIRE_SECONDS=0` — DOT still mints a `refresh_token` field in the token response (cosmetic), but its lifetime is 0 seconds so it cannot actually be used to refresh. Effective behavior: no usable refresh tokens. Authorization code expires in 60 s.
- **URLs**: only `/o/authorize/`, `/o/token/`, `/o/revoke_token/`, and `/o/register` are exposed (curated subset of DOT's URLs plus our RFC 7591 view). `/o/applications/`, `/o/authorized_tokens/`, `/o/introspect/`, `/o/userinfo/` are deliberately absent — no admin/introspection/userinfo surface is reachable.
- **Issuance gate** at `/o/authorize/`: `is_active AND is_staff AND is_mfa_enabled(user) AND resolve_profile(user) binds exactly one profile` (NO_PERM / AMBIGUOUS_PROFILE → `PermissionDenied`). **Option D session-trust** — no fresh-TOTP timestamp check. The consumer's `SESSION_COOKIE_AGE` forces re-MFA at the boundary naturally; an active session is therefore proof of recent-enough MFA. Revisit if the threat model ever requires re-challenging TOTP at every token issuance.
- **Runtime gate** in `MCPOAuth2Authentication.authenticate` (every MCP request): the same issuance checks PLUS an **opt-in** session-existence check. When `MCP_SQL["SESSION_MODEL"]` is set to a session-with-user model, the gate runs `<model>.objects.filter(user=user, expire_date__gt=now()).exists()` and rejects on miss. When `SESSION_MODEL` is unset (`None`, the in-package default), the gate is skipped — stock `django.contrib.sessions.Session` has no `user` FK, so defaulting to it would crash with `FieldError`; making the gate opt-in is the honest contract. Consumers who DO enable the gate get the runtime half of Option D — without it, a Django session can die (cookie cleared, admin deletes the row, `clearsessions` sweeps an expired row, a restart wipes a cache-only session store) while the OAuth bearer outlives it for up to the token's 6h TTL. With the gate enabled, the consumer's `SESSION_COOKIE_AGE` becomes the *real* upper bound on token usefulness rather than just an issuance-time freshness proxy. Explicit logout still has its own fast path via the `user_logged_out` signal regardless of gate setting (revokes tokens immediately so the next request 401s on missing-token, not on missing-session).
- **Per-request re-validation** in `MCPOAuth2Authentication.authenticate`: same gate, every call. A revoked permission, removed MFA device, or deactivated account invalidates outstanding tokens immediately, without waiting for the 6 h expiry.
- **Logout revocation**: `user_logged_out` deletes the user's MCP-purpose `AccessToken` rows (scoped via `application__name__startswith="mcp-sql"`, covering the curated Application, every dynamically-registered client, and every settings-declared `mcp-sql-cloud.<name>` client).
- **Cloud clients (opt-in, Category-B)**: `MCP_SQL["CLOUD_CLIENTS"]` (empty default → off) admits operator-blessed cloud-brokered clients (Claude.ai web/desktop/mobile/Cowork, ChatGPT/Codex-cloud) that vault the token in the provider's cloud behind an `https` callback. Each entry provisions one curated `Application` (`mcp-sql-cloud.<name>`, public/PKCE, no secret, `skip_authorization=False`) via the `post_migrate` receiver `provision_mcp_cloud_clients` (mirrors `provision_mcp_profiles`; create/update only — never deletes, recognition is what gates). Redirect matching is per-entry `"exact"` (DOT stock) or `"prefix"` (the one hardened override). No refresh tokens: cloud users re-consent every 6 h like everyone else. Full onboarding + the `SESSION_MODEL` recommendation live in `docs/oauth.md` → "Cloud clients". **Onboarding is settings-declared, not CIMD** (Client ID Metadata Documents): CIMD is the vendors' strategic direction but is deferred — its payoff is directory-scale we lack, it adds an SSRF-guarded auth-path fetch, and DOT's non-null `Grant.application` FK still needs a row; if DOT gains native CIMD it becomes an additive recognition branch. See `docs/oauth.md` → "Roadmap".
- **Audience binding**: implicit. DOT 3.2.0 + oauthlib 3.3.1 don't natively support RFC 8707 Resource Indicators. Binding is achieved via the single `mcp:sql` scope plus the auth class being mounted only on `/mcp/sql/`. Revisit when DOT releases first-class RFC 8707 support.

## Naming map

The subsystem's identifiers vary in casing and separator because each
target has its own conventions. Use this table when greppling or
renaming.

| Token | Where it appears | Why this spelling |
|---|---|---|
| `mcp_sql` | Python package, Django app label, settings dict key, GUC namespace (`mcp_sql.app_role`), permission's `content_type__app_label`, migration `app_label` | Python / Django identifier — underscore. |
| `mcp-sql` | OAuth Application `name` and `client_id`, URL host path (`mcp/sql/` not `mcp_sql/`) | OAuth client identifiers and URL slugs follow kebab-case convention. |
| `<slug-of-RESOURCE_NAME>` (e.g. `local-my-app`) | `<name>` arg to `claude mcp add --transport http <name> <URL>` — developer-local identifier in `~/.claude.json` | Reuses the env's RFC 9728 `resource_name` (sourced from `MCP_SQL["RESOURCE_NAME"]`) so a developer connected to multiple envs doesn't conflate them. Local-only; never reaches the server. |
| `mcp_readonly_role` | Postgres role name | Postgres identifier — underscore (quoted via `%I` so case is preserved). |
| `mcp_readonly` | Django DB alias | Python dict key for `DATABASES`; underscore for consistency with Python. |
| `mcp_sql_users` | Django Group name | Django group naming — readable underscore form, mirrors `mcp_sql` app. |
| `use_mcp_session` | Permission codename | Note: no `_sql` suffix. The codename is intentionally short — Django concatenates `<app_label>.<codename>` (`mcp_sql.use_mcp_session`) for the dotted permission string, so a `use_mcp_sql_session` codename would read awkwardly. |
| `mcp:sql` | OAuth scope | OAuth scope convention is `category:resource`; the colon is meaningful. |
| `MCP_SQL` | Settings dict key; env-var prefix (`MCP_SQL_*`) for ops-tunable knobs only (`MCP_SQL_DEFAULT_LIMIT`, `MCP_SQL_HARD_LIMIT`, `MCP_SQL_BYTES_LIMIT`). The security/alerting policy fields (per-profile `ALLOWED_MODELS` inside `PROFILES`, `BAN_SELECT_STAR`, `VOLUME_ALERT_THRESHOLDS`) are committed in `settings/<env>.py`, never env-driven. | Python settings constants — uppercase underscore. |
| `MCPQueryLog`, `MCPOAuth2Authentication`, etc. | Python class names | `MCP` is treated as an initialism (uppercase, no underscore inside). |

## Watch out

The load-bearing invariants and footguns, grouped by layer:

- [DB role, connections & `SET LOCAL`](#db-role-connections--set-local)
- [Parser & executor](#parser--executor)
- [Auth & permission gating](#auth--permission-gating)
- [MCP transport & tool dispatch](#mcp-transport--tool-dispatch)
- [Throttling & proxy trust](#throttling--proxy-trust)
- [OAuth tokens & client identity](#oauth-tokens--client-identity)
- [Curated-view migrations](#curated-view-migrations)

### DB role, connections & `SET LOCAL`

- **Role-level GUCs are inert under `SET ROLE`.** `ALTER ROLE r SET param`
  in `role_setup.sql` only fires when something **logs in** as that role.
  `mcp_readonly_role` is `NOLOGIN` and the executor enters via
  `SET LOCAL ROLE` from the app's login session, so those defaults never apply.
  Every transaction that uses the readonly path **must** explicitly
  `SET LOCAL` each guard. `session.enter_readonly_session(cursor, role=...)` is the
  single helper that does this; do not inline a partial copy. The role-level
  defaults are kept in `role_setup.sql` as defense-in-depth in case the role
  is ever switched to `LOGIN`, not as active enforcement today.
- **Only `SET LOCAL`, never bare `SET`.** Library-wide invariant: every SQL
  `SET` issued by `mcp_sql` code (runtime read path AND bootstrap script)
  uses `SET LOCAL` inside an explicit transaction. Deployments commonly
  front the readonly alias with **transaction-mode pgbouncer**, which
  pins a backend to a client for the duration of a transaction and
  returns it to the pool on `COMMIT`/`ROLLBACK`. `SET LOCAL` is scoped
  to the transaction GUC stack and is popped by PG's `AtEOXact_GUC` at
  commit/abort — strictly before pgbouncer emits the backend as
  releasable (the protocol gate is `ReadyForQuery 'I'`, which PG only
  sends after the revert). A bare `SET` modifies session scope, is NOT
  popped at commit, and would persist on the reused backend as pgbouncer
  hands it to the next client. The only SQL `SET`s in the library are:
  `session.py` (`SET LOCAL ROLE` + four `SET LOCAL <guc>` lines — the
  runtime read path), and `sql/role_setup.sql` (`SET LOCAL
  mcp_sql.app_role` inside an explicit `BEGIN ... COMMIT` — the
  bootstrap path). The four `ALTER ROLE mcp_readonly_role SET …` lines
  in `role_setup.sql` are *not* session SETs — they write to
  `pg_db_role_setting` and apply only at LOGIN, so the pgbouncer
  contamination model doesn't reach them. When grepping for compliance:
  `grep -nE '\bSET\b'` over the package tree should match nothing
  outside `SET LOCAL` (or `ALTER ROLE ... SET`).
- **The membership grant** lives in `role_setup.sql` and is parametrised
  via the psql variable `app_role`. Callers pass `-v app_role=<role>`:
  the local/test init wrapper (`sql/10_mcp_role.sh`) supplies
  `$POSTGRES_USER`; the DBA passes the matching value by hand on
  stage / prod. Because psql variables are NOT substituted inside
  `DO $$ ... $$` blocks,
  the script wraps the GRANT in an explicit `BEGIN ... COMMIT` and uses
  `SET LOCAL mcp_sql.app_role = :'app_role'` (which psql does substitute
  at the call site); the DO block, running inside that same transaction,
  reads the value via `current_setting('mcp_sql.app_role')` + `EXECUTE
  format('GRANT mcp_readonly_role TO %I', target_role)` for proper
  identifier quoting, and `COMMIT` reverts the LOCAL GUC. `SET LOCAL` (not
  bare `SET`) is the library-wide invariant — see the dedicated "Only `SET
  LOCAL`, never bare `SET`" bullet below for the threat model. The app
  role cannot issue this GRANT itself because membership grants require
  the admin option, which only superuser holds. Forgetting
  `-v app_role=<role>` makes the `SET LOCAL` fail with "unrecognized
  parameter" / "syntax error at or near :" — the role is still created,
  but membership is skipped and the executor's `SET ROLE` will fail later.
  The `EXCEPTION WHEN undefined_object` block raises a NOTICE rather than
  swallowing so a bootstrap-order issue (app role not yet created)
  surfaces in the DBA's output. `mcp_sql_grants --apply` also verifies
  membership via `pg_has_role` upfront.
- **Default DB alias must never serve MCP read queries**: it has
  `ATOMIC_REQUESTS=True` and would join the request transaction. The
  executor calls `connections["mcp_readonly"]` directly and asserts
  `connection.alias == "mcp_readonly"` before issuing the SELECT — a
  misconfigured `DATABASES` that remapped `mcp_readonly` to the default
  alias would raise `ExecutorMisconfiguredError` loudly. The read-path
  guarantee is that `assert`, **not** the router: routers can't intercept
  explicit `using=` / `connections[...]` calls, which is exactly how the
  executor reaches `mcp_readonly`. `db_router.McpSqlRouter` owns only the
  migration side — `allow_migrate` refuses to build schema on `mcp_readonly`
  (a lens onto the DB `default` owns) — and abstains from everything else;
  audit writes reach `default` via Django's fallback, not a router pin.
### Parser & executor

- **Parser-check ordering matters for audit fidelity.** Security-relevant
  reasons fire before ergonomic ones so the audit row names the actual
  problem: WRITEABLE_CTE catches `WITH a AS (DELETE ... RETURNING ...)`
  before any RETURNING-aware logic would (it cannot anyway —
  `exp.Returning` only appears under write nodes, which NON_SELECT_ROOT
  rejects at the top level); SYSTEM_SCHEMA before SELECT_STAR so
  `SELECT * FROM pg_class` attributes to the catalog. Reorder with care —
  `test_parser.TestCheckOrdering` pins the contract.
- **Row cap is most-restrictive-wins across three sources.** `run_query`'s
  effective row cap is `min(tool_kwarg, sql_LIMIT_N, HARD_LIMIT)`, falling
  back to `DEFAULT_LIMIT` when neither tool kwarg nor SQL LIMIT is set.
  `parser.extract_limit` reads what the user wrote in SQL so the executor
  can honor a small `LIMIT N`; `parser.inject_limit` then clobbers with
  `clamped+1` for the N+1 truncation-detection trick. Without
  most-restrictive, the executor would silently *raise* a user's `LIMIT 3`
  to `LIMIT 10+1` and return 10 rows + `truncated=True` — confusing the
  caller about both the row count and the truncation reason.
  `test_executor.TestExecutorLimitClamp` pins each ordering combination.
- **Truncation has two axes, one flag — but row-count truncation only
  fires when the SERVER capped.** Byte truncation (`BYTES_LIMIT`) always
  sets `truncated=True` because it's server-side regardless of caller
  intent. Row-count truncation only sets `truncated=True` when the
  server's cap was the binding constraint — either `DEFAULT_LIMIT`
  (caller supplied no row cap at all) or `HARD_LIMIT` (caller's value
  exceeded the ceiling). If the caller explicitly asked for `LIMIT 3`
  and we returned 3 of N matching rows, `truncated` stays `False`: the
  caller chose their cap, the aggregation hint would be wrong. The LIMIT
  N+1 trick still runs in both cases — we just suppress the flag when
  the caller's intent was honored. `test_executor.TestExecutorLimitClamp`
  pins both directions.
- **First row always lands even if it exceeds `BYTES_LIMIT`.** Otherwise
  the agent sees `rows=0, truncated=true` and has no idea what was
  returned. The byte cap kicks in from the second row onward.
- **Non-primitive cell types are coerced to `str()` in the row pipeline.**
  Decimal, datetime, UUID, bytes all become JSON-storable strings before
  they hit `QueryResult.rows`. Byte accounting uses `json.dumps(default=str)`
  to mirror this.
- **Pagination is intentionally absent.** OFFSET, FETCH FIRST/NEXT, and any
  cursor/fetch_next/stream tool would push the agent toward unstable
  pagination. The truncation hint steers toward keyset pagination
  (`WHERE id > <last_seen_id> ORDER BY id LIMIT N`) or aggregation.
  `_check_no_offset` / `_check_no_fetch` reject both at parser layer;
  `_check_no_locking_reads` rejects `FOR UPDATE` / `FOR SHARE` (the role
  has no DML grants anyway, but parser-layer reject yields a clearer audit
  reason than `EXECUTION_ERROR`).
- **`limit=0` is a valid "metadata only" request, not a footgun.** The
  executor short-circuits without touching the DB: zero-row `QueryResult`,
  audit row with `decision='allowed'`, `wrapped_sql=''`, `duration_ms=0`,
  `row_count=0`. `limit=-N` is clamped to 0 via `max(0, min(limit, HARD))`.
- **Misconfig vs execution-error audit distinction.** An operator-level
  `ExecutorMisconfiguredError` (alias absent or alias-resolves-wrong) writes an
  audit row with `rejection_reason='misconfigured'`. Real PG errors use
  `'execution_error'`. The per-user volume tripwire (`observability.py`)
  reads `decision` + the closed reason vocabulary, not `error` text.
- **Hint vocabulary stays Django-free.** `schemas.py` does NOT import
  `session.py` (would pull `grants.py` → Django). The timeout text in
  `HINTS[TIMEOUT]` is hardcoded to `5s` and pinned to the actual GUC value
  by `tests/test_executor.py::TestHintConstants`.
- **Audit append-only is convention, not a trigger.** Revisit
  if abuse appears.
- **`grants_apply` / `grants_check` refuse `mcp_sql.*` whitelist entries.**
  Letting the agent read its own audit trail defeats the audit. The
  refusal is a code-level guard in addition to the migration-level REVOKE.
### Auth & permission gating

- **`MCPOAuth2Authentication` is mounted on `/mcp/sql/` only.** It is
  **never** added to `REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]`.
  A token presented to any other DRF endpoint receives no special
  handling — DRF's default `SessionAuthentication + TokenAuthentication`
  doesn't recognise the `Bearer` prefix and yields anonymous. The
  negative test in
  `tests/test_auth_class.py::TestOAuthTokenIsolationFromGlobalDRF` pins
  this contract against `/api/users/` and `/api/global-search/`, with a
  positive-control assertion on the same token via the MCP auth class.
- **The view self-declares its permission contract.**
  `@permission_classes([IsAuthenticated])` sits directly on
  `mcp_endpoint` so the 401 + RFC 9728 `WWW-Authenticate` response for
  anonymous probes does not depend on the consumer's
  `REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"]`. Stock DRF defaults to
  `AllowAny` — without the explicit decorator the anonymous request
  would reach the FastMCP bridge, return 200 with a JSON-RPC error, and
  MCP clients (Claude Code) would never receive the challenge they
  need to bootstrap OAuth. The regression is pinned by
  `tests/test_mcp_endpoint.py::TestStockDRFDefaultsDoNotPiercePackage`.
### MCP transport & tool dispatch

- **`run_query` results are fenced; `rows` is a string, not a list.** The
  `run_query` tool passes `asdict(QueryResult)` through
  `fencing.fence_query_result` before returning, so `rows` (and `error`,
  when set) come back as a per-response random-UUID `<untrusted-data-…>`
  string with a sibling `data_handling` instruction — the agent's defence
  against prompt-injection carried in DB content. The random suffix is the
  point: an attacker who controls a cell value cannot guess it to forge a
  closing tag and "break out". Anything consuming the tool result must
  parse the JSON *inside* the fence; do not assume `rows` is still a list.
  `list_tables` / `describe_table` are NOT fenced (their output is package
  metadata, not DB content). Pinned by `tests/test_fencing.py` and the
  closure assertion in `test_mcp_endpoint.py`.
- **The standing security warning lives in `instructions`, not in tool
  results.** `_SERVER_INSTRUCTIONS` is passed to `FastMCP(instructions=...)`
  and returned once in the MCP `initialize` response — out-of-band from any
  row content, before the agent has fetched a single byte of untrusted data.
  That is deliberate: a warning carried in a tool *result* would share the
  channel with the very injected content it warns about (the fence's
  per-response `data_handling` note is the correct *per-result* granularity;
  the connect-time posture is `instructions`). It warns that `run_query`
  content is untrusted AND that the server cannot constrain the agent's
  OTHER tools, recommending the operator run the client human-in-the-loop
  (not blanket auto-accept) — see `docs/oauth.md` "Run the connecting client
  safely". This is **advisory**: a server cannot force a client's UI or
  permission mode. The honest `readOnlyHint=True` annotations may make a
  client auto-approve the three SQL tools themselves — fine, they only read
  whitelisted tables; the residual risk is the agent's other tools, which is
  why the `instructions` warning targets them. Pinned by
  `test_mcp_endpoint.py::TestBuildMcpServer::test_server_advertises_security_instructions`
  and `::test_tools_are_annotated_read_only`.
- **Per-request `FastMCP` instantiation is deliberate.** Tool callables
  close over the authenticated `user` / `token_id` / `client_ip`. A
  module-level `FastMCP` referencing `request.user` would risk
  cross-request bleed-through or thread-local subtlety. The SDK eagerly
  builds Pydantic schemas for the registered tools, so the construction
  cost is single-digit milliseconds — small relative to the executor's
  tx + SELECT, and the alternative (thread-local-juggled shared FastMCP)
  is one refactor away from cross-request leakage.
- **All three tools are `async def`; each dispatches its ORM work via
  `sync_to_async`.** FastMCP dispatches sync tool callables directly inside
  its asyncio event loop (no auto-thread), and every tool now touches the
  ORM: `run_query` opens the readonly cursor + writes an audit row, and
  `list_tables` / `describe_table` write a metadata audit row via
  `executor.audit_tool_call` (tool-attribution audit). A sync ORM call
  from inside the running loop trips Django's `SynchronousOnlyOperation`.
  So each tool is `async def` and dispatches its ORM work via
  `sync_to_async(...)(...)` with **`thread_sensitive=False`** — the audit
  write goes through the unrelated `default` alias and `run_query` opens
  its own `mcp_readonly` connection per call, so there's no per-thread
  connection state to preserve, and the default (`True`) would serialise
  concurrent `/mcp/sql/` requests through one shared executor thread (one
  slow query head-of-line-blocking every other agent). If a future tool
  also hits the ORM, give it the same shape — never silently call sync ORM
  from a sync FastMCP tool. **Each dispatch is wrapped in
  `_close_conns_after`** so the asgiref pool thread runs
  `close_old_connections()` when the call returns: Django's
  request-boundary connection cleanup is wired to `request_started` /
  `request_finished` on the main worker thread and never fires on these
  `thread_sensitive=False` pool threads, so without it a connection opened
  there (the readonly alias, and the `default` alias for the audit write)
  would linger idle for the worker's life, ignoring its `CONN_MAX_AGE`.
  `close_old_connections` (not `close_all`) **respects** `CONN_MAX_AGE` —
  it closes the `CONN_MAX_AGE=0` readonly alias and leaves a consumer's
  pooled `default` alone.
- **DRF pre-reads `request.body` for content negotiation.** By the time
  we hand the WSGI environ to `a2wsgi.ASGIMiddleware`, `wsgi.input` is at
  EOF. `_invoke_wsgi_app` re-seeds `environ["wsgi.input"]` with
  `io.BytesIO(request.body)` before invoking the bridge. Anyone touching
  the MCP view must preserve the re-seed.
- **Two-tier request-body cap.** `/mcp/sql/` is capped at 1 MiB in
  `auth.MCPOAuth2Authentication` — its body carries the agent's SQL, so even
  a large literal `IN (...)` list must fit. The OAuth endpoints
  (`/o/authorize/`, `/o/token/`, `/o/revoke_token/`, `/o/register`) get a
  tighter 64 KiB cap via `decorators.cap_request_body` in `urls.py`;
  `/o/token/` and `/o/register` are anonymous, so the cap closes a
  memory-amplification vector that would otherwise be bounded only by the
  consumer's global `DATA_UPLOAD_MAX_MEMORY_SIZE`. Both are header-only
  checks — sound because Django wraps `wsgi.input` in
  `LimitedStream(CONTENT_LENGTH)`, which truncates an under-declared body to
  its lie, so a request can only get N bytes read by declaring `>= N` (which
  the cap rejects). Tune either knob without touching the other:
  `MCP_REQUEST_BODY_MAX_BYTES` (`auth.py`) and `OAUTH_REQUEST_BODY_MAX_BYTES`
  (`decorators.py`). Note the `/mcp/sql/` cap doubles as the only bound on
  parser *input* size — sqlglot parses in-worker, before the DB
  `statement_timeout` — so it is the knob to revisit if adversarial large
  queries ever warrant a parse-time guard.
- **CSRF is exempt; CORS is default-deny.** Bearer-token auth, not
  session cookies, so CSRF is structurally inapplicable. CORS is not
  added to `CORS_URLS_REGEX`; the endpoint is server-to-server only.
### Throttling & proxy trust

- **Silent IP block on bad-token probing — observability is one log line per trip.**
  `throttle.is_ip_blocked` (called by `MCPOAuth2Authentication`)
  short-circuits with a generic
  401 once an IP exceeds `MCP_SQL["BAD_TOKEN_IP_THRESHOLD"]` (default 100)
  within `BAD_TOKEN_IP_WINDOW_SECONDS` (default 21600 = 6 h). The wire
  response is deliberately indistinguishable from "bad token" / "no auth"
  so a probing attacker on the guessable `/mcp/sql/` URL cannot
  fingerprint the block and gets no `Retry-After` to optimise against.
  The **same primitive and the same threshold/window** also guard
  `/o/register` under the `register` scope (silent inert 201 there — see
  the `views/registration.py` file-map row); the two scopes keep
  independent per-IP keys so a flood on one never depletes the other's
  budget.
  Operator-visible signal at the threshold-crossing moment only: one
  `logger.warning("MCP bad-token silent IP block engaged: ip=… count=…")`
  per IP per window. No admin UI, no per-request log noise. **Operator
  override**: `cache.delete('mcp_sql:bad_token:ip:<ip>')` from a Django
  shell, or wait the 6 h TTL. **Threat-model scope**: single-host probing
  only. A botnet driving fewer-than-threshold probes per IP bypasses the
  block entirely — that pattern is deliberately accepted (the guessable but
  value-free `/mcp/sql/` URL is a low-value target), and there is no global
  per-minute cross-IP counter to feed a dedicated botnet alert, since
  maintaining that counter is not worth it for this target.
  NAT-collateral risk (multiple
  cohort users sharing one egress IP) is acknowledged but not mitigated
  here — the MCP cohort is small (active staff with MFA + the perm), so
  the bar to silently block a legitimate user is `THRESHOLD` failed
  probes from the shared egress within the window; if it ever materialises
  raise `BAD_TOKEN_IP_THRESHOLD`. Cache-outage posture: fail-open —
  `throttle.is_ip_blocked` returns False, downstream DOT runs normally
  (legitimate users keep working, bad-token traffic resumes at full
  volume — same as if the block feature were off). The outage surfaces
  through the cache backend's own health monitoring and the one-shot
  `MCP <scope> counter increment failed` WARNING from
  `throttle.record_attempt`, not through any mcp_sql-maintained counter.

- **Discovery views trust `ALLOWED_HOSTS` + `SECURE_PROXY_SSL_HEADER`.**
  `views/discovery.py` builds absolute URLs from `request.scheme` and
  `request.get_host()`. Two Django-level layers must be sound for the
  metadata + `WWW-Authenticate` URLs to stay honest: `ALLOWED_HOSTS` is
  pinned per env (no wildcards), and `SECURE_PROXY_SSL_HEADER` is set
  whenever a reverse proxy terminates TLS so `request.scheme` reflects
  the real outer scheme. The proxy itself must also strip
  client-supplied `X-Forwarded-*` and emit its own. If any of those
  layers ever loosens — a wildcard `ALLOWED_HOSTS`, a proxy that stops
  rewriting forwarded headers — the absolute URLs become
  attacker-influenceable. The `DEBUG=False` branch of `_issuer()` is the
  structural defense in depth: even if the scheme ever lies, non-dev
  envs advertise `https://` by construction.
- **The per-IP throttle trusts YOUR deployment's IP handling — you must
  harden it.** Both silent blocks (`bad_token` on `/mcp/sql/`, `register`
  on `/o/register`) key on `request.META["REMOTE_ADDR"]`. The package does
  nothing to derive the real client IP — behind a reverse proxy,
  `REMOTE_ADDR` is the proxy's address for every request, collapsing the
  whole cohort onto one counter (one burst locks everyone out). A consumer
  behind a proxy therefore needs a real-IP middleware (e.g. ipware-based)
  that rewrites `REMOTE_ADDR` from `X-Forwarded-For` — **and that value is
  only the genuine client IP if the edge proxy discards client-supplied
  `X-Forwarded-*` headers and emits its own, and nothing can reach the app
  port bypassing the proxy** (for Traefik: `forwardedHeaders.insecure:
  false` with no `trustedIPs`, app port never published past the proxy;
  other proxies have equivalents). If either half is missing, `REMOTE_ADDR`
  becomes attacker-controllable: an attacker can both evade their own block
  (rotate fake IPs) and weaponise it (spoof a victim's IP to lock them
  out). **Keying on the raw TCP peer is NOT the fix** — that's the
  one-counter-for-everyone failure above. If the proxy guarantee weakens,
  pin the real-IP middleware's trust boundary (ipware `proxy_count` /
  trusted-proxy list) instead. The same proxy invariant underpins the
  discovery-views bullet above (`ALLOWED_HOSTS` +
  `SECURE_PROXY_SSL_HEADER`).
### OAuth tokens & client identity

- **Logout revokes the user's MCP tokens** — scoped via
  `Q(application__name=mcp_sql_settings.APPLICATION_NAME) |
  Q(application__name__startswith=mcp_sql_settings.APPLICATION_NAME_PREFIX)`.
  Both shapes are required since the trailing dash on the prefix means a
  plain `startswith` no longer matches the canonical row. Refresh tokens
  are not deleted separately — they're disabled by
  `REFRESH_TOKEN_EXPIRE_SECONDS=0` and any that appear are config drift
  to investigate.
- **Trailing dash on `APPLICATION_NAME_PREFIX` is structural, and the DCR
  suffix shape is checked.** Without the dash `startswith("mcp-sql")` would
  match BOTH the canonical `mcp-sql` row AND every DCR-minted
  `mcp-sql-<token>` row, with no identifier-layer distinction between
  curated and dynamically-registered clients. The trailing dash makes the
  two shapes disjoint: the canonical name is matched by exact equality, the
  prefix matches only DCR-minted ones. `consts.is_mcp_application_name`
  further requires the prefix's suffix to match the DCR token shape (22
  url-safe-base64 chars from `secrets.token_urlsafe(16)`), so a hand-crafted
  `mcp-sql-<anything>` Application is **not** recognised as MCP-purpose —
  recognition stays bounded to the canonical name and genuinely DCR-minted
  names. Use the helper for the OR; never inline a `startswith` that drops
  the canonical case. The logout signal intentionally matches a looser set
  at the DB layer (`Q(name=...) | Q(name__startswith=...)` — SQL can't run
  the suffix regex); the asymmetry is safe *by direction* — auth **accepts**
  with the strict check, the signal **revokes** with the loose one, so both
  err toward least privilege.
### Curated-view migrations

- **Curated-view migrations have two mandatory invariants** that any new
  view migration MUST uphold (see the "Curated-view pattern" section
  above for the full recipe):
  1. Forward SQL is `CREATE OR REPLACE VIEW`, not bare `CREATE VIEW`, for
     column-*additive* changes. Deployments with a no-destructive-DB-recovery
     posture mean a half-applied view that already exists on retry would stall
     the deploy until a DBA manually drops it. `CREATE OR REPLACE VIEW` is
     retry-idempotent; reverse is always `DROP VIEW IF EXISTS` (views
     own no data). **To remove or reorder columns, `CREATE OR REPLACE VIEW`
     fails (it may only append) — use `DROP VIEW IF EXISTS <view>;` +
     `CREATE VIEW ...` instead, equally retry-idempotent.**
  2. `RunSQL` carries `state_operations=[migrations.CreateModel(..., managed=False)]`
     registering the unmanaged model. Without it Django's state graph
     doesn't know the model exists, `makemigrations` emits a noisy
     state-only migration on every run, and `check-migrations` (CI gate)
     fails. The CreateModel mirrors the model's fields and
     `options={"managed": False, "db_table": ...}`.
