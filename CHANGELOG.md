# Changelog

All notable changes to `django-mcp-sql` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

## 0.2.0b1

The multi-client release: declared clients ship ON, Cursor is supported, every
`MCP_SQL` key has a default, and every audit row now names the client that
made the request.

### Breaking

All but the last two fail loudly at startup, and none require any client to
reconnect (client_ids are unchanged, provisioning never deletes rows, and
tokens are 6-hour anyway). The default-ON flip and the dropped `is_staff`
requirement are called out separately below precisely because they do **not**
announce themselves.

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

- **`"http"` in `OAUTH2_PROVIDER["ALLOWED_REDIRECT_URI_SCHEMES"]` is now
  required unconditionally**, not just when a `local` client is declared.
  `/o/register` is mounted unconditionally and only ever mints `http` loopback
  callbacks, and DOT enforces the scheme list at the authorization redirect
  rather than at boot — so narrowing the list to `["https"]` used to boot clean
  and then break every self-registering client (Claude Code, Cursor
  desktop/CLI) opaquely at `/o/authorize/`. It is now a boot error. A consumer
  running `["https"]` today will not start until they add `"http"`; DOT's own
  default has both, so most consumers never declared the key at all.

  **Known conflict with DOT ≥ 3.4's opt-in RFC 9700 gate.** DOT 3.4 added
  `OAUTH2_PROVIDER["COMPLIANT_BCP_RFC9700_REDIRECT_URI_SCHEME"]`. It changes no
  runtime behaviour — it only sets the severity of the `manage.py check
  --deploy` finding for `"http"` in `ALLOWED_REDIRECT_URI_SCHEMES`: warning
  `oauth2_provider.W008` while the gate is `False` (DOT's default, so on DOT
  ≥ 3.4 every deployment of this package sees that warning under
  `--deploy`), error
  `oauth2_provider.E003` once it is `True`. Since this package will not boot
  without `"http"`, no configuration satisfies both with the gate on:
  `check --deploy` fails on E003. The `http` entry is what RFC 8252 loopback
  callbacks need, and DOT's own hint for E003 says to keep it if you support
  them. Either leave the gate off, or turn it on and add
  `"oauth2_provider.E003"` to `SILENCED_SYSTEM_CHECKS` (Django silences errors
  as well as warnings; checked against DOT 3.4.1). DOT says the gate defaults
  flip to `True` in its 4.0; this package caps DOT at `<4`.

- **Declared clients now ship ON.** `CLOUD_CLIENTS` defaulted to `[]`; `CLIENTS`
  defaults to `claude`, `chatgpt` and `cursor`. A consumer who declared the old
  key hits the `ImproperlyConfigured` above and makes a deliberate choice — but
  one who never declared it was running a structurally loopback-only surface on
  the 0.1.0b5 default, and after this upgrade `provision_mcp_clients` creates
  three `Application` rows bound to `claude.ai` / `chatgpt.com` / `cursor.com`
  callbacks at the next `migrate`, with no error and no prompt. The derived
  client_ids are guessable (`mcp-sql-cloud.claude`), so what stands between a
  phished authorization link and a token is now a cohort user (active + MFA +
  profile — the issuance gate limits who can be a victim, not whether the
  link works) declining the consent screen — no longer RFC 8252 loopback
  delivery. Under loopback-only, a phished code still landed on the victim's
  own machine; with a shared provider callback, the victim's browser is sent
  to the provider carrying a `state` the attacker's own connector minted, and
  the consent page looks the same either way (see "Changed" below). Whether
  the provider then completes that callback for the attacker's connector is
  provider behaviour this server does not control and that was not tested. An operator who
  deliberately chose loopback-only should know the posture moved.
  Set `"CLIENTS": {}` to keep the old behaviour, or name just the clients you
  want. Provisioning logs each client at INFO on every `migrate`.

- **`is_staff` is no longer required for MCP access.** Both the issuance gate
  at `/o/authorize/` and the per-request gate now check only `is_active`,
  `MFA_CHECKER`, and exactly one MCP profile: the explicit profile assignment
  (the profile's permission, via its group or granted directly) is the access
  grant, and a staff flag only duplicated it. At upgrade, any **active
  non-staff** user who already holds an MCP profile permission — for example
  through a group that also has non-staff members — gains access, with no
  error. Check who holds the profile permissions before upgrading. New
  auth-rejection rows use reason `inactive` ("User account is inactive"); rows
  written by 0.1.x keep `inactive_or_non_staff`, which stays a valid choice
  (migration `0014` adds the new one). Custom user models without an
  `is_staff` field now pass the gates, and `mcp_sql_smoke`'s attribution
  fallback no longer assumes the field.

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
  port-wildcards), explicit port, non-root path, `MATCH: "exact"`. While one is
  declared, boot also refuses DOT ≥ 3.4's
  `OAUTH2_PROVIDER["ALLOW_LOCALHOST_LOOPBACK"] = True`, which would
  port-wildcard `localhost` too and silently turn the exact rule into "any port
  on the user's machine". Documented, not shipped — see `docs/oauth.md` →
  "Clients".
- **Client attribution on every audit row.** `MCPQueryLog` gains
  `application_name` and `client_kind`; `MCPAuthRejectionLog` gains
  `client_kind` (migration `0013`). `client_kind` is one of `curated` / `dcr` /
  `cloud` / `local` and is **derived, never declared** — for a declared client
  it comes from its redirect scheme, so it cannot drift from what the client
  is. The query-volume tripwire names the client too — the one whose query
  crossed the threshold; counting stays per user across clients, so a burst
  spread over several clients still alerts.
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
  no label: its `client_name` is attacker-chosen free text. The destination
  names the provider or machine, not whose account there — a shared callback
  (Claude.ai's, every ChatGPT connector's) renders identically for an
  attacker's own connector — so the screen's real check is its "Only continue
  if you started this from there" line.
- The `"prefix"` redirect matcher also refuses a backslash anywhere in the
  (percent-decoded) path, since a browser reads `\` as `/` in an https URL and
  `..\` is traversal by another spelling. Hardening rather than a reachable
  fix: oauthlib's absolute-URI check already rejects such a `redirect_uri`, and
  Django's `iri_to_uri` would encode it to `%5C` in the `Location` anyway — it
  is refused so the path anchor depends on neither.
- Provisioning now names orphaned declared-client `Application` rows in a
  WARNING. It still never deletes them — that would cascade live tokens in the
  middle of a `migrate`.

### Fixed

- **The RFC 9728 discovery document advertised a resource identifier that did
  not match the path it was served at, making the surface unreachable from
  clients that validate it.** `resource` was built straight off
  `reverse("mcp_sql_endpoint")` — `https://<host>/mcp/sql/`, with the trailing
  slash — while the document itself was served only at
  `/.well-known/oauth-protected-resource/mcp/sql`. RFC 9728 §3.3 requires the
  returned `resource` to be *identical* to the identifier the client inserted
  the well-known suffix into, and says the document MUST NOT be used
  otherwise. Cursor Desktop enforces this and aborted the flow after the
  consent screen but before the token exchange; Claude Code and Cursor CLI
  ignored the mismatch. Compounding it, the metadata path implied by the
  advertised identifier (`…/oauth-protected-resource/mcp/sql/`) returned 404,
  so no client could retrieve the document the spec-correct way.

  The document is now served under **both** spellings of the resource path and
  `resource` echoes the one requested, and the 401 challenge's
  `resource_metadata` pointer follows the spelling of the request that drew it
  (`/mcp/sql/` → `…/oauth-protected-resource/mcp/sql/`, `/mcp/sql` →
  `…/oauth-protected-resource/mcp/sql`). That covers both clauses of §3.3: a
  client that builds the metadata URL from its own identifier gets that
  identifier back, and one that follows the 401 pointer gets back the URL it
  sent the request to. What it cannot cover is a client that requests one
  spelling and then compares against the other — no single document satisfies
  that (the MCP Python SDK's `check_resource_allowed` normalises the slash, so
  it is lenient here either way). Both spellings already routed to the
  transport, so the derived audience reaches the same endpoint either way.
  The pointer's path changes only for requests to `/mcp/sql/`; a client whose
  request URL is slash-less — which is what the original Cursor Desktop failure
  implies — is pointed exactly where it was (its scheme is covered by the next
  entry). The pointer change was not re-tested against a live client. Nothing
  server-side validates `resource`, so no live token is affected.
- **Both discovery documents now agree on one origin.** The scheme is the
  other half of the same identifier: `resource` and the four AS endpoint URLs
  were composed with `request.build_absolute_uri`, which trusts
  `request.scheme`, while `issuer` deliberately forced `https` off `DEBUG`.
  Behind a TLS terminator that does not forward `X-Forwarded-Proto` (or with
  `SECURE_PROXY_SSL_HEADER` unwired) one document therefore advertised
  `"resource": "http://host/mcp/sql"` beside
  `"authorization_servers": ["https://host/o"]` — the same §3.3 mismatch, and
  AS endpoints on a different origin than the issuer naming them. Every
  absolute URL in both documents — and the `resource_metadata` URL in the 401
  challenge, which is where clients actually start, and the
  `registration_client_uri` in `/o/register`'s 201 — now goes through one
  hardened helper (`consts.absolute_url`). Note the widened effect: with
  `DEBUG` off, the AS endpoint URLs, the 401 pointer and
  `registration_client_uri` are now forced to https as well, where previously
  only `issuer` was. A `DEBUG=False` plain-http deployment was
  already out of spec for RFC 8414 §2, but it will now advertise an https
  surface it does not serve.
- **A declared https callback on a loopback host was classified and audited
  as `cloud`.** Kind derives from the scheme, so an https callback whose host
  was really the user's own machine (`https://localhost:8443/cb`) took the
  `mcp-sql-cloud.*` namespace, skipped the loopback hardening, and wrote
  `client_kind="cloud"` on every audit row while the browser following the
  redirect delivered the code to the end user's machine. An https declared
  callback's host must now be a **fully-qualified ASCII DNS name** (letters,
  digits, hyphens and dots; an internationalised domain in its punycode
  `xn--` form), is never an **IP literal** of any kind — loopback or not, IPv6
  or IPv4, including the resolver's shorthand forms (`127.1`, `0x7f.1`, `0`) —
  is never **single-label** (`localhost4`, `ip6-localhost`, a machine's own
  hostname: such names resolve only through `/etc/hosts` or a search domain),
  and never sits under a special-use suffix that only resolves locally
  (`.localhost`, mDNS `.local` — which includes the machine's own
  `<hostname>.local` — `.home.arpa`, `.internal`, and the `localdomain*`
  pseudo-TLDs of `localhost.localdomain` / `localhost4.localdomain4`). It is
  an allow-shape rather than a loopback detector because the detector kept
  missing spellings: percent-encoded and fullwidth hosts, `0.0.0.0`,
  `*.localhost`, and — on Python 3.12.3, whose `ipaddress` does not call them
  loopback — IPv4-mapped IPv6 addresses; a list of distro loopback aliases
  missed Fedora's `localhost4` the same way, hence the single-label rule. All
  of these now fail at boot; an https callback declared on an IP literal, a
  single-label or a non-ASCII host must be re-declared as a fully-qualified
  DNS name. Not
  covered: a public DNS name that resolves to loopback, which no syntactic
  check can see. A NUL or lone surrogate in a declared host now fails boot
  with `ImproperlyConfigured` naming the URI instead of escaping as a bare
  `ValueError` / `UnicodeEncodeError`.
- **`approval_prompt=auto` could skip the consent page.** DOT's
  `AuthorizationView.get()` reads `approval_prompt` from the query string
  (falling back to `REQUEST_APPROVAL_PROMPT`), and on `auto` it issues a code
  on a plain GET — no page, no POST — whenever the user already holds an
  unexpired token for the same Application. `skip_authorization=False` did not
  prevent it. A declared client is one Application shared by every account at
  its provider, so a staff user who had connected Claude.ai had their browser
  sent straight to the shared callback with a code bound to the attacker's
  PKCE challenge and carrying the attacker's `state`, just by opening a
  crafted link. Reproduced against DOT 3.4.1 (302
  to the callback with the code). `MCPAuthorizationView` now pins
  `approval_prompt` to `force` for every request, so consent is an explicit
  POST every time; the curated `skip_authorization=True` Application is
  unaffected. **This predates the multi-client work** — DCR clients (and
  0.1.0b5's opt-in cloud clients) had the same skip — but declared clients
  shipping ON makes it reachable by default. Whether a given provider then
  completes a callback it receives in another user's browser is outside this
  server and was not tested.
- **Logout now also revokes pending authorization codes.** The `user_logged_out`
  receiver deleted the user's MCP access tokens but not their DOT `Grant`
  rows, so a code issued just before logout — a consent approved a moment
  ago, or a phished approval the user logs out to undo — could still be
  exchanged at `/o/token/` afterwards for a fresh token nothing had deleted
  (reproduced end to end: consent, logout, exchange → 200 with a new access
  token). Logout now deletes the user's pending MCP codes first, then their
  MCP access tokens, through one shared Application predicate so the two can
  never disagree (the existing name test: exactly `APPLICATION_NAME`, or
  starting with `APPLICATION_NAME_PREFIX`); rows of other Applications are
  untouched, and the logout audit row counts both — and says FAILED for
  whichever delete raised, rather than reporting it as zero. Not reached: a code or refresh exchange
  already in progress at that instant. Refresh-token rows are still not
  deleted; tested with `REFRESH_TOKEN_EXPIRE_SECONDS=0`, one obtained before
  logout yields no usable MCP token after it (DOT 3.4.1: `invalid_grant`;
  DOT 3.2.0: a token with an empty scope, which the `mcp:sql` check refuses).
  Predates the multi-client work.
- **A declared redirect URI with an empty userinfo passed boot validation.**
  The check refused a non-empty user or password, but `https://@claude.ai/cb`
  (or `http://@localhost:8787/cb`) parses with username `""` and slipped
  through. Any `@` in the authority of a declared redirect URI — cloud and
  local alike — is now a boot error; an `@` in the path or query is
  unaffected.
- **The consent screen corrupted IPv6 destinations.** `urlparse().hostname`
  strips the brackets, so `http://[::1]:8787/cb` rendered as
  `http://::1:8787` — and `::1` is an accepted DCR loopback host. An explicit
  `:0` was also dropped by a falsy-port test. Both fixed; this is the one line
  on that page the user is asked to verify.
- **A registered redirect URI could smuggle a second, off-machine one.**
  `Application.redirect_uris` stores the list as `" ".join(...)` and DOT
  matches with `redirect_uris.split()`, so a single submitted string carrying
  whitespace became **two** registered URIs. `urlparse` reports the loopback
  hostname for `"http://127.0.0.1:8765/cb http://evil.example/steal"`, so the
  loopback check passed, the string was stored verbatim, and DOT then
  exact-matched `http://evil.example/steal` as a valid redirect for that
  client — delivering the authorization code off the victim's machine, which
  is the one thing loopback-only registration exists to prevent. PKCE offers
  no protection: the attacker registered the client and holds the verifier.
  The remaining barrier was the consent screen, which this release happens to
  have taught to name the destination. Both the anonymous DCR path and
  operator-declared redirects now refuse embedded whitespace, using the same
  `.split()` operation DOT performs so the two cannot drift.
  **This predates the multi-client work** — the predicate and the join are
  identical on 0.1.0b5 — and is fixed here because this release restates the
  guarantee it broke.
- **`/o/register` capped the redirect_uri count but not each URI's length.**
  `Application.redirect_uris` is an unbounded `TextField`, so ten 6 KB URIs
  still persisted ~60 KB from one anonymous request inside the 64 KiB body
  cap — the thing the count cap's own comment claimed to prevent. Each stored
  URI is now bounded at 1024 characters, applied *inside* the loopback filter
  so an over-long callback the server discards anyway cannot fail the whole
  registration (Cursor presents a hosted callback beside its loopback one, and
  that URL can carry a long `state`).
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
