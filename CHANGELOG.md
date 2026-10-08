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

All but the last four fail loudly — at startup, or for the Python API renames
at import or call time — and none require any client to reconnect (client_ids
are unchanged, provisioning never deletes rows, and tokens are 6-hour anyway).
The default-ON flip, the dropped `is_staff` requirement, the curated client's
new consent page and the consent page no longer skippable by
`REQUEST_APPROVAL_PROMPT` are called out separately below precisely because
they do **not** announce themselves.

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

- **Python API renames** (for code that calls into the package directly; an
  `ImportError` / `AttributeError` / `TypeError` names each at import or call
  time):
  - `executor.run_query(client_redirect=<str>)` → `run_query(client=<ClientIdentity>)`,
    and the same for `executor.audit_tool_call`. A `clients.ClientIdentity`
    carries the client's name, derived kind and allowed callbacks (declared or
    registered); build one with `consts.identify_application(application)`, or
    omit the argument (`clients.NO_CLIENT`, blank attribution).
  - `conf.mcp_sql_settings.cloud_clients()` → `mcp_sql_settings.clients()`
    (still `{client_id: …}`, now covering both declared kinds).
  - `conf.CloudClient` → `clients.DeclaredClient` (moved module; the single
    `redirect_match` / `redirect_uri` pair became a `redirects` tuple of
    `clients.RedirectRule`, plus `kind` and `label`), and the settings
    TypedDict `validation.CloudClientEntry` → `validation.ClientEntry`.
  - `signals.provision_mcp_cloud_clients` → `signals.provision_mcp_clients`
    (a consumer that disconnected or re-dispatched the receiver by name).
  - `consts.is_mcp_application_name(name)` → `consts.is_mcp_application(application)`:
    recognition now needs the row, since it also requires `client_id == name`
    (see "Changed"). `consts.classify_application_name(name)` remains as the
    name-shape half; it is not a recognition check on its own.

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

- **The curated `mcp-sql` client now shows the consent page.** Migration
  `0015` sets `skip_authorization=False` on the existing row (its reverse
  restores `True`), and `0005` creates it that way on fresh installs. Every
  client kind now requires consent. The curated row used to skip it on the
  reasoning that its redirect is fixed, so no attacker can mint a rogue copy;
  but its registered redirect is `http://127.0.0.1`, and DOT accepts any port
  on a loopback IP, so a phished `/o/authorize/?client_id=mcp-sql&
  redirect_uri=http://127.0.0.1:<port>` link opened by a logged-in cohort
  user sent a code silently to any local port, where any listening process
  holding the PKCE verifier it chose could exchange it. Users of the fixed
  `mcp-sql` client_id (an MCP client configured with it explicitly) now click
  Authorize once per token, every 6 hours with the recommended token
  lifetime. Claude Code's `claude mcp add` registers its own client through
  `/o/register` and already saw the consent page, so it is unaffected. Also
  affects 0.1.0b5.

- **`OAUTH2_PROVIDER["REQUEST_APPROVAL_PROMPT"] = "auto"` no longer applies to
  the package's authorization view.** `/o/authorize/` now always shows the
  consent page, for every client kind: `MCPAuthorizationView` pins DOT's
  `approval_prompt` to `force` whatever the setting or the query string says
  (see "Fixed" → "`approval_prompt=auto` could skip the consent page"). A
  consumer who set `"auto"` so that a user re-authorizing the same client
  before the token expires skipped the page will now see it every time; there
  is no setting to bring the skip back. Other OAuth applications served by
  DOT's own views in the same project keep the setting.

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
- **Recognition requires an `Application`'s `client_id` to equal its `name`.**
  Recognition and the consent label keyed on the name while provisioning and
  the redirect checks keyed on the `client_id`, and nothing enforced that the
  two agree. A row whose two differ is now recognised as nothing, on every branch
  (curated, declared, DCR): refused at `/o/authorize/`, its tokens a
  `bad_application` 401 with a blank `client_kind`. Every row the package
  writes carries one string in both (migration 0005, `/o/register` and
  provisioning, in every release), so only a hand-made or hand-edited row is
  affected — e.g. a curated `mcp-sql` row whose `client_id` was changed in the
  admin stops working until the two match again.

### Fixed

- **A declared client's redirects followed its `Application` row, not
  settings.** Its exact callbacks were matched by DOT against the row's
  `redirect_uris`, which provisioning refreshes only in `post_migrate`. So
  after a callback was changed in `CLIENTS` and the process redeployed without
  `migrate`, the old callback was still accepted and the new one refused, and
  a removed rule stayed admissible until the next `migrate` — while
  recognition already followed settings at every request. Now a declared
  client's redirect is decided from its `CLIENTS` entry alone: exact rules by
  DOT's own matcher (`redirect_to_uri_allowed`) on the declared exact URIs (so
  unchanged settings get the same answers as before), prefix rules as before,
  anything else refused — no fall-back to the row. The default redirect used
  when a request omits `redirect_uri` comes from settings too: the callback of
  an entry with exactly one rule that is `"exact"`, otherwise none (the error
  page; a lone prefix rule used to make the prefix itself the default). The
  row still gets the URIs on `migrate`, but nothing reads that copy for a
  declared client: the audit trail's `client_redirect` is built from its
  `CLIENTS` entry too, so audit rows name the callbacks actually enforced
  rather than the row's until the next `migrate`. The curated client and DCR
  clients keep DOT's row-backed matching (and their rows' `client_redirect`).
- **A long `CLIENTS` slug passed boot and failed `migrate`.** The derived
  `<prefix><kind>.<slug>` is written to DOT's `Application.client_id` (100
  characters on DOT 3.2 and 3.3, 255 on 3.4) and `name` (255), so an
  overlong slug raised a `DataError` inside `provision_mcp_clients`. Boot now
  refuses it with `ImproperlyConfigured` naming the maximum slug length, read
  from the installed model's columns minus the longest derived prefix (86
  characters with the default `mcp-sql-` prefix on DOT 3.2/3.3, 241 on 3.4).
  The same holds for `MCP_SQL["APPLICATION_NAME"]` (written verbatim as the
  curated row's `client_id` and `name` by migration 0005) and
  `APPLICATION_NAME_PREFIX` (a DCR client_id is the prefix plus a
  22-character token, written by the anonymous `/o/register`, which answered
  a 500): boot refuses a name longer than the columns, and a prefix longer
  than the columns minus 22 (100 / 78 characters on DOT 3.2/3.3, 255 / 233
  on 3.4).
- **A `redirect_uri` with a port no parser takes was a 500 for the curated and
  DCR clients.** DOT's matcher reads the request's port while comparing it
  with a stored `localhost` callback, and `urllib.parse` raises `ValueError`
  for `http://localhost:99999/cb` or `:notaport`; only the declared-client
  branch of `MCPOAuth2Validator.validate_redirect_uri` caught it. Every
  branch now treats it as a refusal: `/o/authorize/` (GET or consent POST)
  renders oauthlib's redirect-mismatch error page, no redirect, nothing
  stored.
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
  entry). The pointer change was not re-tested against a live client. No live
  token is affected: a token bound to either spelling passes at either
  transport path (see the RFC 8707 entry below for what the server now does
  with `resource`).
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
- **An RFC 8707 `resource` other than this server's MCP endpoint minted a
  token `/mcp/sql/` could never accept (DOT 3.4 and later).** From DOT 3.4 a
  `resource` sent to `/o/authorize/` or `/o/token/` is stored on the grant and
  access token, and DOT audience-checks every bearer carrying one against the
  request URL. Any `resource` was accepted, so another URL — or the endpoint
  with another scheme, host or path — got a 200 token and then a bare 401 on
  every MCP call: indistinguishable from a bad token, no audit row, and each
  call counted toward the bad-token IP throttle until a shared egress IP was
  silently blocked. The advertised value itself failed the same way behind a
  TLS-terminating proxy without `SECURE_PROXY_SSL_HEADER`: discovery says
  `https` (`DEBUG` off), DOT built the request URL as `http`. Now:
  - `/o/authorize/` and `/o/token/` accept a `resource` only if it names the
    discovery document's `resource` on the host of the request: scheme and
    host in any case, the scheme's default port spelled out or omitted, the
    path exactly the endpoint's, with or without the trailing slash. Anything
    else (including an empty value, the bare origin `https://<host>`, another
    path, port, host or scheme, a port the package does not take — two
    ports or above 65535, which URL parsers refuse too, or more than five
    digits, the package's own cap — a query, a fragment, userinfo) is
    **`invalid_target`** — a redirect to the client's validated
    `redirect_uri` with its `state` and no grant at the authorization
    endpoint (GET, and the consent POST's form field and query string), a
    400 at the token endpoint (`MCPTokenView`, now mounted at `/o/token/`;
    the code is not consumed). The package's `invalid_target` names the
    accepted value, never the client's (DOT's own errors may name it, such
    as its token-step `invalid_target` for a code granted for another
    resource). A NUL `resource` at the
    authorization GET, in the consent POST's query string or at the token
    endpoint gets the same answer instead of a 500; in the consent form's
    own `resource` field (DOT 3.4 and later) Django's form validation
    refuses it first, and the consent page is re-rendered with a form error
    (no redirect, nothing stored).
  - Every accepted spelling is stored as one string, the advertised
    identifier without its trailing slash (`https://<host>/mcp/sql`): both
    endpoints rewrite each accepted `resource` to it before DOT reads it
    (`/o/authorize/`: the query string and the consent form's field;
    `/o/token/`: the form body); a foreign value is never rewritten. From
    DOT 3.4, `/o/token/` requires each `resource` to be one of the grant's,
    compared as strings, and Cursor sends `…/mcp/sql/` to `/o/authorize/`
    and `…/mcp/sql` to `/o/token/`: the exchange got DOT's `invalid_target`
    ("cannot escalate resource permissions"). Any accepted spelling now
    works at either step; the grant, the token request and the token carry
    the same string, and the token passes DOT's audience check on both
    `/mcp/sql` and `/mcp/sql/`. A code or refresh token issued before the
    upgrade under another accepted spelling still exchanges: the validator
    (`MCPOAuth2Validator.save_bearer_token`) puts the request's value in the
    stored spelling, and the token is bound to it. A custom string-comparing
    `RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR` now sees the slash-less
    value.
  - Discovery, and every other absolute URL the package builds, spells the
    host canonically: lowercased, without the scheme's default port. A proxy
    forwarding `Host: <name>:443` (nginx `proxy_set_header Host
    $host:$server_port`, or an `X-Forwarded-Host` carrying the port under
    `USE_X_FORWARDED_HOST`) made discovery advertise
    `https://<name>:443/mcp/sql/`, which clients that parse the URL (the MCP
    TypeScript and Python SDKs) send back as `https://<name>/mcp/sql/`.
  - `/mcp/sql/` hands DOT's audience check the request URL built the same way
    discovery builds `resource`, so a token bound to the advertised value
    always passes, with or without `SECURE_PROXY_SSL_HEADER`, whatever the
    spelling of the forwarded host. The check is not disabled: a token bound
    to a URL that is not a prefix of the endpoint's still gets a 401 (tokens
    issued before upgrading expire within their 6 h). DOT's default
    validator is a URL-prefix match, so one bound to a prefix — the origin,
    `https://<host>/mcp` — passes; the package no longer issues those.
  - On the consent POST (DOT 3.4 and later) the form's `resource` and a
    `resource` in the URL's query string must agree; a blank form field
    beside a query `resource` reached the grant as a plain string and 500'd.

  **Behaviour change**, also on DOT below 3.4 (which ignores `resource`, so
  such clients used to get a working, unrestricted token): a client sending
  a `resource` that is not the advertised one is now refused with
  `invalid_target` naming the expected value. The bearer is verified through
  `audience.CanonicalUriOAuthLibCore` on the configured `OAUTH2_SERVER_CLASS`
  and `OAUTH2_VALIDATOR_CLASS`; a custom `OAUTH2_BACKEND_CLASS` no longer
  applies to `/mcp/sql/` or `/o/token/`, which pins DOT's form-body
  `OAuthLibCore` (with DOT's `JSONOAuthLibCore` configured, a JSON token
  request's `resource` was never seen by the check and reached the token; a
  JSON body is now not read, as RFC 6749 §4.1.3 has it, and is refused).
  Discovery's URLs change spelling only where the forwarded host was not
  canonical. `docs/oauth.md` → "The `resource` parameter (RFC 8707)". Also
  affects 0.1.0b5 on DOT 3.4.
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
  POST every time. The pin covers every Application the package creates,
  the curated `mcp-sql` row included (it requires consent since migration
  `0015`, see Breaking). **This predates the multi-client work** — DCR clients (and
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
  also had a prefix rule.** It returned the prefix verdict instead of also
  checking the exact rules (now DOT's exact matcher on the declared exact URIs,
  see the settings-driven redirects entry above). Unreachable in 0.1.0b5 (one
  rule per entry); reachable the moment a client carries both.
- **Over-long `redirect_uris` silently discarded audit rows.** Both writers
  passed the Application's registered list straight into a 1024-char column; an
  overflow raised `DataError`, which the best-effort audit wrappers swallow —
  losing the row entirely. It is now truncated at the single point where the
  client identity is built.
- `MCPQueryLog.client_redirect` was documented as the redirect the token "was
  issued against … the auth url cannot lie". It is the Application's
  **registered** `redirect_uris` — DOT does not persist which redirect a given
  authorization used. Read it as "one of these". The docstring now says so.
- **A GET to `/mcp/sql/` could pin a worker thread forever.** The view
  accepted GET and DELETE and forwarded them into the FastMCP bridge. With a
  valid token and `Accept: application/json, text/event-stream`, the SDK
  answered a GET with an SSE stream that never ends (with `Last-Event-ID`, with
  no response at all), and the bridge waited for it: a sync worker until
  gunicorn's timeout, a gthread or ASGI thread for good, with a default-DB
  connection held throughout (idle in transaction under
  `ATOMIC_REQUESTS=True`), surviving token revocation. `/mcp/sql/` now answers
  every method but POST with `405` and `Allow: POST`, before authentication.
  No client loses anything: the transport is stateless, the Python MCP SDK
  only opens a GET stream or sends DELETE once the server issued an
  `Mcp-Session-Id` (a stateless server never does), and the TypeScript SDK's
  post-initialize GET, previously answered `406`, now gets the `405` it treats
  as "no stream offered". Also affects 0.1.0b5. As a backstop the bridge
  now cancels an exchange after 30 seconds and completes any response the app
  leaves unfinished (`504` if the deadline cut it off before it started, `500`
  if the app ended without one), so no future path that leaves a response
  unfinished can pin a thread either. An exception the app raises itself,
  including its own `TimeoutError`, stays an ordinary `500`.
- **Under `ATOMIC_REQUESTS=True` no auth rejection was ever recorded.** DRF
  rolls back the request transaction on every `APIException`, including the
  `AuthenticationFailed` each per-request gate raises right after writing its
  `MCPAuthRejectionLog` row, so with the documented default-alias setting the
  table stayed empty (the 401 was still sent). `/mcp/sql/` now opts out of
  `ATOMIC_REQUESTS` on every database alias (not just `default`, so audit
  tables routed to another alias are covered too): the rows commit as
  written, and the view no longer holds a transaction open for the whole
  exchange. Also affects 0.1.0b5.
- **A non-IP `REMOTE_ADDR` broke every audit write.** `client_ip` went
  straight into a `GenericIPAddressField`. Behind a front end that copies an
  unvalidated `X-Forwarded-For` entry into `REMOTE_ADDR` (uvicorn with
  `--forwarded-allow-ips='*'`, for one), a client sending `X-Forwarded-For:
  not-an-ip` made psycopg 3 raise `ValueError` at the insert: queries still
  ran but left no `MCPQueryLog` row (nor a tripwire count), and gate denials
  became 500s with no rejection row. On psycopg2 the rows were dropped
  silently. Every audit writer now stores a normalised address, or `NULL`
  when the value is not one. Also affects 0.1.0b5.
- **A per-request gate that raised was an unaudited 500.** An exception from
  the consumer's `MFA_CHECKER`, from profile resolution (a DB blip) or from
  the `SESSION_MODEL` lookup escaped the auth class: fail-closed, but with no
  `MCPAuthRejectionLog` row. It is now a denial with the new reason
  `gate_error` (a choice folded into the unreleased migration `0014`; no new
  migration), answered `503` with `Retry-After: 30` and no `WWW-Authenticate`
  challenge, with the traceback logged. Deliberately not a 401: MCP clients
  answer a 401 with a full OAuth re-authorization, which during an
  MFA-backend or session-store outage fails the same way and can leave a
  hosted connector needing a manual reconnect. Likewise a cache fault in the once-per-hour "ambiguous profile"
  WARNING dedup no longer turns that denial into a 500; the WARNING is
  emitted instead. Also affects 0.1.0b5.
- **Tokens with no user or no Application reached gates that assumed them.**
  DOT allows both to be `NULL` (a `client_credentials` token from another
  OAuth use case on the same install, a shell-minted row). A userless token on
  an MCP Application was an unaudited 500; on any other Application a 401
  whose audit insert failed on the non-null `user` column. A userless token is
  now refused with a 401 and a WARNING naming the token and its client (the
  rejection table is keyed to a user); a token with no Application is an
  audited `bad_application` denial. Also affects 0.1.0b5.
- **Documented: a logout from an expired session revokes nothing.** Django
  sends `user_logged_out` with `user=None` when the web session has already
  ended (and django-allauth sends nothing), so the user's MCP tokens and
  pending codes survive and no audit row is written. `docs/oauth.md` →
  "What logout cannot revoke" says so and gives the remedy (log in, then log
  out). Unchanged behaviour; also affects 0.1.0b5.
- **A consent POST's error redirect trusted the form's hidden `redirect_uri`.**
  DOT raises Cancel's `access_denied` and (DOT 3.4 and later) an invalid
  `resource`'s `invalid_target` before oauthlib validates that field, then
  redirected the user's browser, `state` included, to whatever it held.
  Exploiting it takes a tampered, CSRF-bearing consent POST (script on the
  same origin). The view now
  re-validates the target against the client before every error redirect and
  shows the error page when it does not belong to the client. A consent POST
  naming a `client_id` that does not exist was a 500; it shows the same error
  page, also when the client is deleted while the POST is in flight (on
  every path, Authorize or Cancel, with or without a `resource`). So does a `client_id` containing a NUL byte: on the GET, DOT handed it
  to Postgres, which raised `DataError` (a 500); on the consent POST, Django's
  form validation already rejected it and the consent page was re-rendered
  (a 200), so the POST check is defence in depth. All inherited from DOT; also
  affects 0.1.0b5.
- **`/o/register` could answer an anonymous 500.** Each of these escaped the
  view as a 500 on every retry, before the per-IP `register` counter:
  - a NUL in a loopback redirect URI (`http://127.0.0.1:8761/cb\u0000`): the
    loopback filter refused whitespace but not NUL, and Postgres rejected the
    INSERT (`DataError` under psycopg 3);
  - a lone surrogate there (`\ud800`, a legal JSON escape): the driver
    cannot encode it as UTF-8 (`UnicodeEncodeError`);
  - a redirect URI with a malformed bracketed host (`http://[::1`,
    `http://[127.0.0.1]/cb`) or a host invalid under NFKC normalisation (a
    fullwidth solidus): `ValueError` inside the loopback filter, even when a
    clean URI rode alongside;
  - a body that is not UTF-8, JSON nested past the recursion limit, or an
    integer longer than Python's digit limit;
  - a `grant_types` or `response_types` that is not a list (`null`, a
    number); a string there also turned the "must include
    `authorization_code`" check into a substring test.

  None of these is a 500 any more. A URI that does not parse is now never
  registered: like any other URI that is not a valid loopback callback, it
  drops out of the registered subset (a 400 if nothing else is left). That
  also covers a loopback URI with a port that is not a number in range
  (`http://127.0.0.1:99999/cb`): the filter never read the port, so such a URI
  used to be registered verbatim (a 201), unusable. The rest are RFC 7591
  400s for the whole request, even beside a clean URI: the body and type
  cases above, a `redirect_uris` member that is not a string (it used to be
  dropped silently), a `client_name` that is not a string (absent, `null` or
  empty still gets the default name; a falsy non-string such as `0` or `[]`
  used to get it silently), and the characters below.
  The character rule (documented once, at the top of the character section
  of `views/registration.py`): a requested `redirect_uris` entry
  (`invalid_redirect_uri`) must be printable and visible: no control, format,
  surrogate, private-use, unassigned or noncharacter, separator,
  default-ignorable (invisible) or blank character (e.g. U+2800), and no
  conjoining Hangul jamo. A `client_name` (`invalid_client_metadata`) must be
  assigned, visible text: no control, surrogate, private-use, unassigned or
  noncharacter, line / paragraph separator or blank character, no Hangul
  vowel or final that does not continue a syllable, and no format or
  default-ignorable (invisible) character except inside a well-formed
  sequence: a zero-width non-joiner or joiner between two visible non-ASCII
  characters (Persian and Indic spelling, emoji ZWJ sequences); VS15 / VS16
  after a base Unicode's emoji-variation-sequences.txt lists (so `↔️`, `‼️`,
  `ℹ️` and keycaps work, `★` plus VS16 does not); a Mongolian free variation
  selector after a Mongolian letter; the combining grapheme joiner before a
  combining mark; a subdivision flag (U+1F3F4, a lowercase two-letter region
  and a one-to-four letter / digit subdivision in tags, U+E007F). Visible
  format marks such as the Arabic number sign are ordinary text. Ideographic
  variation selectors and the deprecated Khmer inherent vowels are refused,
  as is the soft hyphen (invisible except at a line break). "Assigned"
  follows the running Python's Unicode version (Python 3.11 ships Unicode
  14.0). Nothing refused is stored, echoed or logged: a callback is copied
  into every audit row's `client_redirect`, and an invisible or reordering
  character there would let a registrant make it read as something else.
  Ordinary non-ASCII text is still accepted. A seeded fuzz of the endpoint
  (malformed hosts, ports, encodings, odd characters) pins that it answers
  only 201 or 400. An unparseable body is `invalid_client_metadata`, and
  `grant_types` / `response_types` must be arrays of strings. Also affects
  0.1.0b5.
- **Known on this branch alone, fixed by PR #4 (branch
  `fix/dcr-redirect-whitespace`, 0.1.0b6, which merges first):** a NUL byte
  in a parameter of DOT's own OAuth views still reaches the database. Under
  psycopg 3 every case below is a 500 (`DataError`). Under psycopg2 the driver
  refuses the NUL client-side with `ValueError`; DOT's client lookup catches
  that (GH #1006), so a NUL `client_id` at `/o/token/` or `/o/revoke_token/`
  is a 401 `invalid_client`, but the other cases are still a 500. The cases:
  `client_id` and `code` at `/o/token/`, `client_id` at `/o/revoke_token/`,
  and `code_challenge` or `nonce` on an
  `/o/authorize/` GET that issues a code without consent — which no
  Application the package creates does any more (every kind requires
  consent since migration `0015`); only a hand-flipped or legacy
  `skip_authorization=True` row reaches it. PR #4 refuses a control
  character in every parameter of those views (and in any `client_id` DOT
  looks up) before DOT runs; nothing here duplicates it. Also fixed by PR #4,
  through its `django-oauth-toolkit>=3.4.1` floor: on DOT 3.2.0 (this
  branch's declared floor), an anonymous `prompt=none` request to
  `/o/authorize/` is redirected to the `redirect_uri` in the query string
  without validating it; DOT 3.4.1 answers 400. Same code on 0.1.0b5.

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
